package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

/* https://elinux.org/images/e/e3/Yaffs.pdf
https://yaffs.net/documents/how-yaffs-works
https://yaffs.net/documents/yaffs-direct-interface
*/

const (
	YAFFS_MAX_NAME_LENGTH  = 255
	YAFFS_MAX_ALIAS_LENGTH = 159 // TODO CHECK

	/* Some special object ids for pseudo objects */
	YAFFS_OBJECTID_ROOT       = 1
	YAFFS_OBJECTID_LOSTNFOUND = 2
	YAFFS_OBJECTID_UNLINKED   = 3
	YAFFS_OBJECTID_DELETED    = 4
	YAFFS_OBJECTID_SUMMARY    = 0x10

	YAFFS_LOWEST_SEQUENCE_NUMBER  = 0x00001000
	YAFFS_HIGHEST_SEQUENCE_NUMBER = 0xefffff00
	/* Special sequence number for bad block that failed to be marked bad */
	YAFFS_SEQUENCE_BAD_BLOCK = 0xffff0000

	/* YAFFS2 Additions */
	EXTRA_HEADER_INFO_FLAG = 0x80000000
	EXTRA_SHRINK_FLAG      = 0x40000000
	EXTRA_SHADOWS_FLAG     = 0x20000000
	EXTRA_SPARE_FLAGS      = 0x10000000

	ALL_EXTRA_FLAGS     = 0xf0000000
	NOT_ALL_EXTRA_FLAGS = 0xfffffff

	/* Also, the top 4 bits of the object Id are set to the object type. */
	EXTRA_OBJECT_TYPE_SHIFT    = (28)
	EXTRA_OBJECT_TYPE_MASK     = ((0x0f) << EXTRA_OBJECT_TYPE_SHIFT)
	NOT_EXTRA_OBJECT_TYPE_MASK = 0xfffffff

	YAFFS_OBJECT_SPACE  = 0x40000
	YAFFS_MAX_OBJECT_ID = (YAFFS_OBJECT_SPACE - 1)

	YAFFS_TNODES_LEVEL0_BITS   = 4
	YAFFS_TNODES_INTERNAL_BITS = (YAFFS_TNODES_LEVEL0_BITS - 1)
	YAFFS_TNODES_MAX_LEVEL     = 8
	YAFFS_TNODES_MAX_BITS      = (YAFFS_TNODES_LEVEL0_BITS + YAFFS_TNODES_INTERNAL_BITS*YAFFS_TNODES_MAX_LEVEL)
	YAFFS_MAX_CHUNK_ID         = ((1 << YAFFS_TNODES_MAX_BITS) - 1)

	YAFFS_NOBJECT_BUCKETS = 256
)

type ObjectHeader struct {
	ObjectType     ObjectType
	ParentObjectID uint32
	Checksum       [2]byte //unused
	Name           [YAFFS_MAX_NAME_LENGTH + 1]byte

	Mode       uint32
	UID        uint32
	GID        uint32
	AccessTime uint32
	ModTime    uint32
	CreateTime uint32

	FileSizeLow [4]byte
	EquivID     int32 // originally int

	Alias [YAFFS_MAX_ALIAS_LENGTH + 1]byte

	RDev uint32

	WinCreateTime uint64
	WinAccessTime uint64
	WinModTime    uint64

	InbandShadowedObjectID uint32
	InbandIsShrink         uint32
	FileSizeHigh           [4]byte

	Reserved uint32

	ShadowsObject int32 // originally ints

	IsShrink uint32
}

type Yaffs2SpareRaw struct {
	SeqNumber   uint32
	ObjectID    uint32
	ChunkID     uint32
	NumberBytes uint32
	// Ignore ECC Packed Tags for now
	// TODO add ECC checks for cases where YAFFS handles ECC?
}

func (s *Yaffs2SpareRaw) Parse() *Yaffs2Spare {

	// Sanity check sequence number
	if s.SeqNumber == YAFFS_SEQUENCE_BAD_BLOCK ||
		s.SeqNumber < YAFFS_LOWEST_SEQUENCE_NUMBER ||
		s.SeqNumber > YAFFS_HIGHEST_SEQUENCE_NUMBER {
		return nil
	}

	var spare = &Yaffs2Spare{
		SeqNumber:   s.SeqNumber,
		ObjectID:    s.ObjectID,
		ChunkID:     s.ChunkID,
		NumberBytes: s.NumberBytes,
	}

	// Match C logic (everything not zero is true)
	if (s.ChunkID & EXTRA_HEADER_INFO_FLAG) != 0 {
		spare.ChunkID = 0
		spare.NumberBytes = 0
		spare.ExtraValid = true
		spare.ParentID = s.ChunkID & NOT_ALL_EXTRA_FLAGS
		spare.IsShrink = s.ChunkID&EXTRA_SHRINK_FLAG != 0
		spare.Shadows = s.ChunkID&EXTRA_SHADOWS_FLAG != 0
		spare.ObjType = s.ObjectID >> EXTRA_OBJECT_TYPE_SHIFT
		spare.ObjectID = s.ObjectID & NOT_EXTRA_OBJECT_TYPE_MASK
	}

	// Checks after parsing extra header information
	if !objectIDValid(spare.ObjectID) || spare.ChunkID > YAFFS_MAX_CHUNK_ID {
		return nil
	}

	return spare

}

type Yaffs2Spare struct {
	SeqNumber   uint32
	ObjectID    uint32
	ChunkID     uint32
	NumberBytes uint32

	// YAFFS2 Extended Tags parsed with Flags from ChunkID
	ExtraValid bool
	ParentID   uint32
	IsShrink   bool
	Shadows    bool
	ObjType    uint32
}

func (oh *ObjectHeader) String() string {

	return fmt.Sprintf("Type: %s, Name: %s, UID: %v, GID: %v, SizeLow: %v, SizeHigh: %v", oh.ObjectType, CToGoString(oh.Name[:]), oh.UID, oh.GID, oh.FileSizeLow, oh.FileSizeHigh)
}

type ObjectType uint32

const (
	YAFFS_OBJECT_TYPE_UNKNOWN ObjectType = iota
	YAFFS_OBJECT_TYPE_FILE
	YAFFS_OBJECT_TYPE_SYMLINK
	YAFFS_OBJECT_TYPE_DIRECTORY
	YAFFS_OBJECT_TYPE_HARDLINK
	YAFFS_OBJECT_TYPE_SPECIAL
)

func (o ObjectType) String() string {
	return []string{"unknown", "file", "symlink", "directory", "hardlink", "special"}[o]
}

func main() {

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// TODO finish & test Big Endian Support (needs test environment)
	// TODO manual size / offset config
	// TODO YAFFS1 support

	image, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer image.Close()

	settings, err := detectSettings(image)
	if err != nil {
		log.Println("Using default settings, auto-detect failed:", err)
		settings = &Settings{
			PageSize:  2048,
			SpareSize: 64,
			SpareSkip: 0,
			ByteOrder: binary.LittleEndian,
		}
	} else {
		log.Println("Using detected settings:", settings)
	}

	_, err = image.Seek(0, 0)
	if err != nil {
		log.Fatal(err)
	}

	// Write TSK config
	// TODO make configurable, disable for Big Endian
	tskConfig := fmt.Sprintf(
		`#YAFFS2 config file
flash_page_size = %d
flash_spare_size = %d

spare_seq_num_offset = %d
spare_obj_id_offset = %d
spare_chunk_id_offset = %d`,
		settings.PageSize,
		settings.SpareSize,
		settings.SpareSkip,
		settings.SpareSkip+4,
		settings.SpareSkip+8)

	err = ioutil.WriteFile(os.Args[1]+"-yaffs2.config", []byte(tskConfig), 0666)
	if err != nil {
		log.Println(err)
	}

	var pages [][]byte
	var spares [][]byte

	for {
		pageBuf := getEmptyBuf(settings.PageSize)
		_, err := io.ReadFull(image, pageBuf)
		if err != nil {
			break
		}

		spareBuf := getEmptyBuf(settings.SpareSize)
		_, err = io.ReadFull(image, spareBuf)
		if err != nil {
			break
		}

		if checkBlockEmpty(pageBuf) && checkBlockEmpty(spareBuf) {
			break
		}

		pages = append(pages, pageBuf)
		spares = append(spares, spareBuf)
	}

	log.Printf("Read %d page blocks", len(pages))
	log.Printf("Read %d spare blocks", len(spares))

	// Read valid blocks

	if len(pages) != len(spares) {
		log.Fatal("Page / Spare Mismatch")
	}

	// TODO implement streaming, backwards parsing
	for k, _ := range pages {

		/*log.Println("\n", hex.Dump(pages[k]))
		log.Println("\n", hex.Dump(spares[k]))*/

		spareRaw := &Yaffs2SpareRaw{}
		err = binary.Read(bytes.NewReader(spares[k][settings.SpareSkip:]), settings.ByteOrder, spareRaw)
		if err != nil {
			log.Fatal(err)
		}

		spare := spareRaw.Parse()

		if spare == nil {
			log.Println("Invalid spare, skipping page")
			continue // TODO Decide on action here
		}

		if spare.ChunkID == 0 {
			// This page contains a header to parse
			header := &ObjectHeader{}
			err = binary.Read(bytes.NewReader(pages[k]), settings.ByteOrder, header)
			if err != nil {
				log.Fatal(err)
			}

			if !bytes.Equal(header.Checksum[:], []byte{0xFF, 0xFF}) {
				log.Println("Invalid header, most likely invalid page / spare sizes or corrupt data")
				break
			}

			//log.Println("\n", hex.Dump(pages[k]))
			log.Printf("%s: %+v", header.ObjectType, CToGoString(header.Name[:]))
			//log.Println("\n\n")
		}

		//log.Printf("%+v", spare)
	}

}

func objectIDValid(objectID uint32) bool {
	switch objectID {
	case 1, 2, 3, 4, 0x10:
		// Special IDs
		return true
	}
	if objectID < YAFFS_NOBJECT_BUCKETS || objectID > YAFFS_MAX_OBJECT_ID {
		return false
	}
	return true
}

// Empty NAND blocks are 0xFF filled / initialized
func checkBlockEmpty(buf []byte) bool {
	for _, v := range buf {
		if v != 0xFF {
			return false
		}
	}

	return true
}

func getEmptyBuf(size int) []byte {
	return bytes.Repeat([]byte{byte(0xFF)}, size)
}

type Settings struct {
	PageSize  int
	SpareSize int
	SpareSkip int
	ByteOrder binary.ByteOrder
}

func detectSettings(image io.ReadSeeker) (*Settings, error) {
	// Try to detect page / spare size
	// YAFFS2 requires minimum 1024/32

	byteOrder := binary.LittleEndian
	var pageSizes = []int{1024, 2048, 4096, 8192, 16384}
	var spareSizes = []int{32, 64, 128, 256, 512}
	var spareSkip = []int{0, 2}

	for _, pageSize := range pageSizes {
		for _, spareSize := range spareSizes {
			for _, spareSkip := range spareSkip {

				//log.Printf("Testing page size %d, spare size %d", pageSize, spareSize)
				_, err := image.Seek(0, 0)
				if err != nil {
					log.Fatal(err)
				}

				var pages [][]byte
				var spares [][]byte

				// Read two blocks for analysis
				for x := 0; x <= 1; x++ {
					pageBuf := getEmptyBuf(pageSize)
					_, err := io.ReadFull(image, pageBuf)
					if err != nil {
						break
					}

					spareBuf := getEmptyBuf(spareSize)
					_, err = io.ReadFull(image, spareBuf)
					if err != nil {
						break
					}

					if checkBlockEmpty(pageBuf) && checkBlockEmpty(spareBuf) {
						break
					}

					pages = append(pages, pageBuf)
					spares = append(spares, spareBuf)
				}

				if len(pages) < 2 || len(pages) != len(spares) {
					continue
				}

				// Verify first two spare pages
				// Allows verifying the offset (first spare should contain ChunkID == 0 for a header)

				firstSpareRaw := &Yaffs2SpareRaw{}
				err = binary.Read(bytes.NewReader(spares[0][spareSkip:]), byteOrder, firstSpareRaw)
				if err != nil {
					log.Fatal(err)
				}

				firstSpare := firstSpareRaw.Parse()

				if firstSpare == nil || firstSpare.ChunkID != 0 {
					continue
				}

				secondSpareRaw := &Yaffs2SpareRaw{}
				err = binary.Read(bytes.NewReader(spares[1][spareSkip:]), byteOrder, secondSpareRaw)
				if err != nil {
					log.Fatal(err)
				}

				secondSpare := secondSpareRaw.Parse()

				if secondSpare == nil {
					continue
				} else {
					log.Printf("Found possible settings: page size %d, spare size %d, spare skip %d", pageSize, spareSize, spareSkip)
					settings := &Settings{
						PageSize:  pageSize,
						SpareSize: spareSize,
						SpareSkip: spareSkip,
						ByteOrder: byteOrder,
					}
					return settings, nil
				}
			}
		}
	}

	return nil, errors.New("no suitable settings detected")
}

func CToGoString(c []byte) string {
	n := -1
	for i, b := range c {
		if b == 0 {
			break
		}
		n = i
	}
	return string(c[:n+1])
}
