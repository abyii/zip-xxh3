package zip

import (
	"bufio"
	"encoding/binary"
	"io"
)

// ReadLocalFileHeader reads a ZIP local file header from the provided reader.
// It returns a partially populated FileHeader containing metadata (Name, Flags, Method, etc.)
// parsed from the local header.
func ReadLocalFileHeader(r io.Reader) (*FileHeader, error) {
	var buf [fileHeaderLen]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, err
	}
	rb := readBuf(buf[:])
	sig := rb.uint32()
	if sig != fileHeaderSignature {
		return nil, ErrFormat
	}
	readerVersion := rb.uint16()
	flags := rb.uint16()
	method := rb.uint16()
	modTime := rb.uint16()
	modDate := rb.uint16()
	crc32Val := rb.uint32()
	compressedSizeVal := rb.uint32()
	uncompressedSizeVal := rb.uint32()
	nameLen := rb.uint16()
	extraLen := rb.uint16()

	nameBytes := make([]byte, nameLen)
	if _, err := io.ReadFull(r, nameBytes); err != nil {
		return nil, err
	}
	extraBytes := make([]byte, extraLen)
	if _, err := io.ReadFull(r, extraBytes); err != nil {
		return nil, err
	}

	return &FileHeader{
		Name:               string(nameBytes),
		ReaderVersion:      readerVersion,
		Flags:              flags,
		Method:             method,
		ModifiedTime:       modTime,
		ModifiedDate:       modDate,
		CRC32:              crc32Val,
		CompressedSize:     compressedSizeVal,
		UncompressedSize:   uncompressedSizeVal,
		CompressedSize64:   uint64(compressedSizeVal),
		UncompressedSize64: uint64(uncompressedSizeVal),
		Extra:              extraBytes,
	}, nil
}

// DataDescriptor represents a ZIP data descriptor structure found after the file data.
type DataDescriptor struct {
	CRC32              uint32
	CompressedSize64   uint64
	UncompressedSize64 uint64
}

type rawPartRingBuffer struct {
	buf  [24]byte
	head int
	tail int
	size int
}

func (r *rawPartRingBuffer) Push(b byte) (byte, bool) {
	if r.size == 24 {
		popped := r.buf[r.head]
		r.buf[r.head] = b
		r.head = (r.head + 1) % 24
		r.tail = (r.tail + 1) % 24
		return popped, true
	}
	r.buf[r.tail] = b
	r.tail = (r.tail + 1) % 24
	r.size++
	return 0, false
}

func (r *rawPartRingBuffer) Bytes() []byte {
	out := make([]byte, r.size)
	for i := 0; i < r.size; i++ {
		out[i] = r.buf[(r.head+i)%24]
	}
	return out
}

type descriptorStripper struct {
	r             *bufio.Reader
	ring          *rawPartRingBuffer
	hasDescriptor bool
	desc          *DataDescriptor
	eofReached    bool
	poppedBuf     []byte
}

func newDescriptorStripper(r io.Reader, hasDescriptor bool) *descriptorStripper {
	return &descriptorStripper{
		r:             bufio.NewReader(r),
		ring:          new(rawPartRingBuffer),
		hasDescriptor: hasDescriptor,
	}
}

func (ds *descriptorStripper) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	if len(ds.poppedBuf) > 0 {
		n = copy(p, ds.poppedBuf)
		ds.poppedBuf = ds.poppedBuf[n:]
		return n, nil
	}

	if ds.eofReached {
		return 0, io.EOF
	}

	var temp [4096]byte
	for {
		rn, rerr := ds.r.Read(temp[:])
		for i := 0; i < rn; i++ {
			popped, ok := ds.ring.Push(temp[i])
			if ok {
				ds.poppedBuf = append(ds.poppedBuf, popped)
			}
		}

		if rerr != nil {
			if rerr == io.EOF {
				ds.eofReached = true
				break
			}
			return 0, rerr
		}

		if len(ds.poppedBuf) > 0 {
			break
		}
	}

	if ds.eofReached {
		windowBytes := ds.ring.Bytes()
		var descStart = -1
		if ds.hasDescriptor {
			if len(windowBytes) >= 24 && binary.LittleEndian.Uint32(windowBytes[0:4]) == dataDescriptorSignature {
				descStart = 0
			} else if len(windowBytes) >= 16 && binary.LittleEndian.Uint32(windowBytes[8:12]) == dataDescriptorSignature {
				descStart = 8
			}
		}

		var limit = len(windowBytes)
		if descStart >= 0 {
			limit = descStart
		}

		for i := 0; i < limit; i++ {
			ds.poppedBuf = append(ds.poppedBuf, windowBytes[i])
		}

		if descStart >= 0 {
			descBytes := windowBytes[descStart:]
			ds.desc = new(DataDescriptor)
			if len(descBytes) == 24 {
				ds.desc.CRC32 = binary.LittleEndian.Uint32(descBytes[4:8])
				ds.desc.CompressedSize64 = binary.LittleEndian.Uint64(descBytes[8:16])
				ds.desc.UncompressedSize64 = binary.LittleEndian.Uint64(descBytes[16:24])
			} else if len(descBytes) == 16 {
				ds.desc.CRC32 = binary.LittleEndian.Uint32(descBytes[4:8])
				ds.desc.CompressedSize64 = uint64(binary.LittleEndian.Uint32(descBytes[8:12]))
				ds.desc.UncompressedSize64 = uint64(binary.LittleEndian.Uint32(descBytes[12:16]))
			}
		}
	}

	if len(ds.poppedBuf) > 0 {
		n = copy(p, ds.poppedBuf)
		ds.poppedBuf = ds.poppedBuf[n:]
		return n, nil
	}

	return 0, io.EOF
}
