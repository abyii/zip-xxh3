package zip

import (
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

	fh := &FileHeader{
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
	}
	parseLFHZip64Extra(fh)
	return fh, nil
}

func parseLFHZip64Extra(fh *FileHeader) {
	if len(fh.Extra) == 0 {
		return
	}
	b := readBuf(fh.Extra)
	for len(b) >= 4 {
		tag := b.uint16()
		size := b.uint16()
		if int(size) > len(b) {
			return
		}
		eb := readBuf(b[:size])
		if tag == zip64ExtraId {
			if fh.UncompressedSize == ^uint32(0) {
				if len(eb) >= 8 {
					fh.UncompressedSize64 = eb.uint64()
				}
			}
			if fh.CompressedSize == ^uint32(0) {
				if len(eb) >= 8 {
					fh.CompressedSize64 = eb.uint64()
				}
			}
			return
		}
		b = b[size:]
	}
}

// DataDescriptor represents a ZIP data descriptor structure found after the file data.
type DataDescriptor struct {
	CRC32              uint32
	CompressedSize64   uint64
	UncompressedSize64 uint64
}

// descriptorStripperBufSize is the read buffer of a descriptorStripper; it
// must comfortably exceed dataDescriptor64Len.
const descriptorStripperBufSize = 64 << 10

// descriptorStripper passes through the payload of a raw file part (the bytes
// following the local file header) and, if hasDescriptor is set, strips the
// trailing data descriptor, which is parsed into desc once EOF is reached.
// Only the last dataDescriptor64Len bytes are held back, so memory use is
// constant regardless of the payload size.
type descriptorStripper struct {
	r             io.Reader
	hasDescriptor bool
	buf           []byte
	start, end    int   // pending bytes are buf[start:end]
	emitted       int64 // payload bytes returned so far
	eof           bool
	err           error // sticky read error
	desc          *DataDescriptor
}

func newDescriptorStripper(r io.Reader, hasDescriptor bool) *descriptorStripper {
	return &descriptorStripper{
		r:             r,
		hasDescriptor: hasDescriptor,
		buf:           make([]byte, descriptorStripperBufSize),
	}
}

// holdBack returns how many pending bytes may still belong to the descriptor.
func (ds *descriptorStripper) holdBack() int {
	if ds.hasDescriptor && !ds.eof {
		return dataDescriptor64Len
	}
	return 0
}

func (ds *descriptorStripper) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if avail := ds.end - ds.start - ds.holdBack(); avail > 0 {
			n := copy(p, ds.buf[ds.start:ds.start+avail])
			ds.start += n
			ds.emitted += int64(n)
			return n, nil
		}
		if ds.eof {
			return 0, io.EOF
		}
		if ds.err != nil {
			return 0, ds.err
		}
		// At most holdBack bytes are pending: move them to the front and refill.
		if ds.start > 0 {
			ds.end = copy(ds.buf, ds.buf[ds.start:ds.end])
			ds.start = 0
		}
		n, err := ds.r.Read(ds.buf[ds.end:])
		ds.end += n
		if err == io.EOF {
			ds.eof = true
			ds.parseDescriptor()
		} else if err != nil {
			ds.err = err
		}
	}
}

// parseDescriptor looks for the data descriptor at the end of the payload.
// Both 32 and 64-bit size variants, with or without signature, are accepted;
// a candidate is only taken if its compressed size equals the number of
// payload bytes preceding it, which rules out data that merely happens to
// contain the signature.
func (ds *descriptorStripper) parseDescriptor() {
	if !ds.hasDescriptor {
		return
	}
	tail := ds.buf[ds.start:ds.end]
	total := ds.emitted + int64(len(tail))
	for _, c := range [...]struct {
		size       int
		sig, zip64 bool
	}{
		{dataDescriptor64Len, true, true},
		{dataDescriptorLen, true, false},
		{dataDescriptor64Len - 4, false, true},
		{dataDescriptorLen - 4, false, false},
	} {
		if len(tail) < c.size {
			continue
		}
		d := tail[len(tail)-c.size:]
		if c.sig {
			if binary.LittleEndian.Uint32(d) != dataDescriptorSignature {
				continue
			}
			d = d[4:]
		}
		desc := DataDescriptor{CRC32: binary.LittleEndian.Uint32(d)}
		if c.zip64 {
			desc.CompressedSize64 = binary.LittleEndian.Uint64(d[4:])
			desc.UncompressedSize64 = binary.LittleEndian.Uint64(d[12:])
		} else {
			desc.CompressedSize64 = uint64(binary.LittleEndian.Uint32(d[4:]))
			desc.UncompressedSize64 = uint64(binary.LittleEndian.Uint32(d[8:]))
		}
		if desc.CompressedSize64 != uint64(total)-uint64(c.size) {
			continue
		}
		ds.desc = &desc
		ds.end -= c.size
		return
	}
}
