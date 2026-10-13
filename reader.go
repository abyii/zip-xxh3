// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zip

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"os"

	"github.com/zeebo/xxh3"
)

var (
	ErrFormat    = errors.New("zip: not a valid zip file")
	ErrAlgorithm = errors.New("zip: unsupported compression algorithm")
	ErrChecksum  = errors.New("zip: checksum error")
	ErrXXH3      = errors.New("zip: xxh3 checksum error")
)

type Reader struct {
	r       io.ReaderAt
	File    []*File
	Comment string
}

type ReadCloser struct {
	f *os.File
	Reader
}

type File struct {
	FileHeader
	zipr         io.ReaderAt
	zipsize      int64
	headerOffset int64
}

func (f *File) hasDataDescriptor() bool {
	return f.Flags&0x8 != 0
}

// OpenReader will open the Zip file specified by name and return a ReadCloser.
func OpenReader(name string) (*ReadCloser, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	r := new(ReadCloser)
	if err := r.init(f, fi.Size()); err != nil {
		f.Close()
		return nil, err
	}
	r.f = f
	return r, nil
}

// NewReader returns a new Reader reading from r, which is assumed to
// have the given size in bytes.
func NewReader(r io.ReaderAt, size int64) (*Reader, error) {
	zr := new(Reader)
	if err := zr.init(r, size); err != nil {
		return nil, err
	}
	return zr, nil
}

func (z *Reader) init(r io.ReaderAt, size int64) error {
	end, err := readDirectoryEnd(r, size)
	if err != nil {
		return err
	}
	if end.directoryRecords > uint64(size)/fileHeaderLen {
		return fmt.Errorf("archive/zip: TOC declares impossible %d files in %d byte zip", end.directoryRecords, size)
	}
	z.r = r
	dirOffset := int64(end.directoryOffset)
	// Every record takes at least directoryHeaderLen bytes of the remaining
	// file, so don't let a forged record count drive the preallocation.
	z.File = make([]*File, 0, min(end.directoryRecords, uint64(size-dirOffset)/directoryHeaderLen))
	z.Comment = end.comment
	// Everything from the directory offset to the end of the file is the
	// central directory followed by the end records; buffer it all so that
	// it is fetched with a single ReadAt (important for remote ReaderAts).
	rs := io.NewSectionReader(r, dirOffset, size-dirOffset)
	buf := bufio.NewReaderSize(rs, int(min(size-dirOffset, maxCentralDirectoryBuffer)))

	// The count of files inside a zip is truncated to fit in a uint16.
	// Gloss over this by reading headers until we encounter
	// a bad one, and then only report a ErrFormat or UnexpectedEOF if
	// the file count modulo 65536 is incorrect.
	for {
		f := &File{zipr: r, zipsize: size}
		err = readDirectoryHeader(f, buf)
		if err == ErrFormat || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return err
		}
		z.File = append(z.File, f)
	}
	if uint16(len(z.File)) != uint16(end.directoryRecords) { // only compare 16 bits here
		// Return the readDirectoryHeader error if we read
		// the wrong number of directory entries.
		return err
	}
	return nil
}

const (
	// maxCentralDirectoryBuffer bounds the buffer used to read the central
	// directory.
	maxCentralDirectoryBuffer = 4 << 20
	// maxEntryReadBuffer bounds the read-ahead buffer placed in front of
	// decompressors when reading an entry.
	maxEntryReadBuffer = 64 << 10
)

// Close closes the Zip file, rendering it unusable for I/O.
func (rc *ReadCloser) Close() error {
	return rc.f.Close()
}

// DataOffset returns the offset of the file's possibly-compressed
// data, relative to the beginning of the zip file.
//
// Most callers should instead use Open, which transparently
// decompresses data and verifies checksums.
func (f *File) DataOffset() (offset int64, err error) {
	bodyOffset, err := f.findBodyOffset()
	if err != nil {
		return
	}
	return f.headerOffset + bodyOffset, nil
}

// HeaderOffset returns the offset of the file's local file header,
// relative to the beginning of the zip file. It does no I/O.
func (f *File) HeaderOffset() int64 {
	return f.headerOffset
}

func (f *File) VerifyXXH3() error {
	if f.XXH3 == 0 {
		return nil
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	h := xxh3.New()
	_, err = io.Copy(h, rc)
	if err != nil {
		return err
	}
	if h.Sum64() != f.XXH3 {
		return ErrXXH3
	}
	return nil
}

func (r *Reader) SetPassword(password string) {
	for _, f := range r.File {
		f.SetPassword(password)
	}
}

// Open returns a ReadCloser that provides access to the File's contents.
// Multiple files may be read concurrently.
func (f *File) Open() (rc io.ReadCloser, err error) {
	bodyOffset, err := f.findBodyOffset()
	if err != nil {
		return
	}
	// If f is encrypted, CompressedSize64 includes salt, pwvv, encrypted data,
	// and auth code lengths
	size := int64(f.CompressedSize64)
	rr := io.NewSectionReader(f.zipr, f.headerOffset+bodyOffset, size)
	var r io.Reader = rr
	// check for encryption
	if f.IsEncrypted() {
		if f.password == nil {
			err = ErrPassword
			return
		}
		if f.ae == 0 {
			_, check := zipCryptoCheckBytes(f.Flags, f.ModifiedTime, f.CRC32)
			zr := newZipCryptoDecryptReader(rr, f.password(), check, true)
			// Verify the password check byte up front so a wrong password
			// fails Open instead of producing garbage.
			if err = zr.readHeader(); err != nil {
				return
			}
			r = zr
		} else if r, err = newDecryptionReader(rr, f); err != nil {
			return
		}
	}
	dcomp := decompressor(f.Method)
	if dcomp == nil {
		err = ErrAlgorithm
		return
	}
	if f.Method != Store {
		// Decompressors read in small chunks (flate uses a 4 KiB bufio);
		// read ahead in larger blocks to keep the number of ReadAt calls low.
		r = bufio.NewReaderSize(r, int(min(max(size, 0), maxEntryReadBuffer)))
	}
	rc = dcomp(r)
	// If AE-2, skip CRC and possible dataDescriptor
	if f.isAE2() {
		return
	}
	var desr io.Reader
	if f.hasDataDescriptor() {
		desr = io.NewSectionReader(f.zipr, f.headerOffset+bodyOffset+size, dataDescriptorLen)
	}
	rc = &checksumReader{
		rc:   rc,
		hash: crc32.NewIEEE(),
		f:    f,
		desr: desr,
	}
	return
}

type checksumReader struct {
	rc    io.ReadCloser
	hash  hash.Hash32
	nread uint64 // number of bytes read so far
	f     *File
	desr  io.Reader // if non-nil, where to read the data descriptor
	err   error     // sticky error
}

func (r *checksumReader) Read(b []byte) (n int, err error) {
	if r.err != nil {
		return 0, r.err
	}
	n, err = r.rc.Read(b)
	r.hash.Write(b[:n])
	r.nread += uint64(n)
	if err == nil {
		return
	}
	if err == io.EOF {
		if r.nread != r.f.UncompressedSize64 {
			err = io.ErrUnexpectedEOF
		} else if r.desr != nil {
			if err1 := readDataDescriptor(r.desr, r.f); err1 != nil {
				if err1 == io.EOF {
					err = io.ErrUnexpectedEOF
				} else {
					err = err1
				}
			} else if r.hash.Sum32() != r.f.CRC32 {
				err = ErrChecksum
			}
		} else {
			// If there's not a data descriptor, we still compare
			// the CRC32 of what we've read against the file header
			// or TOC's CRC32, if it seems like it was set.
			if r.f.CRC32 != 0 && r.hash.Sum32() != r.f.CRC32 {
				err = ErrChecksum
			}
		}
	}
	r.err = err
	return
}

func (r *checksumReader) Close() error { return r.rc.Close() }

// findBodyOffset does the minimum work to verify the file has a header
// and returns the file body offset.
func (f *File) findBodyOffset() (int64, error) {
	var buf [fileHeaderLen]byte
	if _, err := f.zipr.ReadAt(buf[:], f.headerOffset); err != nil {
		return 0, err
	}
	b := readBuf(buf[:])
	if sig := b.uint32(); sig != fileHeaderSignature {
		return 0, ErrFormat
	}
	b = b[22:] // skip over most of the header
	filenameLen := int(b.uint16())
	extraLen := int(b.uint16())
	return int64(fileHeaderLen + filenameLen + extraLen), nil
}

// readDirectoryHeader attempts to read a directory header from r.
// It returns io.ErrUnexpectedEOF if it cannot read a complete header,
// and ErrFormat if it doesn't find a valid header signature.
func readDirectoryHeader(f *File, r io.Reader) error {
	var buf [directoryHeaderLen]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return err
	}
	b := readBuf(buf[:])
	if sig := b.uint32(); sig != directoryHeaderSignature {
		return ErrFormat
	}
	f.CreatorVersion = b.uint16()
	f.ReaderVersion = b.uint16()
	f.Flags = b.uint16()
	f.Method = b.uint16()
	f.ModifiedTime = b.uint16()
	f.ModifiedDate = b.uint16()
	f.CRC32 = b.uint32()
	f.CompressedSize = b.uint32()
	f.UncompressedSize = b.uint32()
	f.CompressedSize64 = uint64(f.CompressedSize)
	f.UncompressedSize64 = uint64(f.UncompressedSize)
	filenameLen := int(b.uint16())
	extraLen := int(b.uint16())
	commentLen := int(b.uint16())
	b = b[4:] // skipped start disk number and internal attributes (2x uint16)
	f.ExternalAttrs = b.uint32()
	f.headerOffset = int64(b.uint32())
	d := make([]byte, filenameLen+extraLen+commentLen)
	if _, err := io.ReadFull(r, d); err != nil {
		return err
	}
	f.Name = string(d[:filenameLen])
	f.Extra = d[filenameLen : filenameLen+extraLen]
	f.Comment = string(d[filenameLen+extraLen:])

	if len(f.Extra) > 0 {
		b := readBuf(f.Extra)
		for len(b) >= 4 { // need at least tag and size
			tag := b.uint16()
			size := b.uint16()
			if int(size) > len(b) {
				return ErrFormat
			}
			eb := readBuf(b[:size])
			switch tag {
			case zip64ExtraId:
				// update directory values from the zip64 extra block
				if f.UncompressedSize == ^uint32(0) {
					if len(eb) < 8 {
						return ErrFormat
					}
					f.UncompressedSize64 = eb.uint64()
				}
				if f.CompressedSize == ^uint32(0) {
					if len(eb) < 8 {
						return ErrFormat
					}
					f.CompressedSize64 = eb.uint64()
				}
				if f.headerOffset == int64(^uint32(0)) {
					if len(eb) < 8 {
						return ErrFormat
					}
					f.headerOffset = int64(eb.uint64())
				}
			case winzipAesExtraId:
				// AE version (2), vendor ID (2), strength (1), method (2).
				// Ignore truncated fields rather than panic on them.
				if len(eb) < 7 {
					break
				}
				// grab the AE version
				f.ae = eb.uint16()
				// skip vendor ID
				_ = eb.uint16()
				// AES strength
				f.aesStrength = eb.uint8()
				// set the actual compression method.
				f.Method = eb.uint16()
			case xxh3ExtraId:
				if len(eb) >= 8 {
					f.XXH3 = eb.uint64()
				}
			}
			b = b[size:]
		}
		// Should have consumed the whole header.
		// But popular zip & JAR creation tools are broken and
		// may pad extra zeros at the end, so accept those
		// too. See golang.org/issue/8186.
		for _, v := range b {
			if v != 0 {
				return ErrFormat
			}
		}
	}
	return nil
}

func readDataDescriptor(r io.Reader, f *File) error {
	var buf [dataDescriptorLen]byte

	// The spec says: "Although not originally assigned a
	// signature, the value 0x08074b50 has commonly been adopted
	// as a signature value for the data descriptor record.
	// Implementers should be aware that ZIP files may be
	// encountered with or without this signature marking data
	// descriptors and should account for either case when reading
	// ZIP files to ensure compatibility."
	//
	// Read the whole descriptor at once (one ReadAt); a descriptor
	// without signature may be 4 bytes shorter.
	n, err := io.ReadFull(r, buf[:])
	if err == io.ErrUnexpectedEOF && n >= dataDescriptorLen-4 {
		err = nil
	}
	if err != nil {
		return err
	}
	b := readBuf(buf[:n])
	if binary.LittleEndian.Uint32(b) == dataDescriptorSignature {
		if n < dataDescriptorLen {
			return io.ErrUnexpectedEOF
		}
		b = b[4:]
	}
	if b.uint32() != f.CRC32 {
		return ErrChecksum
	}

	// The two sizes that follow here can be either 32 bits or 64 bits
	// but the spec is not very clear on this and different
	// interpretations has been made causing incompatibilities. We
	// already have the sizes from the central directory so we can
	// just ignore these.

	return nil
}

func readDirectoryEnd(r io.ReaderAt, size int64) (dir *directoryEnd, err error) {
	// look for directoryEndSignature in the last 1k, then in the last 65k
	if size < directoryEndLen {
		return nil, ErrFormat
	}
	var buf []byte
	var p int
	var directoryEndOffset int64
	for i, bLen := range []int64{1024, 65 * 1024} {
		if bLen > size {
			bLen = size
		}
		buf = make([]byte, int(bLen))
		if _, err := r.ReadAt(buf, size-bLen); err != nil && err != io.EOF {
			return nil, err
		}
		if p = findSignatureInBlock(buf); p >= 0 {
			directoryEndOffset = size - bLen + int64(p)
			break
		}
		if i == 1 || bLen == size {
			return nil, ErrFormat
		}
	}
	// The zip64 locator immediately precedes the end record; reuse the
	// bytes already read when possible instead of issuing another ReadAt.
	var loc []byte
	if p >= directory64LocLen {
		loc = buf[p-directory64LocLen : p]
	}
	buf = buf[p:]

	// read header into struct
	b := readBuf(buf[4:]) // skip signature
	d := &directoryEnd{
		diskNbr:            uint32(b.uint16()),
		dirDiskNbr:         uint32(b.uint16()),
		dirRecordsThisDisk: uint64(b.uint16()),
		directoryRecords:   uint64(b.uint16()),
		directorySize:      uint64(b.uint32()),
		directoryOffset:    uint64(b.uint32()),
		commentLen:         b.uint16(),
	}
	l := int(d.commentLen)
	if l > len(b) {
		return nil, errors.New("zip: invalid comment length")
	}
	d.comment = string(b[:l])

	var p64 int64
	if loc != nil {
		p64 = parseDirectory64Loc(loc)
	} else {
		p64, err = findDirectory64End(r, directoryEndOffset)
	}
	if err == nil && p64 >= 0 {
		err = readDirectory64End(r, p64, d)
	}
	if err != nil {
		return nil, err
	}

	// Make sure directoryOffset points to somewhere in our file.
	if o := int64(d.directoryOffset); o < 0 || o >= size {
		return nil, ErrFormat
	}
	return d, nil
}

// findDirectory64End tries to read the zip64 locator just before the
// directory end and returns the offset of the zip64 directory end if
// found.
func findDirectory64End(r io.ReaderAt, directoryEndOffset int64) (int64, error) {
	locOffset := directoryEndOffset - directory64LocLen
	if locOffset < 0 {
		return -1, nil // no need to look for a header outside the file
	}
	buf := make([]byte, directory64LocLen)
	if _, err := r.ReadAt(buf, locOffset); err != nil {
		return -1, err
	}
	return parseDirectory64Loc(buf), nil
}

// parseDirectory64Loc returns the zip64 end of central directory offset
// stored in a zip64 locator, or -1 if buf is not a locator.
func parseDirectory64Loc(buf []byte) int64 {
	b := readBuf(buf)
	if sig := b.uint32(); sig != directory64LocSignature {
		return -1
	}
	b = b[4:]       // skip number of the disk with the start of the zip64 end of central directory
	p := b.uint64() // relative offset of the zip64 end of central directory record
	return int64(p)
}

// readDirectory64End reads the zip64 directory end and updates the
// directory end with the zip64 directory end values.
func readDirectory64End(r io.ReaderAt, offset int64, d *directoryEnd) (err error) {
	buf := make([]byte, directory64EndLen)
	if _, err := r.ReadAt(buf, offset); err != nil {
		return err
	}

	b := readBuf(buf)
	if sig := b.uint32(); sig != directory64EndSignature {
		return ErrFormat
	}

	b = b[12:]                        // skip dir size, version and version needed (uint64 + 2x uint16)
	d.diskNbr = b.uint32()            // number of this disk
	d.dirDiskNbr = b.uint32()         // number of the disk with the start of the central directory
	d.dirRecordsThisDisk = b.uint64() // total number of entries in the central directory on this disk
	d.directoryRecords = b.uint64()   // total number of entries in the central directory
	d.directorySize = b.uint64()      // size of the central directory
	d.directoryOffset = b.uint64()    // offset of start of central directory with respect to the starting disk number

	return nil
}

func findSignatureInBlock(b []byte) int {
	for i := len(b) - directoryEndLen; i >= 0; i-- {
		// defined from directoryEndSignature in struct.go
		if b[i] == 'P' && b[i+1] == 'K' && b[i+2] == 0x05 && b[i+3] == 0x06 {
			// n is length of comment
			n := int(b[i+directoryEndLen-2]) | int(b[i+directoryEndLen-1])<<8
			if n+directoryEndLen+i <= len(b) {
				return i
			}
		}
	}
	return -1
}

type readBuf []byte

func (b *readBuf) uint8() byte {
	v := (*b)[0]
	*b = (*b)[1:]
	return v
}

func (b *readBuf) uint16() uint16 {
	v := binary.LittleEndian.Uint16(*b)
	*b = (*b)[2:]
	return v
}

func (b *readBuf) uint32() uint32 {
	v := binary.LittleEndian.Uint32(*b)
	*b = (*b)[4:]
	return v
}

func (b *readBuf) uint64() uint64 {
	v := binary.LittleEndian.Uint64(*b)
	*b = (*b)[8:]
	return v
}
