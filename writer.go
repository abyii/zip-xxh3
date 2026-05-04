// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zip

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"hash"
	"hash/crc32"
	"io"
	"sort"
	"sync"

	"github.com/zeebo/xxh3"
)

// TODO(adg): support zip file comments

// Writer implements a zip file writer.
type Writer struct {
	cw               *countWriter
	dir              []*header
	last             *fileWriter
	closed           bool
	detached         bool
	mu               sync.Mutex
	centralDirectory []byte
}

type header struct {
	*FileHeader
	offset uint64
	order  int
}

// NewWriter returns a new Writer writing a zip file to w.
func NewWriter(w ...io.Writer) *Writer {
	if len(w) > 1 {
		panic("zip: NewWriter only supports one writer")
	}
	if len(w) == 1 {
		return &Writer{cw: &countWriter{w: bufio.NewWriter(w[0])}}
	}
	return &Writer{detached: true}
}

// SetOffset sets the offset of the beginning of the zip data within the
// underlying writer. It should be used when the zip data is appended to an
// existing file, such as a binary executable.
// It must be called before any data is written.
func (w *Writer) SetOffset(n int64) {
	if w.cw.count != 0 {
		panic("zip: SetOffset called after data was written")
	}
	w.cw.count = n
}

// Flush flushes any buffered data to the underlying writer.
// Calling Flush is not normally necessary; calling Close is sufficient.
func (w *Writer) Flush() error {
	if w.detached {
		return nil
	}
	return w.cw.w.(*bufio.Writer).Flush()
}

// Close finishes writing the zip file by writing the central directory.
// It does not (and can not) close the underlying writer.
func (w *Writer) Close() error {
	if w.last != nil && !w.last.closed {
		if err := w.last.Close(); err != nil {
			return err
		}
		w.last = nil
	}
	if w.closed {
		return errors.New("zip: writer closed twice")
	}
	w.closed = true

	if w.detached {
		w.generateCentralDirectory()
		return nil
	}

	// write central directory
	start := w.cw.count
	for _, h := range w.dir {
		var buf [directoryHeaderLen]byte
		b := writeBuf(buf[:])
		b.uint32(uint32(directoryHeaderSignature))
		b.uint16(h.CreatorVersion)
		b.uint16(h.ReaderVersion)
		b.uint16(h.Flags)
		b.uint16(h.Method)
		b.uint16(h.ModifiedTime)
		b.uint16(h.ModifiedDate)
		b.uint32(h.CRC32)

		// adding xxh3
		if h.XXH3 != 0 {
			var buf [12]byte
			eb := writeBuf(buf[:])
			eb.uint16(xxh3ExtraId)
			eb.uint16(8) // size = 1x uint64
			eb.uint64(h.XXH3)
			h.Extra = append(h.Extra, buf[:]...)
		}

		if h.isZip64() || h.offset > uint32max {
			// the file needs a zip64 header. store maxint in both
			// 32 bit size fields (and offset later) to signal that the
			// zip64 extra header should be used.
			b.uint32(uint32max) // compressed size
			b.uint32(uint32max) // uncompressed size

			// append a zip64 extra block to Extra
			var buf [28]byte // 2x uint16 + 3x uint64
			eb := writeBuf(buf[:])
			eb.uint16(zip64ExtraId)
			eb.uint16(24) // size = 3x uint64
			eb.uint64(h.UncompressedSize64)
			eb.uint64(h.CompressedSize64)
			eb.uint64(h.offset)
			h.Extra = append(h.Extra, buf[:]...)
		} else {
			b.uint32(h.CompressedSize)
			b.uint32(h.UncompressedSize)
		}
		b.uint16(uint16(len(h.Name)))
		b.uint16(uint16(len(h.Extra)))
		b.uint16(uint16(len(h.Comment)))
		b = b[4:] // skip disk number start and internal file attr (2x uint16)
		b.uint32(h.ExternalAttrs)
		if h.offset > uint32max {
			b.uint32(uint32max)
		} else {
			b.uint32(uint32(h.offset))
		}
		if _, err := w.cw.Write(buf[:]); err != nil {
			return err
		}
		if _, err := io.WriteString(w.cw, h.Name); err != nil {
			return err
		}
		if _, err := w.cw.Write(h.Extra); err != nil {
			return err
		}
		if _, err := io.WriteString(w.cw, h.Comment); err != nil {
			return err
		}
	}
	end := w.cw.count

	records := uint64(len(w.dir))
	size := uint64(end - start)
	offset := uint64(start)

	if records > uint16max || size > uint32max || offset > uint32max {
		var buf [directory64EndLen + directory64LocLen]byte
		b := writeBuf(buf[:])

		// zip64 end of central directory record
		b.uint32(directory64EndSignature)
		b.uint64(directory64EndLen - 12) // length minus signature (uint32) and length fields (uint64)
		b.uint16(zipVersion45)           // version made by
		b.uint16(zipVersion45)           // version needed to extract
		b.uint32(0)                      // number of this disk
		b.uint32(0)                      // number of the disk with the start of the central directory
		b.uint64(records)                // total number of entries in the central directory on this disk
		b.uint64(records)                // total number of entries in the central directory
		b.uint64(size)                   // size of the central directory
		b.uint64(offset)                 // offset of start of central directory with respect to the starting disk number

		// zip64 end of central directory locator
		b.uint32(directory64LocSignature)
		b.uint32(0)           // number of the disk with the start of the zip64 end of central directory
		b.uint64(uint64(end)) // relative offset of the zip64 end of central directory record
		b.uint32(1)           // total number of disks

		if _, err := w.cw.Write(buf[:]); err != nil {
			return err
		}

		// store max values in the regular end record to signal that
		// that the zip64 values should be used instead
		records = uint16max
		size = uint32max
		offset = uint32max
	}

	// write end record
	var buf [directoryEndLen]byte
	b := writeBuf(buf[:])
	b.uint32(uint32(directoryEndSignature))
	b = b[4:]                 // skip over disk number and first disk number (2x uint16)
	b.uint16(uint16(records)) // number of entries this disk
	b.uint16(uint16(records)) // number of entries total
	b.uint32(uint32(size))    // size of directory
	b.uint32(uint32(offset))  // start of directory
	// skipped size of comment (always zero)
	if _, err := w.cw.Write(buf[:]); err != nil {
		return err
	}

	return w.cw.w.(*bufio.Writer).Flush()
}

// Create adds a file to the zip file using the provided name, compression and encryption options.
// It returns a Writer to which the file contents should be written.
// The name must be a relative path: it must not start with a drive
// letter (e.g. C:) or leading slash, and only forward slashes are
// allowed.
// The file's contents must be written to the io.Writer before the next
// call to Create, CreateHeader, or Close.
func createHeader(name string, method uint16, level int, enc EncryptionMethod, password string) (*FileHeader, error) {
	if method == Store && level != 0 {
		return nil, errors.New("archive/zip: invalid compression level for store method. Should be 0.")
	}
	if enc != NoEncryption && method != Deflate {
		return nil, errors.New("archive/zip: encryption method only supported for deflate method.")
	}
	if enc != NoEncryption && password == "" {
		return nil, errors.New("archive/zip: password required for encryption method.")
	}
	if password != "" && enc == NoEncryption {
		return nil, errors.New("archive/zip: encryption method required for password.")
	}
	header := &FileHeader{
		Name:             name,
		Method:           method,
		CompressionLevel: level,
	}
	if enc != NoEncryption {
		header.SetEncryptionMethod(enc)
		header.SetPassword(password)
	}
	return header, nil
}

// Create adds a file to the zip file using the provided name, compression and encryption options.
// It returns a Writer to which the file contents should be written.
// The name must be a relative path: it must not start with a drive
// letter (e.g. C:) or leading slash, and only forward slashes are
// allowed.
// The file's contents must be written to the io.Writer before the next
// call to Create, CreateHeader, or Close.
func (w *Writer) Create(name string, method uint16, level int, enc EncryptionMethod, password string) (io.Writer, error) {
	header, err := createHeader(name, method, level, enc, password)
	if err != nil {
		return nil, err
	}
	return w.CreateHeader(header)
}

// CreateHeader adds a file to the zip file using the provided FileHeader
// for the file metadata.
// It returns a Writer to which the file contents should be written.
//
// The file's contents must be written to the io.Writer before the next
// call to Create, CreateHeader, or Close. The provided FileHeader fh
// must not be modified after a call to CreateHeader.
func (w *Writer) CreateHeader(fh *FileHeader) (io.Writer, error) {
	if w.detached {
		return nil, errors.New("zip: CreateHeader cannot be used in detached mode")
	}
	if w.last != nil && !w.last.closed {
		if err := w.last.Close(); err != nil {
			return nil, err
		}
	}
	if len(w.dir) > 0 && w.dir[len(w.dir)-1].FileHeader == fh {
		// See https://golang.org/issue/11144 confusion.
		return nil, errors.New("archive/zip: invalid duplicate FileHeader")
	}

	h := &header{
		FileHeader: fh,
		offset:     uint64(w.cw.count),
	}
	w.dir = append(w.dir, h)

	fw, err := newFileWriter(fh, h, w.cw)
	if err != nil {
		return nil, err
	}

	w.last = fw
	return fw, nil
}

func newFileWriter(fh *FileHeader, h *header, w io.Writer) (*fileWriter, error) {
	fh.Flags |= 0x8                                             // we will write a data descriptor
	fh.CreatorVersion = fh.CreatorVersion&0xff00 | zipVersion20 // preserve compatibility byte
	fh.ReaderVersion = zipVersion20

	compCount := &countWriter{w: w}

	fw := &fileWriter{
		zipw:      w,
		compCount: compCount,
		crc32:     crc32.NewIEEE(),
		xxh3:      xxh3.New(),
		header:    h,
	}

	comp := compressor(fh.Method, fh.CompressionLevel)
	if comp == nil {
		return nil, ErrAlgorithm
	}

	var sw io.Writer = fw.compCount
	// check for password
	if fh.password != nil {
		if fh.encryption == StandardEncryption {
			ew, err := ZipCryptoEncryptor(sw, fh.password, fw)
			if err != nil {
				return nil, err
			}
			sw = ew
		} else {
			// we have a password and need to encrypt.
			fh.writeWinZipExtra()
			fh.Method = 99 // ok to change, we've gotten the comp and wrote extra
			ew, err := newEncryptionWriter(sw, fh.password, fw, fh.aesStrength)
			if err != nil {
				return nil, err
			}
			sw = ew
		}
	}

	var err error
	fw.comp, err = comp(sw)
	if err != nil {
		return nil, err
	}
	fw.rawCount = &countWriter{w: fw.comp}

	if err := writeHeader(w, fh); err != nil {
		return nil, err
	}

	return fw, nil
}

// CreateFilePartSimple adds a file to the zip file using the provided name, compression and encryption options.
// It returns a Writer to which the file contents should be written.
// This is for detached mode.
func (w *Writer) CreateFilePartSimple(name string, method uint16, level int, enc EncryptionMethod, password string, order int, partWriter io.Writer) (io.WriteCloser, error) {
	header, err := createHeader(name, method, level, enc, password)
	if err != nil {
		return nil, err
	}
	return w.CreateFileParts(header, order, partWriter)
}

func (w *Writer) CreateFileParts(fh *FileHeader, order int, partWriter io.Writer) (io.WriteCloser, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	h := &header{
		FileHeader: fh,
		order:      order,
	}

	w.dir = append(w.dir, h)

	return newFileWriter(fh, h, partWriter)
}

// AddFileWithOffset explicitly registers a file in the Central Directory
// with a pre-calculated byte offset. This is specifically for detached
// streaming modes where you manually construct the file blocks.
func (w *Writer) AddFileWithOffset(fh *FileHeader, order int, offset uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	h := &header{
		FileHeader: fh,
		order:      order,
		offset:     offset,
	}
	w.dir = append(w.dir, h)
}

func writeHeader(w io.Writer, h *FileHeader) error {
	var buf [fileHeaderLen]byte
	b := writeBuf(buf[:])
	b.uint32(uint32(fileHeaderSignature))
	b.uint16(h.ReaderVersion)
	b.uint16(h.Flags)
	b.uint16(h.Method)
	b.uint16(h.ModifiedTime)
	b.uint16(h.ModifiedDate)
	b.uint32(0) // since we are writing a data descriptor crc32,
	b.uint32(0) // compressed size,
	b.uint32(0) // and uncompressed size should be zero
	b.uint16(uint16(len(h.Name)))
	b.uint16(uint16(len(h.Extra)))
	if _, err := w.Write(buf[:]); err != nil {
		return err
	}
	if _, err := io.WriteString(w, h.Name); err != nil {
		return err
	}
	_, err := w.Write(h.Extra)
	return err
}

type fileWriter struct {
	*header
	zipw       io.Writer
	rawCount   *countWriter
	comp       io.WriteCloser
	compCount  *countWriter
	crc32      hash.Hash32
	xxh3       hash.Hash64
	closed     bool
	partWriter io.Writer

	hmac hash.Hash // possible hmac used for authentication when encrypting
}

func (w *fileWriter) Write(p []byte) (int, error) {
	if w.closed {
		return 0, errors.New("zip: write to closed file")
	}
	w.crc32.Write(p)
	w.xxh3.Write(p)
	return w.rawCount.Write(p)
}

func (w *fileWriter) Close() error {
	if w.closed {
		return errors.New("zip: file closed twice")
	}
	w.closed = true
	if err := w.comp.Close(); err != nil {
		return err
	}
	// if encrypted grab the hmac and write it out
	if w.header.IsEncrypted() && w.header.encryption != StandardEncryption {
		authCode := w.hmac.Sum(nil)
		authCode = authCode[:10]
		_, err := w.compCount.Write(authCode)
		if err != nil {
			return errors.New("zip: error writing authcode")
		}
	}
	// update FileHeader
	fh := w.header.FileHeader
	// ae-2 we don't write out CRC
	if !fh.IsEncrypted() || fh.encryption == StandardEncryption {
		fh.CRC32 = w.crc32.Sum32()
	}
	fh.XXH3 = w.xxh3.Sum64()
	fh.CompressedSize64 = uint64(w.compCount.count)
	fh.UncompressedSize64 = uint64(w.rawCount.count)

	if fh.isZip64() {
		fh.CompressedSize = uint32max
		fh.UncompressedSize = uint32max
		fh.ReaderVersion = zipVersion45 // requires 4.5 - File uses ZIP64 format extensions
	} else {
		fh.CompressedSize = uint32(fh.CompressedSize64)
		fh.UncompressedSize = uint32(fh.UncompressedSize64)
	}

	// Write data descriptor. This is more complicated than one would
	// think, see e.g. comments in zipfile.c:putextended() and
	// http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=7073588.
	// The approach here is to write 8 byte sizes if needed without
	// adding a zip64 extra in the local header (too late anyway).
	var buf []byte
	if fh.isZip64() {
		buf = make([]byte, dataDescriptor64Len)
	} else {
		buf = make([]byte, dataDescriptorLen)
	}
	b := writeBuf(buf)
	if !fh.IsEncrypted() || fh.encryption == StandardEncryption {
		b.uint32(dataDescriptorSignature) // de-facto standard, required by OS X
	}
	b.uint32(fh.CRC32)
	if fh.isZip64() {
		b.uint64(fh.CompressedSize64)
		b.uint64(fh.UncompressedSize64)
	} else {
		b.uint32(fh.CompressedSize)
		b.uint32(fh.UncompressedSize)
	}

	written := len(buf) - len(b)
	_, err := w.zipw.Write(buf[:written])
	return err
}

type countWriter struct {
	w     io.Writer
	count int64
}

func (w *countWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.count += int64(n)
	return n, err
}

type nopCloser struct {
	io.Writer
}

func (w nopCloser) Close() error {
	return nil
}

type writeBuf []byte

func (b *writeBuf) uint8(v uint8) {
	(*b)[0] = v
	*b = (*b)[1:]
}

func (b *writeBuf) uint16(v uint16) {
	binary.LittleEndian.PutUint16(*b, v)
	*b = (*b)[2:]
}

func (b *writeBuf) uint32(v uint32) {
	binary.LittleEndian.PutUint32(*b, v)
	*b = (*b)[4:]
}

func (b *writeBuf) uint64(v uint64) {
	binary.LittleEndian.PutUint64(*b, v)
	*b = (*b)[8:]
}

func (w *Writer) generateCentralDirectory() {
	// protect concurrent access to w.dir
	w.mu.Lock()
	defer w.mu.Unlock()

	// if central directory is already generated, do nothing
	if w.centralDirectory != nil {
		return
	}

	sort.SliceStable(w.dir, func(i, j int) bool {
		return w.dir[i].order < w.dir[j].order
	})

	var offset uint64
	for _, h := range w.dir {
		// Only recalculate offset if it was not explicitly provided by AddFileWithOffset
		if h.offset == 0 && offset > 0 {
			h.offset = offset
		} else if h.offset > 0 {
			offset = h.offset
		} else {
			h.offset = offset
		}

		partLen := uint64(fileHeaderLen + len(h.Name) + len(h.Extra))
		partLen += h.CompressedSize64

		ddLen := uint64(dataDescriptorLen)
		if h.isZip64() {
			ddLen = uint64(dataDescriptor64Len)
		}
		if h.IsEncrypted() && h.encryption != StandardEncryption {
			ddLen -= 4
		}
		partLen += ddLen
		offset += partLen
	}

	buf := new(bytes.Buffer)
	for _, h := range w.dir {
		var cbuf [directoryHeaderLen]byte
		b := writeBuf(cbuf[:])
		b.uint32(uint32(directoryHeaderSignature))
		b.uint16(h.CreatorVersion)
		b.uint16(h.ReaderVersion)
		b.uint16(h.Flags)
		b.uint16(h.Method)
		b.uint16(h.ModifiedTime)
		b.uint16(h.ModifiedDate)
		b.uint32(h.CRC32)

		// adding xxh3
		if h.XXH3 != 0 {
			var xxh3buf [12]byte
			eb := writeBuf(xxh3buf[:])
			eb.uint16(xxh3ExtraId)
			eb.uint16(8) // size = 1x uint64
			eb.uint64(h.XXH3)
			h.Extra = append(h.Extra, xxh3buf[:]...)
		}

		if h.isZip64() || h.offset > uint32max {
			// the file needs a zip64 header. store maxint in both
			// 32 bit size fields (and offset later) to signal that the
			// zip64 extra header should be used.
			b.uint32(uint32max) // compressed size
			b.uint32(uint32max) // uncompressed size

			// append a zip64 extra block to Extra
			var zip64buf [28]byte // 2x uint16 + 3x uint64
			eb := writeBuf(zip64buf[:])
			eb.uint16(zip64ExtraId)
			eb.uint16(24) // size = 3x uint64
			eb.uint64(h.UncompressedSize64)
			eb.uint64(h.CompressedSize64)
			eb.uint64(h.offset)
			h.Extra = append(h.Extra, zip64buf[:]...)
		} else {
			b.uint32(h.CompressedSize)
			b.uint32(h.UncompressedSize)
		}
		b.uint16(uint16(len(h.Name)))
		b.uint16(uint16(len(h.Extra)))
		b.uint16(uint16(len(h.Comment)))
		b = b[4:] // skip disk number start and internal file attr (2x uint16)
		b.uint32(h.ExternalAttrs)
		if h.offset > uint32max {
			b.uint32(uint32max)
		} else {
			b.uint32(uint32(h.offset))
		}
		if _, err := buf.Write(cbuf[:]); err != nil {
			panic(err)
		}
		if _, err := io.WriteString(buf, h.Name); err != nil {
			panic(err)
		}
		if _, err := buf.Write(h.Extra); err != nil {
			panic(err)
		}
		if _, err := io.WriteString(buf, h.Comment); err != nil {
			panic(err)
		}
	}

	records := uint64(len(w.dir))
	size := uint64(buf.Len())

	if records > uint16max || size > uint32max || offset > uint32max {
		var ebuf [directory64EndLen + directory64LocLen]byte
		b := writeBuf(ebuf[:])

		// zip64 end of central directory record
		b.uint32(directory64EndSignature)
		b.uint64(directory64EndLen - 12) // length minus signature (uint32) and length fields (uint64)
		b.uint16(zipVersion45)           // version made by
		b.uint16(zipVersion45)           // version needed to extract
		b.uint32(0)                      // number of this disk
		b.uint32(0)                      // number of the disk with the start of the central directory
		b.uint64(records)                // total number of entries in the central directory on this disk
		b.uint64(records)                // total number of entries in the central directory
		b.uint64(size)                   // size of the central directory
		b.uint64(offset)                 // offset of start of central directory with respect to the starting disk number

		// zip64 end of central directory locator
		b.uint32(directory64LocSignature)
		b.uint32(0)             // number of the disk with the start of the zip64 end of central directory
		b.uint64(offset + size) // relative offset of the zip64 end of central directory record
		b.uint32(1)             // total number of disks

		if _, err := buf.Write(ebuf[:]); err != nil {
			panic(err)
		}

		// store max values in the regular end record to signal that
		// that the zip64 values should be used instead
		records = uint16max
		size = uint32max
		offset = uint32max
	}

	// write end record
	var ebuf [directoryEndLen]byte
	b := writeBuf(ebuf[:])
	b.uint32(uint32(directoryEndSignature))
	b = b[4:]                 // skip over disk number and first disk number (2x uint16)
	b.uint16(uint16(records)) // number of entries this disk
	b.uint16(uint16(records)) // number of entries total
	b.uint32(uint32(size))    // size of directory
	b.uint32(uint32(offset))  // start of directory
	// skipped size of comment (always zero)
	if _, err := buf.Write(ebuf[:]); err != nil {
		panic(err)
	}

	w.centralDirectory = buf.Bytes()
}

func (w *Writer) GetCentralDirectoryBytes() ([]byte, error) {
	if !w.detached {
		return nil, errors.New("zip: GetCentralDirectoryBytes cannot be used in non-detached mode")
	}
	w.generateCentralDirectory()
	return w.centralDirectory, nil
}
