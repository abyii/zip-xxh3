package zip

import (
	"errors"
	"hash/crc32"
	"io"

	"github.com/zeebo/xxh3"
)

// CreateRaw adds a file to the zip file using the provided FileHeader.
// The file's contents are expected to be already compressed, but if a password/encryption is set on fh,
// the writer will encrypt the contents as they are written.
func (w *Writer) CreateRaw(fh *FileHeader) (io.Writer, error) {
	if w.detached {
		return nil, errors.New("zip: CreateRaw cannot be used in detached mode")
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

	fw, err := newRawFileWriter(fh, h, w.cw)
	if err != nil {
		return nil, err
	}

	w.last = fw
	return fw, nil
}

// CreateRawFileParts adds a file part to the detached zip file using the provided FileHeader.
func (w *Writer) CreateRawFileParts(fh *FileHeader, order int, partWriter io.Writer) (io.WriteCloser, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	h := &header{
		FileHeader: fh,
		order:      order,
	}

	w.dir = append(w.dir, h)

	return newRawFileWriter(fh, h, partWriter)
}

func newRawFileWriter(fh *FileHeader, h *header, w io.Writer) (*fileWriter, error) {
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
		raw:       true,
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

	fw.comp = nopCloser{sw}
	fw.rawCount = &countWriter{w: fw.comp}

	if err := writeHeader(w, fh); err != nil {
		return nil, err
	}

	return fw, nil
}

// OverridableFileHeader represents safe metadata fields that are allowed to be modified
// during raw copying/re-keying without affecting the compressed data integrity.
type OverridableFileHeader struct {
	Name           string
	ModifiedTime   uint16
	ModifiedDate   uint16
	Comment        string
	XXH3           uint64
	CreatorVersion uint16
	ReaderVersion  uint16
	ExternalAttrs  uint32
	Extra          []byte
}

// CopyRawPart re-keys and copies a single file part (local header + encrypted content + optional descriptor)
// from `src` to the Writer, without decompressing and re-compressing the data.
// It decrypts the source using `oldPassword` (if encrypted with ZipCrypto) and
// encrypts it using `newPassword` (if provided) under raw writing.
// It allows modifying the FileHeader metadata (such as filename, modification time, extra fields, comment,
// or XXH3 checksum) via the optional `modifyHeader` callback before writing.
// This operates with strictly constant memory overhead and runs synchronously.
func (w *Writer) CopyRawPart(src io.Reader, oldPassword, newPassword string, modifyHeader func(*OverridableFileHeader)) error {
	fh, err := ReadLocalFileHeader(src)
	if err != nil {
		return err
	}

	override := &OverridableFileHeader{
		Name:           fh.Name,
		ModifiedTime:   fh.ModifiedTime,
		ModifiedDate:   fh.ModifiedDate,
		Comment:        fh.Comment,
		XXH3:           fh.XXH3,
		CreatorVersion: fh.CreatorVersion,
		ReaderVersion:  fh.ReaderVersion,
		ExternalAttrs:  fh.ExternalAttrs,
		Extra:          fh.Extra,
	}

	if modifyHeader != nil {
		modifyHeader(override)
	}

	// Apply overridden values back to the FileHeader
	fh.Name = override.Name
	fh.ModifiedTime = override.ModifiedTime
	fh.ModifiedDate = override.ModifiedDate
	fh.Comment = override.Comment
	fh.XXH3 = override.XXH3
	fh.CreatorVersion = override.CreatorVersion
	fh.ReaderVersion = override.ReaderVersion
	fh.ExternalAttrs = override.ExternalAttrs
	fh.Extra = override.Extra

	if newPassword != "" {
		fh.SetPassword(newPassword)
		fh.SetEncryptionMethod(StandardEncryption)
	} else {
		fh.Flags &^= 0x1
		fh.password = nil
		fh.encryption = NoEncryption
	}

	tw, err := w.CreateRaw(fh)
	if err != nil {
		return err
	}

	hasDescriptor := (fh.Flags & 0x8) != 0
	stripper := newDescriptorStripper(src, hasDescriptor)

	var decryptedSrc io.Reader = stripper
	if oldPassword != "" {
		decryptedSrc = NewZipCryptoDecryptReader(stripper, []byte(oldPassword))
	}

	if _, err := io.Copy(tw, decryptedSrc); err != nil {
		return err
	}

	if stripper.desc != nil {
		fh.CRC32 = stripper.desc.CRC32
		fh.CompressedSize64 = stripper.desc.CompressedSize64
		fh.UncompressedSize64 = stripper.desc.UncompressedSize64
	}

	return w.last.Close()
}
