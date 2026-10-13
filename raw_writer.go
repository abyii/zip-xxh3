package zip

import (
	"errors"
	"hash/crc32"
	"io"
	"math"

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

	fw, err := newRawFileWriter(fh, h, w.cw)
	if err != nil {
		return nil, err
	}
	w.dir = append(w.dir, h)

	w.last = fw
	return fw, nil
}

// CreateRawFileParts adds a file part to the detached zip file using the provided FileHeader.
func (w *Writer) CreateRawFileParts(fh *FileHeader, order int, partWriter io.Writer) (io.WriteCloser, error) {
	h := &header{
		FileHeader: fh,
		order:      order,
	}

	fw, err := newRawFileWriter(fh, h, partWriter)
	if err != nil {
		return nil, err
	}
	w.addDetachedHeader(h)
	return fw, nil
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
			if closer, ok := ew.(io.Closer); ok {
				fw.enc = closer
			}
		} else {
			// we have a password and need to encrypt.
			fh.writeWinZipExtra()
			fh.Method = winzipAesMethod // ok to change, we've gotten the comp and wrote extra
			ew, err := newEncryptionWriter(sw, fh.password, fw, fh.aesStrength)
			if err != nil {
				return nil, err
			}
			sw = ew
			if closer, ok := ew.(io.Closer); ok {
				fw.enc = closer
			}
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
//
// An encrypted source requires oldPassword; a wrong oldPassword is reported as
// ErrPassword before anything is written. WinZip AES sources are not supported.
func (w *Writer) CopyRawPart(src io.Reader, oldPassword, newPassword string, modifyHeader func(*OverridableFileHeader)) error {
	fh, err := ReadLocalFileHeader(src)
	if err != nil {
		return err
	}

	sourceEncrypted := (fh.Flags & 0x1) != 0
	hasDescriptor := (fh.Flags & 0x8) != 0
	if sourceEncrypted {
		if fh.Method == winzipAesMethod {
			return errors.New("zip: CopyRawPart does not support AES encrypted entries")
		}
		if oldPassword == "" {
			return ErrPassword
		}
	}
	// The ZipCrypto check byte is derived from the source header, so capture
	// it before any metadata override.
	_, check := zipCryptoCheckBytes(fh.Flags, fh.ModifiedTime, fh.CRC32)

	// A zip64 extra in the source local header describes the source sizes;
	// the writer emits its own zip64 record where needed.
	fh.Extra = removeExtraField(fh.Extra, zip64ExtraId)

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

	if newPassword != "" && sourceEncrypted {
		fh.SetPassword(newPassword)
		fh.SetEncryptionMethod(StandardEncryption)
	} else {
		fh.Flags &^= 0x1
		fh.password = nil
		fh.encryption = NoEncryption
	}

	// Without a descriptor the local header holds the authoritative sizes;
	// with one, the payload runs to the end of src and ends with it.
	var payload io.Reader
	var stripper *descriptorStripper
	var limited *io.LimitedReader
	if hasDescriptor {
		stripper = newDescriptorStripper(src, true)
		payload = stripper
	} else {
		if fh.CompressedSize64 > math.MaxInt64 {
			return ErrFormat
		}
		limited = &io.LimitedReader{R: src, N: int64(fh.CompressedSize64)}
		payload = limited
	}

	if sourceEncrypted {
		dr := newZipCryptoDecryptReader(payload, []byte(oldPassword), check, true)
		// Reject a wrong password before writing anything.
		if err := dr.readHeader(); err != nil {
			return err
		}
		payload = dr
	}

	tw, err := w.CreateRaw(fh)
	if err != nil {
		return err
	}

	if _, err := io.Copy(tw, payload); err != nil {
		return err
	}

	if limited != nil && limited.N != 0 {
		return io.ErrUnexpectedEOF
	}
	if stripper != nil {
		if stripper.desc == nil {
			return errors.New("zip: data descriptor not found at end of raw part")
		}
		fh.CRC32 = stripper.desc.CRC32
		fh.CompressedSize64 = stripper.desc.CompressedSize64
		fh.UncompressedSize64 = stripper.desc.UncompressedSize64
	}

	return w.last.Close()
}
