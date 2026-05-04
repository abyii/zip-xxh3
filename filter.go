package zip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sort"
)

// FilterZipStream takes a parsed zip.Reader and a sequential io.Reader (stream)
// representing the exact same underlying zip file data. It evaluates the provided
// filter function for each file. Matched files are streamed efficiently from 'stream'
// directly into 'w', preserving their original compressed byte structures precisely.
// Finally, it hand-constructs and writes a new perfectly compliant Central Directory.
func FilterZipStream(r *Reader, stream io.Reader, w io.Writer, filter func(*File) bool) error {
	var matchedFiles []*File
	for _, f := range r.File {
		if filter(f) {
			matchedFiles = append(matchedFiles, f)
		}
	}

	if len(matchedFiles) == 0 {
		return nil
	}

	// Sort files by their physical position in the zip stream
	sort.SliceStable(matchedFiles, func(i, j int) bool {
		return matchedFiles[i].headerOffset < matchedFiles[j].headerOffset
	})

	var streamOffset int64
	var outOffset int64
	newOffsets := make([]int64, len(matchedFiles))

	for i, f := range matchedFiles {
		hOffset := f.headerOffset

		// Fast-forward stream to the file's local header
		if hOffset > streamOffset {
			skipped, err := io.CopyN(io.Discard, stream, hOffset-streamOffset)
			if err != nil {
				return err
			}
			streamOffset += skipped
		} else if hOffset < streamOffset {
			return errors.New("zip: cannot stream backwards, offsets must be strictly monotonic")
		}

		newOffsets[i] = outOffset

		// Read Local Header
		lHead := make([]byte, 30)
		if _, err := io.ReadFull(stream, lHead); err != nil {
			return err
		}
		if _, err := w.Write(lHead); err != nil {
			return err
		}
		streamOffset += 30
		outOffset += 30

		nameLen := binary.LittleEndian.Uint16(lHead[26:28])
		extraLen := binary.LittleEndian.Uint16(lHead[28:30])

		// Copy Name + Extra
		n, err := io.CopyN(w, stream, int64(nameLen+extraLen))
		streamOffset += n
		outOffset += n
		if err != nil {
			return err
		}

		// Copy Compressed Data
		n, err = io.CopyN(w, stream, int64(f.CompressedSize64))
		streamOffset += n
		outOffset += n
		if err != nil {
			return err
		}

		// Copy Data Descriptor if present
		if f.Flags&0x8 != 0 {
			var sig [4]byte
			if _, err := io.ReadFull(stream, sig[:]); err != nil {
				return err
			}
			streamOffset += 4
			outOffset += 4

			hasSig := binary.LittleEndian.Uint32(sig[:]) == 0x08074b50
			w.Write(sig[:])

			var remaining int64 = 12 // 16 - 4
			if f.CompressedSize64 >= 0xFFFFFFFF || f.UncompressedSize64 >= 0xFFFFFFFF {
				remaining = 20 // 24 - 4
			}
			if f.IsEncrypted() && f.encryption != StandardEncryption {
				remaining -= 4
			}
			if !hasSig {
				remaining -= 4
			}

			n, err = io.CopyN(w, stream, remaining)
			streamOffset += n
			outOffset += n
			if err != nil {
				return err
			}
		}
	}

	cdStartOffset := outOffset

	// Write Central Directory directly
	var dirSize uint64
	buf := bytes.NewBuffer(nil)

	for i, f := range matchedFiles {
		fh := &f.FileHeader
		hOffset := newOffsets[i]

		var cbuf [46]byte
		binary.LittleEndian.PutUint32(cbuf[0:4], 0x02014b50)
		binary.LittleEndian.PutUint16(cbuf[4:6], fh.CreatorVersion)
		binary.LittleEndian.PutUint16(cbuf[6:8], fh.ReaderVersion)
		binary.LittleEndian.PutUint16(cbuf[8:10], fh.Flags)
		binary.LittleEndian.PutUint16(cbuf[10:12], fh.Method)
		binary.LittleEndian.PutUint16(cbuf[12:14], fh.ModifiedTime)
		binary.LittleEndian.PutUint16(cbuf[14:16], fh.ModifiedDate)
		binary.LittleEndian.PutUint32(cbuf[16:20], fh.CRC32)

		if fh.CompressedSize64 >= 0xFFFFFFFF || fh.UncompressedSize64 >= 0xFFFFFFFF || hOffset >= 0xFFFFFFFF {
			binary.LittleEndian.PutUint32(cbuf[20:24], 0xFFFFFFFF)
			binary.LittleEndian.PutUint32(cbuf[24:28], 0xFFFFFFFF)
		} else {
			binary.LittleEndian.PutUint32(cbuf[20:24], uint32(fh.CompressedSize64))
			binary.LittleEndian.PutUint32(cbuf[24:28], uint32(fh.UncompressedSize64))
		}

		binary.LittleEndian.PutUint16(cbuf[28:30], uint16(len(fh.Name)))
		binary.LittleEndian.PutUint16(cbuf[30:32], uint16(len(fh.Extra)))
		binary.LittleEndian.PutUint16(cbuf[32:34], uint16(len(fh.Comment)))
		binary.LittleEndian.PutUint16(cbuf[34:36], 0) // disk number start
		binary.LittleEndian.PutUint16(cbuf[36:38], 0) // internal attrs
		binary.LittleEndian.PutUint32(cbuf[38:42], fh.ExternalAttrs)

		if hOffset >= 0xFFFFFFFF {
			binary.LittleEndian.PutUint32(cbuf[42:46], 0xFFFFFFFF)
		} else {
			binary.LittleEndian.PutUint32(cbuf[42:46], uint32(hOffset))
		}

		buf.Write(cbuf[:])
		buf.WriteString(fh.Name)
		buf.Write(fh.Extra)
		buf.WriteString(fh.Comment)
	}

	dirBytes := buf.Bytes()
	dirSize = uint64(len(dirBytes))

	if _, err := w.Write(dirBytes); err != nil {
		return err
	}

	records := uint64(len(matchedFiles))
	if records >= 0xFFFF || dirSize >= 0xFFFFFFFF || cdStartOffset >= 0xFFFFFFFF {
		var zip64eocd [56]byte
		binary.LittleEndian.PutUint32(zip64eocd[0:4], 0x06064b50)
		binary.LittleEndian.PutUint64(zip64eocd[4:12], 44)
		binary.LittleEndian.PutUint16(zip64eocd[12:14], 45)
		binary.LittleEndian.PutUint16(zip64eocd[14:16], 45)
		binary.LittleEndian.PutUint32(zip64eocd[16:20], 0)
		binary.LittleEndian.PutUint32(zip64eocd[20:24], 0)
		binary.LittleEndian.PutUint64(zip64eocd[24:32], records)
		binary.LittleEndian.PutUint64(zip64eocd[32:40], records)
		binary.LittleEndian.PutUint64(zip64eocd[40:48], dirSize)
		binary.LittleEndian.PutUint64(zip64eocd[48:56], uint64(cdStartOffset))
		w.Write(zip64eocd[:])

		var locator [20]byte
		binary.LittleEndian.PutUint32(locator[0:4], 0x07064b50)
		binary.LittleEndian.PutUint32(locator[4:8], 0)
		binary.LittleEndian.PutUint64(locator[8:16], uint64(cdStartOffset)+dirSize)
		binary.LittleEndian.PutUint32(locator[16:20], 1)
		w.Write(locator[:])

		records = 0xFFFF
		dirSize = 0xFFFFFFFF
		cdStartOffset = 0xFFFFFFFF
	}

	var eocd [22]byte
	binary.LittleEndian.PutUint32(eocd[0:4], 0x06054b50)
	binary.LittleEndian.PutUint16(eocd[4:6], 0)
	binary.LittleEndian.PutUint16(eocd[6:8], 0)
	binary.LittleEndian.PutUint16(eocd[8:10], uint16(records))
	binary.LittleEndian.PutUint16(eocd[10:12], uint16(records))
	binary.LittleEndian.PutUint32(eocd[12:16], uint32(dirSize))
	binary.LittleEndian.PutUint32(eocd[16:20], uint32(cdStartOffset))
	binary.LittleEndian.PutUint16(eocd[20:22], 0)
	_, err := w.Write(eocd[:])
	return err
}
