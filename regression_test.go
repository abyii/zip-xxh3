package zip

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	mrand "math/rand/v2"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

// oldZipCryptoHeaderTemplate is the fixed filler the writer used to put in
// bytes 0-9 of every ZipCrypto encryption header.
var oldZipCryptoHeaderTemplate = []byte{0xF8, 0x53, 0xCF, 0x05, 0x2D, 0xDD, 0xAD, 0xC8, 0x66, 0x3F}

// wrongZipCryptoPassword deterministically picks a password whose decrypted
// check byte for encHeader differs from check (a random wrong password passes
// the one-byte check with probability 1/256).
func wrongZipCryptoPassword(encHeader []byte, check byte) []byte {
	for i := 0; ; i++ {
		p := fmt.Appendf(nil, "wrong-%d", i)
		if NewZipCrypto(p).Decrypt(encHeader[:zipCryptoHeaderLen])[zipCryptoHeaderLen-1] != check {
			return p
		}
	}
}

func pseudoRandomBytes(n int, seed uint64) []byte {
	r := mrand.New(mrand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

// zipCiphertextHeader returns the first 12 payload bytes of f.
func zipCiphertextHeader(t *testing.T, zr *Reader, f *File) []byte {
	t.Helper()
	off, err := f.DataOffset()
	if err != nil {
		t.Fatal(err)
	}
	h := make([]byte, zipCryptoHeaderLen)
	if _, err := zr.r.ReadAt(h, off); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestZipCryptoHeaderIsRandomWithCheckBytes(t *testing.T) {
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	modTime := time.Date(2026, 10, 13, 17, 42, 10, 0, time.UTC)
	for _, name := range []string{"a.txt", "b.txt"} {
		fh := &FileHeader{Name: name, Method: Store}
		fh.SetModTime(modTime)
		fh.SetEncryptionMethod(StandardEncryption)
		fh.SetPassword("pw")
		w, err := zw.CreateHeader(fh)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte("same content")); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var plainHeaders [][]byte
	for _, f := range zr.File {
		h := NewZipCrypto([]byte("pw")).Decrypt(zipCiphertextHeader(t, zr, f))
		if h[10] != byte(f.ModifiedTime) || h[11] != byte(f.ModifiedTime>>8) {
			t.Errorf("%s: check bytes %#x %#x, want mod time %#04x", f.Name, h[10], h[11], f.ModifiedTime)
		}
		if bytes.Equal(h[:10], oldZipCryptoHeaderTemplate) {
			t.Errorf("%s: encryption header still uses the fixed template", f.Name)
		}
		plainHeaders = append(plainHeaders, h)
	}
	if bytes.Equal(plainHeaders[0][:10], plainHeaders[1][:10]) {
		t.Error("two entries share the same encryption header filler")
	}
}

func TestZipCryptoOpenVerifiesPassword(t *testing.T) {
	content := []byte(strings.Repeat("zipcrypto check byte ", 50))
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	fh := &FileHeader{Name: "secret.txt", Method: Deflate, CompressionLevel: -1}
	fh.SetModTime(time.Date(2025, 1, 2, 3, 4, 6, 0, time.UTC))
	fh.SetEncryptionMethod(StandardEncryption)
	fh.SetPassword("right")
	w, err := zw.CreateHeader(fh)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(content)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	f := zr.File[0]

	// No password: an error, not a nil function call panic.
	if _, err := f.Open(); !errors.Is(err, ErrPassword) {
		t.Fatalf("Open without password: got %v, want ErrPassword", err)
	}

	wrong := wrongZipCryptoPassword(zipCiphertextHeader(t, zr, f), byte(f.ModifiedTime>>8))
	f.SetPassword(string(wrong))
	if _, err := f.Open(); !errors.Is(err, ErrPassword) {
		t.Fatalf("Open with wrong password: got %v, want ErrPassword", err)
	}

	f.SetPassword("right")
	rc, err := f.Open()
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("read with right password: err=%v, content match=%v", err, bytes.Equal(got, content))
	}
}

func TestNewZipCryptoDecryptReaderCheckByteRules(t *testing.T) {
	password := []byte("golang")
	plaintext := []byte("payload")
	encrypt := func(check byte) []byte {
		z := NewZipCrypto(password)
		header := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, check}
		return append(z.Encrypt(header), z.Encrypt(plaintext)...)
	}

	tests := []struct {
		name  string
		check byte
		fh    *FileHeader
		want  error
	}{
		{"crc rule", 0xAB, &FileHeader{CRC32: 0xAB123456}, nil},
		{"crc rule mismatch", 0xAB, &FileHeader{CRC32: 0xAC123456}, ErrPassword},
		{"mod time rule", 0x5C, &FileHeader{Flags: 0x8, ModifiedTime: 0x5C11, CRC32: 0xAB123456}, nil},
		{"mod time rule ignores crc", 0xAB, &FileHeader{Flags: 0x8, ModifiedTime: 0x5C11, CRC32: 0xAB123456}, ErrPassword},
	}
	for _, tt := range tests {
		r := NewVerifiedZipCryptoDecryptReader(bytes.NewReader(encrypt(tt.check)), password, tt.fh)
		got, err := io.ReadAll(r)
		if !errors.Is(err, tt.want) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.want)
			continue
		}
		if tt.want == nil && !bytes.Equal(got, plaintext) {
			t.Errorf("%s: got %q, want %q", tt.name, got, plaintext)
		}
		if tt.want != nil {
			// The error is sticky.
			if _, err := r.Read(make([]byte, 8)); !errors.Is(err, tt.want) {
				t.Errorf("%s: second Read err = %v, want %v", tt.name, err, tt.want)
			}
		}
	}

	// Truncated header and nil header are errors, not silent EOF.
	for _, n := range []int{0, 5, 11} {
		r := NewVerifiedZipCryptoDecryptReader(bytes.NewReader(encrypt(0)[:n]), password, &FileHeader{})
		if _, err := io.ReadAll(r); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("truncated to %d bytes: err = %v, want ErrUnexpectedEOF", n, err)
		}
	}
	if _, err := io.ReadAll(NewVerifiedZipCryptoDecryptReader(bytes.NewReader(encrypt(0)), password, nil)); err == nil {
		t.Error("nil FileHeader: expected an error")
	}
}

// TestRawPartWritersCheckByte covers the SDK flows: parts written by
// CreateFilePartSimple / CreateRawFileParts are restored by reading the local
// header and decrypting with NewZipCryptoDecryptReader.
func TestRawPartWritersCheckByte(t *testing.T) {
	content := []byte(strings.Repeat("raw part content ", 40))
	modTime := time.Date(2024, 6, 7, 8, 9, 10, 0, time.UTC)

	type part struct {
		name    string
		data    []byte
		inflate bool
	}
	var parts []part

	{
		var buf bytes.Buffer
		zw := NewWriter()
		w, err := zw.CreateFilePartSimple("simple.txt", Deflate, -1, StandardEncryption, "pw", 0, &buf)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(content)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		parts = append(parts, part{"CreateFilePartSimple", buf.Bytes(), true})
	}
	{
		var buf bytes.Buffer
		fh := &FileHeader{
			Name:               "raw.txt",
			Method:             Store,
			CRC32:              crc32.ChecksumIEEE(content),
			UncompressedSize64: uint64(len(content)),
		}
		fh.SetModTime(modTime)
		fh.SetEncryptionMethod(StandardEncryption)
		fh.SetPassword("pw")
		w, err := NewWriter().CreateRawFileParts(fh, 0, &buf)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(content)
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		parts = append(parts, part{"CreateRawFileParts", buf.Bytes(), false})
	}

	for _, p := range parts {
		open := func(password []byte) ([]byte, error) {
			r := bytes.NewReader(p.data)
			fh, err := ReadLocalFileHeader(r)
			if err != nil {
				return nil, err
			}
			payload := p.data[len(p.data)-r.Len() : len(p.data)-dataDescriptorLen]
			var pr io.Reader = NewVerifiedZipCryptoDecryptReader(bytes.NewReader(payload), password, fh)
			if p.inflate {
				fr := newFlateReader(pr)
				defer fr.Close()
				pr = fr
			}
			return io.ReadAll(pr)
		}
		got, err := open([]byte("pw"))
		if err != nil || !bytes.Equal(got, content) {
			t.Errorf("%s: right password: err=%v match=%v", p.name, err, bytes.Equal(got, content))
		}

		r := bytes.NewReader(p.data)
		fh, _ := ReadLocalFileHeader(r)
		encHeader := p.data[len(p.data)-r.Len():]
		if _, err := open(wrongZipCryptoPassword(encHeader, byte(fh.ModifiedTime>>8))); !errors.Is(err, ErrPassword) {
			t.Errorf("%s: wrong password: err = %v, want ErrPassword", p.name, err)
		}
	}
}

func TestZipCryptoDecryptorSizeAndErrors(t *testing.T) {
	z := NewZipCrypto([]byte("pw"))
	data := []byte("decrypted payload")
	ct := append(z.Encrypt(make([]byte, zipCryptoHeaderLen)), z.Encrypt(data)...)
	sr, err := ZipCryptoDecryptor(io.NewSectionReader(bytes.NewReader(ct), 0, int64(len(ct))), []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	if sr.Size() != int64(len(data)) {
		t.Errorf("Size() = %d, want %d", sr.Size(), len(data))
	}
	got, _ := io.ReadAll(sr)
	if !bytes.Equal(got, data) {
		t.Errorf("got %q, want %q", got, data)
	}
	if _, err := ZipCryptoDecryptor(io.NewSectionReader(bytes.NewReader(ct[:5]), 0, 5), []byte("pw")); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("short input: err = %v, want ErrUnexpectedEOF", err)
	}
}

func TestReaderTruncatedAESExtraNoPanic(t *testing.T) {
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	// WinZip AES extra (0x9901) with only 2 data bytes instead of 7.
	w, err := zw.CreateHeader(&FileHeader{Name: "x", Method: Store, Extra: []byte{0x01, 0x99, 0x02, 0x00, 0x02, 0x00}})
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("data"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if f := zr.File[0]; f.ae != 0 || f.Method != Store {
		t.Errorf("truncated AES extra was interpreted: ae=%d method=%d", f.ae, f.Method)
	}
}

func TestAESCompressedSizeTooSmall(t *testing.T) {
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	w, err := zw.Create("aes.txt", Store, 0, AES256Encryption, "pw")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("hello"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	f := zr.File[0]
	f.SetPassword("pw")
	// Enough for salt (16) + pwv (2) but not for the 10-byte auth code.
	f.CompressedSize64 = 16 + 2 + 5
	if _, err := f.Open(); !errors.Is(err, ErrFormat) {
		t.Fatalf("Open: err = %v, want ErrFormat", err)
	}
}

func TestChecksumReaderShortEntry(t *testing.T) {
	data := []byte("0123456789")
	f := &File{FileHeader: FileHeader{UncompressedSize64: uint64(len(data)) + 1, CRC32: crc32.ChecksumIEEE(data)}}
	// DataErrReader returns the final bytes together with io.EOF.
	r := &checksumReader{
		rc:   io.NopCloser(iotest.DataErrReader(bytes.NewReader(data))),
		hash: crc32.NewIEEE(),
		f:    f,
	}
	got, err := io.ReadAll(r)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err = %v, want ErrUnexpectedEOF", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("bytes read alongside the error were dropped: got %q", got)
	}
	if _, err := r.Read(make([]byte, 4)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("error is not sticky: %v", err)
	}
}

func TestReadDataDescriptorVariants(t *testing.T) {
	f := &File{FileHeader: FileHeader{CRC32: 0x11223344}}
	le := binary.LittleEndian
	withSig := le.AppendUint32(le.AppendUint32(le.AppendUint32(le.AppendUint32(nil, dataDescriptorSignature), 0x11223344), 5), 5)
	noSig := withSig[4:]
	tests := []struct {
		name string
		b    []byte
		want error
	}{
		{"signature", withSig, nil},
		{"no signature", noSig, nil},
		{"crc mismatch", le.AppendUint32(le.AppendUint32(le.AppendUint32(nil, 0x99), 5), 5), ErrChecksum},
		{"truncated signature descriptor", withSig[:12], io.ErrUnexpectedEOF},
		{"empty", nil, io.EOF},
	}
	for _, tt := range tests {
		if err := readDataDescriptor(bytes.NewReader(tt.b), f); !errors.Is(err, tt.want) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.want)
		}
	}
}

func TestZip64SizeBoundary(t *testing.T) {
	const size = uint32max // 0xFFFFFFFF must be stored as zip64
	var part bytes.Buffer
	zw := NewWriter()
	fh := &FileHeader{Name: "x", Method: Store, CRC32: 1, UncompressedSize64: size}
	w, err := zw.CreateRawFileParts(fh, 0, &part)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("abc"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if want := fileHeaderLen + 1 + 3 + dataDescriptor64Len; part.Len() != want {
		t.Fatalf("part length %d, want %d (zip64 data descriptor)", part.Len(), want)
	}
	cd, err := zw.GetCentralDirectoryBytes()
	if err != nil {
		t.Fatal(err)
	}
	archive := append(part.Bytes(), cd...)
	zr, err := NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	f := zr.File[0]
	if f.UncompressedSize64 != size || f.CompressedSize64 != 3 || f.headerOffset != 0 {
		t.Errorf("got sizes %d/%d offset %d", f.UncompressedSize64, f.CompressedSize64, f.headerOffset)
	}
	if len(removeExtraField(f.Extra, zip64ExtraId)) == len(f.Extra) {
		t.Error("central directory record has no zip64 extra field")
	}
}

func TestWriteDirectoryEndZip64Thresholds(t *testing.T) {
	tests := []struct {
		records, size, offset uint64
		zip64                 bool
	}{
		{uint16max - 1, 10, 20, false},
		{uint16max, 10, 20, true},
		{1, uint32max, 20, true},
		{1, 10, uint32max, true},
		{1, 10, uint32max - 1, false},
	}
	for _, tt := range tests {
		var buf bytes.Buffer
		if err := writeDirectoryEnd(&buf, tt.records, tt.size, tt.offset); err != nil {
			t.Fatal(err)
		}
		gotZip64 := binary.LittleEndian.Uint32(buf.Bytes()) == directory64EndSignature
		if gotZip64 != tt.zip64 {
			t.Errorf("records=%d size=%d offset=%d: zip64 = %v, want %v", tt.records, tt.size, tt.offset, gotZip64, tt.zip64)
		}
	}
}

type countingReaderAt struct {
	r     io.ReaderAt
	calls int
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	c.calls++
	return c.r.ReadAt(p, off)
}

func TestReaderIssuesFewReadAtCalls(t *testing.T) {
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	for i := range 300 {
		w, err := zw.Create(fmt.Sprintf("dir/file-%04d.txt", i), Store, 0, NoEncryption, "")
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(w, "content %d", i)
	}
	big := pseudoRandomBytes(1<<20, 7)
	w, err := zw.Create("big.bin", Deflate, 1, NoEncryption, "")
	if err != nil {
		t.Fatal(err)
	}
	w.Write(big)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	cr := &countingReaderAt{r: bytes.NewReader(buf.Bytes())}
	zr, err := NewReader(cr, int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	// One read for the end record (which also covers the zip64 locator
	// position) and one for the whole central directory.
	if cr.calls > 2 {
		t.Errorf("NewReader issued %d ReadAt calls, want <= 2", cr.calls)
	}

	cr.calls = 0
	rc, err := zr.File[len(zr.File)-1].Open()
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil || !bytes.Equal(got, big) {
		t.Fatalf("read big entry: err=%v match=%v", err, bytes.Equal(got, big))
	}
	// local header + ~1 MiB in 64 KiB blocks + data descriptor.
	if limit := 2 + (1<<20)/maxEntryReadBuffer + 4; cr.calls > limit {
		t.Errorf("reading a 1 MiB deflate entry issued %d ReadAt calls, want <= %d", cr.calls, limit)
	}
}

func TestFlateWriterPoolsArePerLevel(t *testing.T) {
	w9, err := newFlateWriter(io.Discard, 9)
	if err != nil {
		t.Fatal(err)
	}
	inner9 := w9.(*pooledFlateWriter).fw
	w9.Close()
	w1, err := newFlateWriter(io.Discard, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer w1.Close()
	if w1.(*pooledFlateWriter).fw == inner9 {
		t.Fatal("level 1 writer reused a pooled level 9 writer")
	}
}

func TestInvalidCompressionLevelLeavesNoEntry(t *testing.T) {
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	if _, err := zw.Create("bad", Deflate, 42, NoEncryption, ""); err == nil {
		t.Fatal("expected an error for compression level 42")
	}
	w, err := zw.Create("good", Store, 0, NoEncryption, "")
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("ok"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) != 1 || zr.File[0].Name != "good" {
		t.Fatalf("got %d entries, want only \"good\"", len(zr.File))
	}
}

func TestFilterZipStreamKeepsAllEntriesByteIdentical(t *testing.T) {
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	add := func(name string, method uint16, level int, enc EncryptionMethod, pw string, data []byte) {
		w, err := zw.Create(name, method, level, enc, pw)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(data)
	}
	add("plain.txt", Deflate, -1, NoEncryption, "", []byte(strings.Repeat("plain ", 100)))
	add("zipcrypto.txt", Deflate, -1, StandardEncryption, "pw", []byte(strings.Repeat("zipcrypto ", 100)))
	add("aes.txt", Deflate, -1, AES256Encryption, "pw", []byte(strings.Repeat("aes ", 100)))
	// Name + extra longer than 65535 bytes in total.
	fh := &FileHeader{Name: strings.Repeat("n", 40000), Method: Store, Extra: append([]byte{0xcd, 0xab, 0x2c, 0x75}, make([]byte, 30000)...)}
	w, err := zw.CreateHeader(fh)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("long header"))
	add("last.txt", Store, 0, StandardEncryption, "pw", []byte("last"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}

	orig := buf.Bytes()
	zr, err := NewReader(bytes.NewReader(orig), int64(len(orig)))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := FilterZipStream(zr, bytes.NewReader(orig), &out, func(*File) bool { return true }); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), orig) {
		t.Fatalf("filtering every entry changed the archive (%d -> %d bytes)", len(orig), out.Len())
	}
}

func TestFilterZipStreamNoMatchWritesEmptyArchive(t *testing.T) {
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	w, _ := zw.Create("a.txt", Store, 0, NoEncryption, "")
	w.Write([]byte("a"))
	zw.Close()
	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := FilterZipStream(zr, bytes.NewReader(buf.Bytes()), &out, func(*File) bool { return false }); err != nil {
		t.Fatal(err)
	}
	zr2, err := NewReader(bytes.NewReader(out.Bytes()), int64(out.Len()))
	if err != nil {
		t.Fatalf("output is not a valid zip: %v", err)
	}
	if len(zr2.File) != 0 {
		t.Fatalf("got %d entries, want 0", len(zr2.File))
	}
}

// encryptedRawPart writes one ZipCrypto entry and returns its raw part bytes
// (local header + payload + data descriptor) and the reader's File.
func encryptedRawPart(t *testing.T, name, password string, content []byte) ([]byte, *File) {
	t.Helper()
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	w, err := zw.Create(name, Deflate, -1, StandardEncryption, password)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(content)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	f := zr.File[0]
	off, _ := f.DataOffset()
	end := off + int64(f.CompressedSize64) + dataDescriptorLen
	return buf.Bytes()[f.headerOffset:end], f
}

func TestCopyRawPartPasswordErrors(t *testing.T) {
	part, f := encryptedRawPart(t, "s.txt", "old", []byte("secret secret secret"))
	encHeader := part[fileHeaderLen+len(f.Name):]
	wrong := wrongZipCryptoPassword(encHeader, byte(f.ModifiedTime>>8))

	for _, oldPassword := range []string{string(wrong), ""} {
		var buf bytes.Buffer
		zw := NewWriter(&buf)
		err := zw.CopyRawPart(bytes.NewReader(part), oldPassword, "new", nil)
		if !errors.Is(err, ErrPassword) {
			t.Fatalf("oldPassword %q: err = %v, want ErrPassword", oldPassword, err)
		}
		if err := zw.Close(); err != nil {
			t.Fatal(err)
		}
		zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		if err != nil {
			t.Fatal(err)
		}
		if len(zr.File) != 0 {
			t.Fatalf("oldPassword %q: failed copy left %d entries in the archive", oldPassword, len(zr.File))
		}
	}
}

func TestCopyRawPartRekeyWithModTimeOverride(t *testing.T) {
	content := []byte(strings.Repeat("rekey ", 30))
	part, _ := encryptedRawPart(t, "s.txt", "old", content)
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	err := zw.CopyRawPart(bytes.NewReader(part), "old", "new", func(o *OverridableFileHeader) {
		o.ModifiedTime = 0xBEEF
	})
	if err != nil {
		t.Fatal(err)
	}
	zw.Close()
	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	f := zr.File[0]
	f.SetPassword("new")
	rc, err := f.Open()
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("err=%v match=%v", err, bytes.Equal(got, content))
	}
}

func TestCopyRawPartRejectsAES(t *testing.T) {
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	w, _ := zw.Create("aes.txt", Store, 0, AES128Encryption, "pw")
	w.Write([]byte("aes data"))
	zw.Close()
	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	f := zr.File[0]
	if err := NewWriter(io.Discard).CopyRawPart(bytes.NewReader(buf.Bytes()[f.headerOffset:]), "pw", "x", nil); err == nil {
		t.Fatal("expected an error for an AES source part")
	}
}

// rawLocalPart builds a local header without data descriptor (sizes in the
// header), optionally with a zip64 extra field, followed by data and junk.
func rawLocalPart(name string, data []byte, zip64Extra bool, trailing []byte) []byte {
	le := binary.LittleEndian
	var extra []byte
	size32 := uint32(len(data))
	if zip64Extra {
		extra = le.AppendUint16(le.AppendUint16(nil, zip64ExtraId), 16)
		extra = le.AppendUint64(le.AppendUint64(extra, uint64(len(data))), uint64(len(data)))
		size32 = uint32max
	}
	b := le.AppendUint32(nil, fileHeaderSignature)
	b = le.AppendUint16(b, 45)
	b = le.AppendUint16(b, 0) // flags: no descriptor
	b = le.AppendUint16(b, Store)
	b = le.AppendUint16(b, 0x1234)
	b = le.AppendUint16(b, 0x5678)
	b = le.AppendUint32(b, crc32.ChecksumIEEE(data))
	b = le.AppendUint32(b, size32)
	b = le.AppendUint32(b, size32)
	b = le.AppendUint16(b, uint16(len(name)))
	b = le.AppendUint16(b, uint16(len(extra)))
	b = append(b, name...)
	b = append(b, extra...)
	b = append(b, data...)
	return append(b, trailing...)
}

func TestCopyRawPartWithoutDescriptor(t *testing.T) {
	data := []byte("stored payload without data descriptor")
	for _, zip64Extra := range []bool{false, true} {
		var buf bytes.Buffer
		zw := NewWriter(&buf)
		if err := zw.CopyRawPart(bytes.NewReader(rawLocalPart("n.txt", data, zip64Extra, []byte("JUNKJUNK"))), "", "", nil); err != nil {
			t.Fatal(err)
		}
		zw.Close()
		zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		if err != nil {
			t.Fatal(err)
		}
		f := zr.File[0]
		if len(removeExtraField(f.Extra, zip64ExtraId)) != len(f.Extra) {
			t.Errorf("zip64Extra=%v: stale zip64 extra copied into the central directory", zip64Extra)
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(rc)
		if err != nil || !bytes.Equal(got, data) {
			t.Errorf("zip64Extra=%v: err=%v got %q", zip64Extra, err, got)
		}
	}

	// A truncated payload is an error.
	part := rawLocalPart("n.txt", data, false, nil)
	if err := NewWriter(io.Discard).CopyRawPart(bytes.NewReader(part[:len(part)-3]), "", "", nil); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("truncated part: err = %v, want ErrUnexpectedEOF", err)
	}
}

func TestDescriptorStripperVariants(t *testing.T) {
	le := binary.LittleEndian
	dd := func(sig, zip64 bool, crc uint32, comp, uncomp uint64) []byte {
		var b []byte
		if sig {
			b = le.AppendUint32(b, dataDescriptorSignature)
		}
		b = le.AppendUint32(b, crc)
		if zip64 {
			return le.AppendUint64(le.AppendUint64(b, comp), uncomp)
		}
		return le.AppendUint32(le.AppendUint32(b, uint32(comp)), uint32(uncomp))
	}
	big := pseudoRandomBytes(200<<10, 3)
	// Payload whose last 8 bytes look like the start of a zip64 descriptor.
	fake := append([]byte("payload"), le.AppendUint32(le.AppendUint32(nil, dataDescriptorSignature), 0xdead)...)

	tests := []struct {
		name    string
		payload []byte
		dd      []byte
	}{
		{"large 32-bit", big, dd(true, false, 7, uint64(len(big)), 9)},
		{"zip64", big[:1000], dd(true, true, 7, 1000, 9)},
		{"no signature", big[:1000], dd(false, false, 7, 1000, 9)},
		{"no signature zip64", big[:1000], dd(false, true, 7, 1000, 9)},
		{"signature inside payload", fake, dd(true, false, 7, uint64(len(fake)), 9)},
		{"empty payload", nil, dd(true, false, 0, 0, 0)},
	}
	for _, tt := range tests {
		ds := newDescriptorStripper(iotest.HalfReader(bytes.NewReader(append(append([]byte(nil), tt.payload...), tt.dd...))), true)
		got, err := io.ReadAll(ds)
		if err != nil {
			t.Fatalf("%s: %v", tt.name, err)
		}
		if !bytes.Equal(got, tt.payload) {
			t.Errorf("%s: payload mismatch (%d bytes, want %d)", tt.name, len(got), len(tt.payload))
		}
		if ds.desc == nil || ds.desc.CRC32 != 7 && len(tt.payload) > 0 || ds.desc.CompressedSize64 != uint64(len(tt.payload)) {
			t.Errorf("%s: descriptor = %+v", tt.name, ds.desc)
		}
	}

	// No descriptor at all: everything is payload and desc stays nil.
	ds := newDescriptorStripper(bytes.NewReader(big[:100]), true)
	got, _ := io.ReadAll(ds)
	if !bytes.Equal(got, big[:100]) || ds.desc != nil {
		t.Errorf("missing descriptor: got %d bytes, desc %+v", len(got), ds.desc)
	}
}

func TestRawAESStoresNoCRC(t *testing.T) {
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	fh := &FileHeader{Name: "a", Method: Store, CRC32: 0xdeadbeef, UncompressedSize64: 4}
	fh.SetEncryptionMethod(AES256Encryption)
	fh.SetPassword("pw")
	w, err := zw.CreateRaw(fh)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("data"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	f := zr.File[0]
	if f.CRC32 != 0 {
		t.Errorf("AE-2 entry has CRC %#x, want 0", f.CRC32)
	}
	f.SetPassword("pw")
	rc, err := f.Open()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(rc); err != nil || string(got) != "data" {
		t.Fatalf("err=%v got %q", err, got)
	}
}

// Copying ZipCrypto ciphertext as-is via CreateRaw (encrypted flag set, no
// password) used to dereference a nil HMAC.
func TestCreateRawEncryptedPassthrough(t *testing.T) {
	content := []byte(strings.Repeat("passthrough ", 20))
	part, fA := encryptedRawPart(t, "p.txt", "pw", content)
	payload := part[fileHeaderLen+len(fA.Name) : len(part)-dataDescriptorLen]

	var buf bytes.Buffer
	zw := NewWriter(&buf)
	fh := &FileHeader{
		Name:               fA.Name,
		Method:             fA.Method,
		Flags:              fA.Flags,
		ModifiedTime:       fA.ModifiedTime,
		ModifiedDate:       fA.ModifiedDate,
		CRC32:              fA.CRC32,
		UncompressedSize64: fA.UncompressedSize64,
	}
	w, err := zw.CreateRaw(fh)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(payload)
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	f := zr.File[0]
	f.SetPassword("pw")
	rc, err := f.Open()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(rc); err != nil || !bytes.Equal(got, content) {
		t.Fatalf("err=%v match=%v", err, bytes.Equal(got, content))
	}
}

func TestNewReaderRejectsTinySizes(t *testing.T) {
	for _, size := range []int64{-1, 0, directoryEndLen - 1} {
		if _, err := NewReader(bytes.NewReader(make([]byte, 64)), size); !errors.Is(err, ErrFormat) {
			t.Errorf("size %d: err = %v, want ErrFormat", size, err)
		}
	}
}

func TestWriterDoesNotMutateCallerExtra(t *testing.T) {
	backing := make([]byte, 4, 64)
	binary.LittleEndian.PutUint16(backing, 0xabcd)
	var buf bytes.Buffer
	zw := NewWriter(&buf)
	fh := &FileHeader{Name: "x", Method: Store, Extra: backing[:4]}
	w, err := zw.CreateHeader(fh)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("data"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if len(fh.Extra) != 4 {
		t.Errorf("FileHeader.Extra grew to %d bytes", len(fh.Extra))
	}
	if !bytes.Equal(backing[4:64], make([]byte, 60)) {
		t.Error("writer appended into the caller's Extra backing array")
	}
}

type failOnceWriter struct{ failed bool }

func (w *failOnceWriter) Write(p []byte) (int, error) {
	if !w.failed {
		w.failed = true
		return 0, errors.New("transient")
	}
	return len(p), nil
}

// After a failed write the ZipCrypto key stream is out of sync with the
// output, so later writes must keep failing instead of emitting garbage.
func TestZipCryptoWriterErrorIsSticky(t *testing.T) {
	zc, _ := ZipCryptoEncryptor(&failOnceWriter{}, func() []byte { return []byte("pw") }, nil)
	if _, err := zc.Write([]byte("a")); err == nil {
		t.Fatal("first write: expected error")
	}
	if _, err := zc.Write([]byte("b")); err == nil {
		t.Fatal("second write after failure succeeded")
	}
	if err := zc.(io.Closer).Close(); err == nil {
		t.Fatal("Close after failure succeeded")
	}
}

// sparseTailReaderAt is a size-byte file of zeros ending with tail.
type sparseTailReaderAt struct {
	size int64
	tail []byte
}

func (s sparseTailReaderAt) ReadAt(p []byte, off int64) (int, error) {
	tailStart := s.size - int64(len(s.tail))
	n := 0
	for ; n < len(p) && off+int64(n) < s.size; n++ {
		if pos := off + int64(n); pos >= tailStart {
			p[n] = s.tail[pos-tailStart]
		} else {
			p[n] = 0
		}
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// A forged zip64 record count must not drive a huge allocation.
func TestReaderForgedRecordCount(t *testing.T) {
	const size = int64(1) << 50
	const records = uint64(1)<<40 + 5
	const cdSize = 100
	// The end records (zip64 end + locator + end) take 98 bytes; the
	// "central directory" before them is all zeros.
	dirOffset := uint64(size) - cdSize - (directory64EndLen + directory64LocLen + directoryEndLen)
	var tail bytes.Buffer
	if err := writeDirectoryEnd(&tail, records, cdSize, dirOffset); err != nil {
		t.Fatal(err)
	}
	r := sparseTailReaderAt{size: size, tail: tail.Bytes()}
	if d, err := readDirectoryEnd(r, size); err != nil || d.directoryRecords != records {
		t.Fatalf("forged end records not parsed: %v", err)
	}
	if _, err := NewReader(r, size); !errors.Is(err, ErrFormat) {
		t.Fatalf("err = %v, want ErrFormat", err)
	}
}
