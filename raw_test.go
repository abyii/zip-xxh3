package zip

import (
	"bytes"
	"io"
	"testing"
)

func TestReadLocalFileHeader(t *testing.T) {
	// Generate a mock LFH stream
	var buf bytes.Buffer
	rawBuf := make([]byte, 30)
	b := writeBuf(rawBuf)
	b.uint32(fileHeaderSignature)
	b.uint16(20)      // reader version
	b.uint16(0x8)     // flags
	b.uint16(Deflate) // method
	b.uint16(1234)    // mod time
	b.uint16(5678)    // mod date
	b.uint32(0)       // CRC (0 because of descriptor)
	b.uint32(0)       // compressed size (0 because of descriptor)
	b.uint32(0)       // uncompressed size (0 because of descriptor)
	b.uint16(8)       // name len
	b.uint16(4)       // extra len

	buf.Write(rawBuf)
	buf.WriteString("test.txt")
	buf.Write([]byte{1, 2, 3, 4}) // extra bytes

	fh, err := ReadLocalFileHeader(&buf)
	if err != nil {
		t.Fatalf("Failed to read local file header: %v", err)
	}

	if fh.Name != "test.txt" {
		t.Errorf("Expected name 'test.txt', got '%s'", fh.Name)
	}
	if fh.Method != Deflate {
		t.Errorf("Expected method %d, got %d", Deflate, fh.Method)
	}
	if fh.Flags != 0x8 {
		t.Errorf("Expected flags 0x8, got 0x%x", fh.Flags)
	}
	if !bytes.Equal(fh.Extra, []byte{1, 2, 3, 4}) {
		t.Errorf("Extra mismatch: got %v", fh.Extra)
	}
}

func TestDescriptorStripper(t *testing.T) {
	// Mock stream containing some file data followed by a descriptor
	fileData := []byte("Some compressed file data here...")

	// Create 32-bit descriptor bytes
	var descBuf [16]byte
	db := writeBuf(descBuf[:])
	db.uint32(dataDescriptorSignature)
	db.uint32(0x12345678)            // CRC32
	db.uint32(uint32(len(fileData))) // Comp size
	db.uint32(100)                   // Uncomp size

	var stream bytes.Buffer
	stream.Write(fileData)
	stream.Write(descBuf[:])

	stripper := newDescriptorStripper(&stream, true)
	readData, err := io.ReadAll(stripper)
	if err != nil {
		t.Fatalf("Failed to read: %v", err)
	}

	if !bytes.Equal(readData, fileData) {
		t.Errorf("Read data mismatch: got %q, expected %q", readData, fileData)
	}

	if stripper.desc == nil {
		t.Fatal("DataDescriptor is nil after EOF")
	}

	if stripper.desc.CRC32 != 0x12345678 {
		t.Errorf("CRC32 mismatch: got %x", stripper.desc.CRC32)
	}
	if stripper.desc.CompressedSize64 != uint64(len(fileData)) {
		t.Errorf("CompSize mismatch: got %d", stripper.desc.CompressedSize64)
	}
	if stripper.desc.UncompressedSize64 != 100 {
		t.Errorf("UncompSize mismatch: got %d", stripper.desc.UncompressedSize64)
	}
}

func TestNewZipCryptoDecryptReader(t *testing.T) {
	password := []byte("golang")
	plaintext := []byte("This is plaintext for streaming decryption test!")

	// Encrypt the plaintext using ZipCrypto
	zEnc := NewZipCrypto(password)
	header := []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc}
	encHeader := zEnc.Encrypt(header)
	encData := zEnc.Encrypt(plaintext)

	var stream bytes.Buffer
	stream.Write(encHeader)
	stream.Write(encData)

	// Decrypt using NewZipCryptoDecryptReader
	decReader := NewZipCryptoDecryptReader(&stream, password)
	decrypted, err := io.ReadAll(decReader)
	if err != nil {
		t.Fatalf("Failed to read from decrypt reader: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("Decrypted mismatch: got %q, expected %q", decrypted, plaintext)
	}
}

func TestCreateRaw(t *testing.T) {
	// 1. Create a zip file containing an encrypted, compressed file (ZipCrypto with passwordA)
	plaintext := []byte("This is some super secret raw data that is compressed and encrypted!")
	bufA := new(bytes.Buffer)
	zwA := NewWriter(bufA)

	fhA := &FileHeader{
		Name:   "secret.txt",
		Method: Deflate,
	}
	fhA.SetPassword("passwordA")
	fhA.SetEncryptionMethod(StandardEncryption)

	wA, err := zwA.CreateHeader(fhA)
	if err != nil {
		t.Fatalf("Failed to create header in zip A: %v", err)
	}
	if _, err := wA.Write(plaintext); err != nil {
		t.Fatalf("Failed to write to zip A: %v", err)
	}
	if err := zwA.Close(); err != nil {
		t.Fatalf("Failed to close zip A: %v", err)
	}

	// 2. Read the zip back and extract the raw encrypted, compressed bytes
	zipDataA := bufA.Bytes()
	zrA, err := NewReader(bytes.NewReader(zipDataA), int64(len(zipDataA)))
	if err != nil {
		t.Fatalf("Failed to open zip A reader: %v", err)
	}
	if len(zrA.File) != 1 {
		t.Fatalf("Expected 1 file in zip A, got %d", len(zrA.File))
	}
	fileA := zrA.File[0]

	// Read raw ciphertext from the file
	offset, err := fileA.DataOffset()
	if err != nil {
		t.Fatalf("Failed to get data offset for file A: %v", err)
	}
	ciphertext := make([]byte, fileA.CompressedSize64)
	if _, err := zrA.r.ReadAt(ciphertext, offset); err != nil {
		t.Fatalf("Failed to read raw ciphertext from zip A: %v", err)
	}

	// 3. Decrypt the raw ciphertext using ZipCryptoDecryptor and passwordA
	decryptor, err := ZipCryptoDecryptor(io.NewSectionReader(bytes.NewReader(ciphertext), 0, int64(len(ciphertext))), []byte("passwordA"))
	if err != nil {
		t.Fatalf("Failed to decrypt ciphertext: %v", err)
	}
	compressedBytes := make([]byte, decryptor.Size())
	if _, err := decryptor.Read(compressedBytes); err != nil && err != io.EOF {
		t.Fatalf("Failed to read decrypted compressed bytes: %v", err)
	}

	// 4. Create a new zip file using CreateRaw and a different password (passwordB)
	bufB := new(bytes.Buffer)
	zwB := NewWriter(bufB)

	fhB := &FileHeader{
		Name:               fileA.Name,
		Method:             fileA.Method,
		CRC32:              fileA.CRC32,
		XXH3:               fileA.XXH3,
		UncompressedSize64: fileA.UncompressedSize64,
	}
	fhB.SetPassword("passwordB")
	fhB.SetEncryptionMethod(StandardEncryption)

	wB, err := zwB.CreateRaw(fhB)
	if err != nil {
		t.Fatalf("Failed to create raw file in zip B: %v", err)
	}
	if _, err := wB.Write(compressedBytes); err != nil {
		t.Fatalf("Failed to write raw data to zip B: %v", err)
	}
	if err := zwB.Close(); err != nil {
		t.Fatalf("Failed to close zip B: %v", err)
	}

	// 5. Open the new zip and verify we can read it using passwordB
	zipDataB := bufB.Bytes()
	zrB, err := NewReader(bytes.NewReader(zipDataB), int64(len(zipDataB)))
	if err != nil {
		t.Fatalf("Failed to open zip B reader: %v", err)
	}
	if len(zrB.File) != 1 {
		t.Fatalf("Expected 1 file in zip B, got %d", len(zrB.File))
	}
	fileB := zrB.File[0]
	fileB.SetPassword("passwordB")

	rc, err := fileB.Open()
	if err != nil {
		t.Fatalf("Failed to open decrypted file B: %v", err)
	}
	defer rc.Close()

	readData, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("Failed to read data from decrypted file B: %v", err)
	}

	if !bytes.Equal(readData, plaintext) {
		t.Errorf("Expected decrypted data %q, but got %q", plaintext, readData)
	}

	// Also verify that the metadata (CRC32, size) is preserved and matches
	if fileB.CRC32 != fileA.CRC32 {
		t.Errorf("CRC32 mismatch: got %x, expected %x", fileB.CRC32, fileA.CRC32)
	}
	if fileB.UncompressedSize64 != fileA.UncompressedSize64 {
		t.Errorf("Uncompressed size mismatch: got %d, expected %d", fileB.UncompressedSize64, fileA.UncompressedSize64)
	}
}

func TestCopyRawPart(t *testing.T) {
	// 1. Create Zip A containing file1.txt encrypted with passwordA
	plaintext1 := []byte("Content of file 1 from Zip A")
	bufA := new(bytes.Buffer)
	zwA := NewWriter(bufA)
	fhA := &FileHeader{
		Name:   "file1.txt",
		Method: Deflate,
	}
	fhA.SetPassword("passwordA")
	fhA.SetEncryptionMethod(StandardEncryption)
	wA, _ := zwA.CreateHeader(fhA)
	wA.Write(plaintext1)
	zwA.Close()

	// 2. Create Zip B containing file2.txt encrypted with passwordB
	plaintext2 := []byte("Content of file 2 from Zip B - some more text to deflate!")
	bufB := new(bytes.Buffer)
	zwB := NewWriter(bufB)
	fhB := &FileHeader{
		Name:   "file2.txt",
		Method: Deflate,
	}
	fhB.SetPassword("passwordB")
	fhB.SetEncryptionMethod(StandardEncryption)
	wB, _ := zwB.CreateHeader(fhB)
	wB.Write(plaintext2)
	zwB.Close()

	// 3. Extract the full raw file part bytes from both zip archives
	zipDataA := bufA.Bytes()
	zrA, _ := NewReader(bytes.NewReader(zipDataA), int64(len(zipDataA)))
	fileA := zrA.File[0]
	var lfhBufA [30]byte
	zrA.r.ReadAt(lfhBufA[:], fileA.headerOffset)
	extraLenA := uint16(lfhBufA[28]) | uint16(lfhBufA[29])<<8
	partLenA := uint64(fileHeaderLen + len(fileA.Name) + int(extraLenA)) + fileA.CompressedSize64 + uint64(dataDescriptorLen)
	partBytesA := zipDataA[fileA.headerOffset : fileA.headerOffset+int64(partLenA)]

	zipDataB := bufB.Bytes()
	zrB, _ := NewReader(bytes.NewReader(zipDataB), int64(len(zipDataB)))
	fileB := zrB.File[0]
	var lfhBufB [30]byte
	zrB.r.ReadAt(lfhBufB[:], fileB.headerOffset)
	extraLenB := uint16(lfhBufB[28]) | uint16(lfhBufB[29])<<8
	partLenB := uint64(fileHeaderLen + len(fileB.Name) + int(extraLenB)) + fileB.CompressedSize64 + uint64(dataDescriptorLen)
	partBytesB := zipDataB[fileB.headerOffset : fileB.headerOffset+int64(partLenB)]

	// 4. Rekey and merge both raw file parts into Zip C under passwordCommon
	bufC := new(bytes.Buffer)
	zwC := NewWriter(bufC)

	err := zwC.CopyRawPart(bytes.NewReader(partBytesA), "passwordA", "passwordCommon", nil)
	if err != nil {
		t.Fatalf("Failed to copy/rekey part 1: %v", err)
	}

	err = zwC.CopyRawPart(bytes.NewReader(partBytesB), "passwordB", "passwordCommon", nil)
	if err != nil {
		t.Fatalf("Failed to copy/rekey part 2: %v", err)
	}

	zwC.Close()

	// 5. Read back Zip C and verify both files decrypt and decompress correctly with passwordCommon
	zipDataC := bufC.Bytes()
	zrC, err := NewReader(bytes.NewReader(zipDataC), int64(len(zipDataC)))
	if err != nil {
		t.Fatalf("Failed to open zip C reader: %v", err)
	}
	if len(zrC.File) != 2 {
		t.Fatalf("Expected 2 files in zip C, got %d", len(zrC.File))
	}

	zrC.SetPassword("passwordCommon")

	// Verify file1
	fC1 := zrC.File[0]
	if fC1.Name != "file1.txt" {
		t.Fatalf("Expected first file to be file1.txt, got %s", fC1.Name)
	}
	rc1, err := fC1.Open()
	if err != nil {
		t.Fatalf("Failed to open file1 from Zip C: %v", err)
	}
	data1, _ := io.ReadAll(rc1)
	rc1.Close()
	if !bytes.Equal(data1, plaintext1) {
		t.Errorf("file1 content mismatch: got %q, expected %q", data1, plaintext1)
	}
	if fC1.CRC32 != fileA.CRC32 || fC1.UncompressedSize64 != fileA.UncompressedSize64 {
		t.Errorf("file1 metadata mismatch")
	}

	// Verify file2
	fC2 := zrC.File[1]
	rc2, err := fC2.Open()
	if err != nil {
		t.Fatalf("Failed to open file2 from Zip C: %v", err)
	}
	data2, _ := io.ReadAll(rc2)
	rc2.Close()
	if !bytes.Equal(data2, plaintext2) {
		t.Errorf("file2 content mismatch: got %q, expected %q", data2, plaintext2)
	}
	if fC2.CRC32 != fileB.CRC32 || fC2.UncompressedSize64 != fileB.UncompressedSize64 {
		t.Errorf("file2 metadata mismatch")
	}
}

func TestCopyRawPartRobustOverrides(t *testing.T) {
	// 1. Create a zip with one file encrypted with passwordA
	plaintext := []byte("Some robust secret data for full metadata override and decryption to plaintext!")
	bufA := new(bytes.Buffer)
	zwA := NewWriter(bufA)
	fhA := &FileHeader{
		Name:   "to_be_overridden.txt",
		Method: Deflate,
	}
	fhA.SetPassword("passwordA")
	fhA.SetEncryptionMethod(StandardEncryption)
	wA, _ := zwA.CreateHeader(fhA)
	wA.Write(plaintext)
	zwA.Close()

	// 2. Extract the raw file part
	zipDataA := bufA.Bytes()
	zrA, _ := NewReader(bytes.NewReader(zipDataA), int64(len(zipDataA)))
	fileA := zrA.File[0]
	var lfhBuf [30]byte
	zrA.r.ReadAt(lfhBuf[:], fileA.headerOffset)
	extraLen := uint16(lfhBuf[28]) | uint16(lfhBuf[29])<<8
	partLen := uint64(fileHeaderLen + len(fileA.Name) + int(extraLen)) + fileA.CompressedSize64 + uint64(dataDescriptorLen)
	partBytes := zipDataA[fileA.headerOffset : fileA.headerOffset+int64(partLen)]

	// 3. Rekey and merge with robust overrides AND decryption to plaintext (newPassword = "")
	bufB := new(bytes.Buffer)
	zwB := NewWriter(bufB)

	customXXH3 := uint64(0x9876543210abcdef)
	customExtra := []byte{0xcd, 0xab, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04} // Custom tag 0xabcd, length 4, value 0x01020304
	err := zwB.CopyRawPart(bytes.NewReader(partBytes), "passwordA", "", func(override *OverridableFileHeader) {
		override.Name = "robust_overridden.txt"
		override.ModifiedTime = 12345
		override.ModifiedDate = 23456
		override.Comment = "Robust overridden comment"
		override.XXH3 = customXXH3
		override.CreatorVersion = 0x031e // UNIX, version 3.0
		override.ReaderVersion = 20
		override.ExternalAttrs = 0x81ed0000 // UNIX permissions -rwxr-xr-x
		override.Extra = customExtra
	})
	if err != nil {
		t.Fatalf("Failed to CopyRawPart: %v", err)
	}
	zwB.Close()

	// 4. Read back and verify the overrides and content
	zipDataB := bufB.Bytes()
	zrB, err := NewReader(bytes.NewReader(zipDataB), int64(len(zipDataB)))
	if err != nil {
		t.Fatalf("Failed to open zip B: %v", err)
	}
	if len(zrB.File) != 1 {
		t.Fatalf("Expected 1 file, got %d", len(zrB.File))
	}

	fileB := zrB.File[0]

	// Verify safe metadata overrides
	if fileB.Name != "robust_overridden.txt" {
		t.Errorf("Expected Name 'robust_overridden.txt', got '%s'", fileB.Name)
	}
	if fileB.ModifiedTime != 12345 {
		t.Errorf("Expected ModifiedTime 12345, got %d", fileB.ModifiedTime)
	}
	if fileB.ModifiedDate != 23456 {
		t.Errorf("Expected ModifiedDate 23456, got %d", fileB.ModifiedDate)
	}
	if fileB.Comment != "Robust overridden comment" {
		t.Errorf("Expected Comment 'Robust overridden comment', got '%s'", fileB.Comment)
	}
	if fileB.XXH3 != customXXH3 {
		t.Errorf("Expected XXH3 %x, got %x", customXXH3, fileB.XXH3)
	}
	if fileB.CreatorVersion != 0x0314 {
		t.Errorf("Expected CreatorVersion 0x0314, got 0x%x", fileB.CreatorVersion)
	}
	if fileB.ReaderVersion != 20 {
		t.Errorf("Expected ReaderVersion 20, got %d", fileB.ReaderVersion)
	}
	if fileB.ExternalAttrs != 0x81ed0000 {
		t.Errorf("Expected ExternalAttrs 0x81ed0000, got 0x%x", fileB.ExternalAttrs)
	}
	if !bytes.Contains(fileB.Extra, customExtra) {
		t.Errorf("Expected Extra to contain custom extra block %v, got %v", customExtra, fileB.Extra)
	}

	// Verify encryption was stripped
	if fileB.IsEncrypted() {
		t.Errorf("Expected fileB.IsEncrypted() to be false, but it was true")
	}

	// Verify content decrypts/decompresses correctly (without setting password on fileB)
	rc, err := fileB.Open()
	if err != nil {
		t.Fatalf("Failed to open fileB: %v", err)
	}
	defer rc.Close()
	data, _ := io.ReadAll(rc)
	if !bytes.Equal(data, plaintext) {
		t.Errorf("Content mismatch: got %q, expected %q", data, plaintext)
	}

	// Verify data integrity sizes & CRC32 are uncorrupted
	if fileB.CRC32 != fileA.CRC32 {
		t.Errorf("CRC32 mismatch: got %x, expected %x", fileB.CRC32, fileA.CRC32)
	}
	if fileB.UncompressedSize64 != fileA.UncompressedSize64 {
		t.Errorf("Uncompressed size mismatch: got %d, expected %d", fileB.UncompressedSize64, fileA.UncompressedSize64)
	}
}

func TestCopyRawPartEmptyFilesAndDirectories(t *testing.T) {
	// 1. Create a zip with an empty file and a directory (which are not encrypted)
	bufA := new(bytes.Buffer)
	zwA := NewWriter(bufA)

	// Directory entry (marked by trailing slash in ZIP format)
	fhDir := &FileHeader{
		Name: "testdir/",
	}
	_, err := zwA.CreateHeader(fhDir)
	if err != nil {
		t.Fatalf("Failed to create dir header: %v", err)
	}

	// Empty file entry
	fhEmpty := &FileHeader{
		Name: "testdir/empty.txt",
	}
	_, err = zwA.CreateHeader(fhEmpty)
	if err != nil {
		t.Fatalf("Failed to create empty file header: %v", err)
	}

	zwA.Close()

	// 2. Extract raw file parts from Zip A
	zipDataA := bufA.Bytes()
	zrA, err := NewReader(bytes.NewReader(zipDataA), int64(len(zipDataA)))
	if err != nil {
		t.Fatalf("Failed to parse Zip A: %v", err)
	}

	if len(zrA.File) != 2 {
		t.Fatalf("Expected 2 files in Zip A, got %d", len(zrA.File))
	}

	// Extract raw part bytes for Directory
	fileDir := zrA.File[0]
	var lfhBufDir [30]byte
	zrA.r.ReadAt(lfhBufDir[:], fileDir.headerOffset)
	extraLenDir := uint16(lfhBufDir[28]) | uint16(lfhBufDir[29])<<8
	partLenDir := uint64(fileHeaderLen + len(fileDir.Name) + int(extraLenDir)) + fileDir.CompressedSize64 + uint64(dataDescriptorLen)
	partBytesDir := zipDataA[fileDir.headerOffset : fileDir.headerOffset+int64(partLenDir)]

	// Extract raw part bytes for Empty File
	fileEmpty := zrA.File[1]
	var lfhBufEmpty [30]byte
	zrA.r.ReadAt(lfhBufEmpty[:], fileEmpty.headerOffset)
	extraLenEmpty := uint16(lfhBufEmpty[28]) | uint16(lfhBufEmpty[29])<<8
	partLenEmpty := uint64(fileHeaderLen + len(fileEmpty.Name) + int(extraLenEmpty)) + fileEmpty.CompressedSize64 + uint64(dataDescriptorLen)
	partBytesEmpty := zipDataA[fileEmpty.headerOffset : fileEmpty.headerOffset+int64(partLenEmpty)]

	// 3. Re-key/Reconstruct these raw parts into Zip B
	// Even though they are unencrypted, we pass a non-empty oldPassword and newPassword
	// to simulate the backup database behavior described in Bug 2.
	bufB := new(bytes.Buffer)
	zwB := NewWriter(bufB)

	// Copy directory raw part
	err = zwB.CopyRawPart(bytes.NewReader(partBytesDir), "oldPass", "newPass", nil)
	if err != nil {
		t.Fatalf("Failed to copy dir raw part: %v", err)
	}

	// Copy empty file raw part
	err = zwB.CopyRawPart(bytes.NewReader(partBytesEmpty), "oldPass", "newPass", nil)
	if err != nil {
		t.Fatalf("Failed to copy empty file raw part: %v", err)
	}

	zwB.Close()

	// 4. Read back Zip B and verify sizes are exactly 0
	zipDataB := bufB.Bytes()
	zrB, err := NewReader(bytes.NewReader(zipDataB), int64(len(zipDataB)))
	if err != nil {
		t.Fatalf("Failed to parse Zip B: %v", err)
	}

	if len(zrB.File) != 2 {
		t.Fatalf("Expected 2 files in Zip B, got %d", len(zrB.File))
	}

	// Verify Directory
	resDir := zrB.File[0]
	if resDir.Name != "testdir/" {
		t.Errorf("Expected 'testdir/', got '%s'", resDir.Name)
	}
	if resDir.UncompressedSize64 != 0 {
		t.Errorf("Expected directory uncompressed size 0, got %d", resDir.UncompressedSize64)
	}
	if resDir.CompressedSize64 != 0 {
		t.Errorf("Expected directory compressed size 0, got %d", resDir.CompressedSize64)
	}

	// Verify Empty File
	resEmpty := zrB.File[1]
	if resEmpty.Name != "testdir/empty.txt" {
		t.Errorf("Expected 'testdir/empty.txt', got '%s'", resEmpty.Name)
	}
	if resEmpty.UncompressedSize64 != 0 {
		t.Errorf("Expected empty file uncompressed size 0, got %d", resEmpty.UncompressedSize64)
	}
	if resEmpty.CompressedSize64 != 0 {
		t.Errorf("Expected empty file compressed size 0, got %d", resEmpty.CompressedSize64)
	}
}


