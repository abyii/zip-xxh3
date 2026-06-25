package zip

import (
	"bytes"
	"io"
	"path/filepath"
	"testing"
)

// Test simple password reading.
func TestPasswordReadSimple(t *testing.T) {
	file := "hello-aes.zip"
	var buf bytes.Buffer
	r, err := OpenReader(filepath.Join("testdata", file))
	if err != nil {
		t.Errorf("Expected %s to open: %v.", file, err)
	}
	defer r.Close()
	if len(r.File) != 1 {
		t.Errorf("Expected %s to contain one file.", file)
	}
	f := r.File[0]
	if f.FileInfo().Name() != "hello.txt" {
		t.Errorf("Expected %s to have a file named hello.txt", file)
	}
	if f.Method != 0 {
		t.Errorf("Expected %s to have its Method set to 0.", file)
	}
	f.SetPassword("golang")
	rc, err := f.Open()
	if err != nil {
		t.Errorf("Expected to open the readcloser: %v.", err)
	}
	_, err = io.Copy(&buf, rc)
	if err != nil {
		t.Errorf("Expected to copy bytes: %v.", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("Hello World\r\n")) {
		t.Errorf("Expected contents were not found.")
	}
}

// Test for multi-file password protected zip.
// Each file can be protected with a different password.
func TestPasswordHelloWorldAes(t *testing.T) {
	file := "world-aes.zip"
	expecting := "helloworld"
	r, err := OpenReader(filepath.Join("testdata", file))
	if err != nil {
		t.Errorf("Expected %s to open: %v", file, err)
	}
	defer r.Close()
	if len(r.File) != 2 {
		t.Errorf("Expected %s to contain two files.", file)
	}
	var b bytes.Buffer
	for _, f := range r.File {
		if !f.IsEncrypted() {
			t.Errorf("Expected %s to be encrypted.", f.FileInfo().Name())
		}
		f.SetPassword("golang")
		rc, err := f.Open()
		if err != nil {
			t.Errorf("Expected to open readcloser: %v", err)
		}
		defer rc.Close()
		if _, err := io.Copy(&b, rc); err != nil {
			t.Errorf("Expected to copy bytes to buffer: %v", err)
		}
	}
	if !bytes.Equal([]byte(expecting), b.Bytes()) {
		t.Errorf("Expected ending content to be %s instead of %s", expecting, b.Bytes())
	}
}

// Test for password protected file that is larger than a single
// AES block size to check CTR implementation.
func TestPasswordMacbethAct1(t *testing.T) {
	file := "macbeth-act1.zip"
	expecting := "Exeunt"
	var b bytes.Buffer
	r, err := OpenReader(filepath.Join("testdata", file))
	if err != nil {
		t.Errorf("Expected %s to open: %v", file, err)
	}
	defer r.Close()
	for _, f := range r.File {
		if !f.IsEncrypted() {
			t.Errorf("Expected %s to be encrypted.", f.Name)
		}
		f.SetPassword("golang")
		rc, err := f.Open()
		if err != nil {
			t.Errorf("Expected to open readcloser: %v", err)
		}
		defer rc.Close()
		if _, err := io.Copy(&b, rc); err != nil {
			t.Errorf("Expected to copy bytes to buffer: %v", err)
		}
	}
	if !bytes.Contains(b.Bytes(), []byte(expecting)) {
		t.Errorf("Expected to find %s in the buffer %v", expecting, b.Bytes())
	}
}

// Change to AE-1 and change CRC value to fail check.
// Must be != 0 due to zip package already skipping if == 0.
func returnAE1BadCRC() (io.ReaderAt, int64) {
	return messWith("hello-aes.zip", func(b []byte) {
		// Change version to AE-1(1)
		b[0x2B] = 1 // file
		b[0xBA] = 1 // TOC
		// Change CRC to bad value
		b[0x11]++ // file
		b[0x6B]++ // TOC
	})
}

// Test for AE-1 Corrupt CRC
func TestPasswordAE1BadCRC(t *testing.T) {
	buf := new(bytes.Buffer)
	file, s := returnAE1BadCRC()
	r, err := NewReader(file, s)
	if err != nil {
		t.Errorf("Expected hello-aes.zip to open: %v", err)
	}
	for _, f := range r.File {
		if !f.IsEncrypted() {
			t.Errorf("Expected zip to be encrypted")
		}
		f.SetPassword("golang")
		rc, err := f.Open()
		if err != nil {
			t.Errorf("Expected the readcloser to open.")
		}
		defer rc.Close()
		if _, err := io.Copy(buf, rc); err != ErrChecksum {
			t.Errorf("Expected the checksum to fail")
		}
	}
}

// Corrupt the last byte of ciphertext to fail authentication
func returnTamperedData() (io.ReaderAt, int64) {
	return messWith("hello-aes.zip", func(b []byte) {
		b[0x50]++
	})
}

// Test for tampered file data payload.
func TestPasswordTamperedData(t *testing.T) {
	buf := new(bytes.Buffer)
	file, s := returnTamperedData()
	r, err := NewReader(file, s)
	if err != nil {
		t.Errorf("Expected hello-aes.zip to open: %v", err)
	}
	for _, f := range r.File {
		if !f.IsEncrypted() {
			t.Errorf("Expected zip to be encrypted")
		}
		f.SetPassword("golang")
		rc, err := f.Open()
		if err != nil {
			t.Errorf("Expected the readcloser to open.")
		}
		defer rc.Close()
		if _, err := io.Copy(buf, rc); err != ErrAuthentication {
			t.Errorf("Expected the checksum to fail")
		}
	}
}

func TestPasswordWriteSimple(t *testing.T) {
	contents := []byte("Hello World")
	conLen := len(contents)

	methods := []struct {
		method uint16
		level  int
	}{
		{Deflate, -1},
		{Store, 0},
	}

	for _, m := range methods {
		for _, enc := range []EncryptionMethod{StandardEncryption, AES128Encryption, AES192Encryption, AES256Encryption} {
			raw := new(bytes.Buffer)
			zipw := NewWriter(raw)
			w, err := zipw.Create("hello.txt", m.method, m.level, enc, "golang")
			if err != nil {
				t.Errorf("Expected to create a new FileHeader for method %d: %v", m.method, err)
				continue
			}
			n, err := io.Copy(w, bytes.NewReader(contents))
			if err != nil || n != int64(conLen) {
				t.Errorf("Expected to write the full contents to the writer for method %d: %v", m.method, err)
			}
			zipw.Close()

			// Read the zip
			buf := new(bytes.Buffer)
			zipr, err := NewReader(bytes.NewReader(raw.Bytes()), int64(raw.Len()))
			if err != nil {
				t.Errorf("Expected to open a new zip reader for method %d: %v", m.method, err)
				continue
			}
			nn := len(zipr.File)
			if nn != 1 {
				t.Errorf("Expected to have one file in the zip archive, but has %d files", nn)
			}
			z := zipr.File[0]
			z.SetPassword("golang")
			rr, err := z.Open()
			if err != nil {
				t.Errorf("Expected to open the readcloser for method %d: %v", m.method, err)
				continue
			}
			n, err = io.Copy(buf, rr)
			if err != nil {
				t.Errorf("Expected to write to temporary buffer: %v", err)
			}
			if n != int64(conLen) {
				t.Errorf("Expected to copy %d bytes to temp buffer, but copied %d bytes instead", conLen, n)
			}
			if !bytes.Equal(contents, buf.Bytes()) {
				t.Errorf("Expected the unzipped contents to equal '%s', but was '%s' instead for method %d", contents, buf.Bytes(), m.method)
			}
			rr.Close()
		}
	}
}

func TestZipCrypto(t *testing.T) {
	contents := []byte("Hello World")
	conLen := len(contents)

	raw := new(bytes.Buffer)
	zipw := NewWriter(raw)
	w, err := zipw.Create("hello.txt", Deflate, -1, StandardEncryption, "golang")
	if err != nil {
		t.Errorf("Expected to create a new FileHeader")
	}
	n, err := io.Copy(w, bytes.NewReader(contents))
	if err != nil || n != int64(conLen) {
		t.Errorf("Expected to write the full contents to the writer.")
	}
	zipw.Close()

	zipr, _ := NewReader(bytes.NewReader(raw.Bytes()), int64(raw.Len()))
	zipr.File[0].SetPassword("golang")
	r, _ := zipr.File[0].Open()
	res := new(bytes.Buffer)
	io.Copy(res, r)
	r.Close()

	if !bytes.Equal(contents, res.Bytes()) {
		t.Errorf("Expected the unzipped contents to equal '%s', but was '%s' instead", contents, res.Bytes())
	}
}

func TestPasswordWriteZeroBytes(t *testing.T) {
	methods := []struct {
		method uint16
		level  int
	}{
		{Deflate, -1},
		{Store, 0},
	}

	for _, m := range methods {
		for _, enc := range []EncryptionMethod{StandardEncryption, AES128Encryption, AES192Encryption, AES256Encryption} {
			raw := new(bytes.Buffer)
			zipw := NewWriter(raw)
			_, err := zipw.Create("empty.txt", m.method, m.level, enc, "golang")
			if err != nil {
				t.Fatalf("Expected to create a new FileHeader for method %d, enc %d: %v", m.method, enc, err)
			}
			// Write nothing (0 bytes)
			if err := zipw.Close(); err != nil {
				t.Fatalf("Expected to close writer: %v", err)
			}

			// Read the zip back
			zipr, err := NewReader(bytes.NewReader(raw.Bytes()), int64(raw.Len()))
			if err != nil {
				t.Fatalf("Expected to open new zip reader for method %d, enc %d: %v", m.method, enc, err)
			}
			if len(zipr.File) != 1 {
				t.Fatalf("Expected 1 file, got %d", len(zipr.File))
			}
			f := zipr.File[0]
			if f.UncompressedSize64 != 0 {
				t.Errorf("Expected UncompressedSize64 to be 0, but got %d", f.UncompressedSize64)
			}
			// Windows size/underflow check: compressed size must not underflow
			// Let's verify decryption of the 0-byte file works properly
			f.SetPassword("golang")
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("Expected f.Open() to succeed for method %d, enc %d: %v", m.method, enc, err)
			}
			buf, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				t.Errorf("Expected to read f successfully for method %d, enc %d: %v", m.method, enc, err)
			}
			if len(buf) != 0 {
				t.Errorf("Expected 0 bytes, but read %d bytes: %v", len(buf), buf)
			}
		}
	}
}
