// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zip

import (
	"bytes"
	"io"
	"math/rand"
	"os"
	"testing"
)

// TODO(adg): a more sophisticated test suite

type WriteTest struct {
	Name   string
	Data   []byte
	Method uint16
	Mode   os.FileMode
}

var writeTests = []WriteTest{
	{
		Name:   "foo",
		Data:   []byte("Rabbits, guinea pigs, gophers, marsupial rats, and quolls."),
		Method: Store,
		Mode:   0666,
	},
	{
		Name:   "bar",
		Data:   nil, // large data set in the test
		Method: Deflate,
		Mode:   0644,
	},
	{
		Name:   "setuid",
		Data:   []byte("setuid file"),
		Method: Deflate,
		Mode:   0755 | os.ModeSetuid,
	},
	{
		Name:   "setgid",
		Data:   []byte("setgid file"),
		Method: Deflate,
		Mode:   0755 | os.ModeSetgid,
	},
	{
		Name:   "symlink",
		Data:   []byte("../link/target"),
		Method: Deflate,
		Mode:   0755 | os.ModeSymlink,
	},
}

func TestWriter(t *testing.T) {
	largeData := make([]byte, 1<<17)
	for i := range largeData {
		largeData[i] = byte(rand.Int())
	}
	writeTests[1].Data = largeData
	defer func() {
		writeTests[1].Data = nil
	}()

	// write a zip file
	buf := new(bytes.Buffer)
	w := NewWriter(buf)

	for _, wt := range writeTests {
		testCreate(t, w, &wt)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// read it back
	r, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for i, wt := range writeTests {
		testReadFile(t, r.File[i], &wt)
	}
}

func TestDetachedWriter(t *testing.T) {
	// Create a new detached writer
	zipw := NewWriter()

	// Create a file part
	buf := new(bytes.Buffer)
	fh := &FileHeader{
		Name:   "hello.txt",
		Method: Deflate,
	}
	w, err := zipw.CreateFileParts(fh, 0, buf)
	if err != nil {
		t.Fatalf("Failed to create file part: %v", err)
	}

	// Write to the file part
	contents := []byte("Hello, World!")
	_, err = w.Write(contents)
	if err != nil {
		t.Fatalf("Failed to write to file part: %v", err)
	}

	// Close the file part
	if err := w.Close(); err != nil {
		t.Fatalf("Failed to close file part: %v", err)
	}

	// Close the writer
	if err := zipw.Close(); err != nil {
		t.Fatalf("Failed to close writer: %v", err)
	}

	// Get the central directory
	cd, err := zipw.GetCentralDirectoryBytes()
	if err != nil {
		t.Fatalf("Failed to get central directory: %v", err)
	}

	// Verify the central directory
	if len(cd) == 0 {
		t.Fatal("Central directory is empty")
	}
}

func TestDetachedWriterComprehensive(t *testing.T) {
	// Define the files to be added to the zip archive
	testFiles := []struct {
		Name             string
		Content          []byte
		Password         string
		Method           uint16
		EncMethod        EncryptionMethod
		CompressionLevel int
	}{
		{
			Name:             "file1.txt",
			Content:          []byte("This is a test file."),
			Method:           Deflate,
			CompressionLevel: 9,
		},
		{
			Name:             "file2-std.txt",
			Content:          []byte("This is a standard encrypted file."),
			Password:         "password123",
			Method:           Deflate,
			EncMethod:        StandardEncryption,
			CompressionLevel: 8,
		},
		{
			Name:             "file3-aes128.txt",
			Content:          []byte("This is an AES-128 encrypted file."),
			Password:         "password456",
			Method:           Deflate,
			EncMethod:        AES128Encryption,
			CompressionLevel: 7,
		},
		{
			Name:             "file4-aes192.txt",
			Content:          []byte("This is an AES-192 encrypted file."),
			Password:         "password789",
			Method:           Deflate,
			EncMethod:        AES192Encryption,
			CompressionLevel: 6,
		},
		{
			Name:             "file5-aes256.txt",
			Content:          []byte("This is an AES-256 encrypted file."),
			Password:         "passwordabc",
			Method:           Deflate,
			EncMethod:        AES256Encryption,
			CompressionLevel: 5,
		},
		{
			Name:             "empty.txt",
			Content:          []byte{},
			Method:           Deflate,
			CompressionLevel: 4,
		},
		{
			Name:             "stored.txt",
			Content:          []byte("This file is stored without compression."),
			Method:           Store,
			CompressionLevel: 0,
		},
	}

	// Create a new detached writer
	zipw := NewWriter()

	// Create file parts and write content
	var fileParts [][]byte
	for i, tf := range testFiles {
		buf := new(bytes.Buffer)
		w, err := zipw.CreateFilePartSimple(tf.Name, tf.Method, tf.CompressionLevel, tf.EncMethod, tf.Password, i, buf)
		if err != nil {
			t.Fatalf("Failed to create file part for %s: %v", tf.Name, err)
		}
		_, err = w.Write(tf.Content)
		if err != nil {
			t.Fatalf("Failed to write to file part for %s: %v", tf.Name, err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("Failed to close file part for %s: %v", tf.Name, err)
		}
		fileParts = append(fileParts, buf.Bytes())
	}

	// Close the writer
	if err := zipw.Close(); err != nil {
		t.Fatalf("Failed to close writer: %v", err)
	}

	// Get the central directory
	cd, err := zipw.GetCentralDirectoryBytes()
	if err != nil {
		t.Fatalf("Failed to get central directory: %v", err)
	}

	// Assemble the zip file
	zipBuf := new(bytes.Buffer)
	for _, p := range fileParts {
		zipBuf.Write(p)
	}
	zipBuf.Write(cd)

	// Read and verify the zip file
	r, err := NewReader(bytes.NewReader(zipBuf.Bytes()), int64(zipBuf.Len()))
	if err != nil {
		t.Fatalf("Failed to create zip reader: %v", err)
	}

	if len(r.File) != len(testFiles) {
		t.Fatalf("Expected %d files in zip, but got %d", len(testFiles), len(r.File))
	}

	for _, f := range r.File {
		var tf struct {
			Name             string
			Content          []byte
			Password         string
			Method           uint16
			EncMethod        EncryptionMethod
			CompressionLevel int
		}
		found := false
		for _, testFile := range testFiles {
			if testFile.Name == f.Name {
				tf = testFile
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Found unexpected file %s in zip", f.Name)
		}

		if tf.Password != "" {
			f.SetPassword(tf.Password)
		}

		rc, err := f.Open()
		if err != nil {
			t.Fatalf("Failed to open file %s: %v", f.Name, err)
		}

		content, err := io.ReadAll(rc)
		if err != nil {
			if err == ErrPassword {
				t.Fatalf("Invalid password for file %s", f.Name)
			}
			t.Fatalf("Failed to read content of file %s: %v", f.Name, err)
		}

		if !bytes.Equal(content, tf.Content) {
			t.Errorf("Content of file %s does not match expected content", f.Name)
		}

		rc.Close()
	}
}

func TestDetachedWriterWithPassword(t *testing.T) {
	// Create a new detached writer
	zipw := NewWriter()

	// Create a file part
	buf := new(bytes.Buffer)
	fh := &FileHeader{
		Name:   "hello.txt",
		Method: Deflate,
	}
	fh.SetEncryptionMethod(AES256Encryption)
	fh.SetPassword("golang")
	w, err := zipw.CreateFileParts(fh, 0, buf)
	if err != nil {
		t.Fatalf("Failed to create file part: %v", err)
	}

	// Write to the file part
	contents := []byte("Hello, World!")
	_, err = w.Write(contents)
	if err != nil {
		t.Fatalf("Failed to write to file part: %v", err)
	}

	// Close the file part
	if err := w.Close(); err != nil {
		t.Fatalf("Failed to close file part: %v", err)
	}

	// Close the writer
	if err := zipw.Close(); err != nil {
		t.Fatalf("Failed to close writer: %v", err)
	}

	// Get the central directory
	cd, err := zipw.GetCentralDirectoryBytes()
	if err != nil {
		t.Fatalf("Failed to get central directory: %v", err)
	}

	// Verify the central directory
	if len(cd) == 0 {
		t.Fatal("Central directory is empty")
	}
}

func TestWriterOffset(t *testing.T) {
	largeData := make([]byte, 1<<17)
	for i := range largeData {
		largeData[i] = byte(rand.Int())
	}
	writeTests[1].Data = largeData
	defer func() {
		writeTests[1].Data = nil
	}()

	// write a zip file
	buf := new(bytes.Buffer)
	existingData := []byte{1, 2, 3, 1, 2, 3, 1, 2, 3}
	n, _ := buf.Write(existingData)
	w := NewWriter(buf)
	w.SetOffset(int64(n))

	for _, wt := range writeTests {
		testCreate(t, w, &wt)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	// read it back
	r, err := NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	for i, wt := range writeTests {
		testReadFile(t, r.File[i], &wt)
	}
}

func TestWriterFlush(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(struct{ io.Writer }{&buf})
	_, err := w.Create("foo", Store, 0, NoEncryption, "")
	if err != nil {
		t.Fatal(err)
	}
	if buf.Len() > 0 {
		t.Fatalf("Unexpected %d bytes already in buffer", buf.Len())
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("No bytes written after Flush")
	}
}

func testCreate(t *testing.T, w *Writer, wt *WriteTest) {
	header := &FileHeader{
		Name:   wt.Name,
		Method: wt.Method,
	}
	if wt.Mode != 0 {
		header.SetMode(wt.Mode)
	}
	f, err := w.CreateHeader(header)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.Write(wt.Data)
	if err != nil {
		t.Fatal(err)
	}
}

func testReadFile(t *testing.T, f *File, wt *WriteTest) {
	if f.Name != wt.Name {
		t.Fatalf("File name: got %q, want %q", f.Name, wt.Name)
	}
	testFileMode(t, wt.Name, f, wt.Mode)
	rc, err := f.Open()
	if err != nil {
		t.Fatal("opening:", err)
	}
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal("reading:", err)
	}
	err = rc.Close()
	if err != nil {
		t.Fatal("closing:", err)
	}
	if !bytes.Equal(b, wt.Data) {
		t.Errorf("File contents %q, want %q", b, wt.Data)
	}
}

func BenchmarkCompressedZipGarbage(b *testing.B) {
	b.ReportAllocs()
	var buf bytes.Buffer
	bigBuf := bytes.Repeat([]byte("a"), 1<<20)
	for i := 0; i < b.N; i++ {
		buf.Reset()
		zw := NewWriter(&buf)
		for j := 0; j < 3; j++ {
			w, _ := zw.CreateHeader(&FileHeader{
				Name:   "foo",
				Method: Deflate,
			})
			w.Write(bigBuf)
		}
		zw.Close()
	}
}
