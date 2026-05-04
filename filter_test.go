package zip

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestFilterZipStream(t *testing.T) {
	// Create a dummy zip file
	buf := new(bytes.Buffer)
	w := NewWriter(buf)

	// File 1: keep
	f1, err := w.Create("keep.txt", Deflate, 5, NoEncryption, "")
	if err != nil {
		t.Fatal(err)
	}
	f1.Write([]byte("this file should be kept"))

	// File 2: ignore
	f2, err := w.Create("ignore.txt", Deflate, 5, NoEncryption, "")
	if err != nil {
		t.Fatal(err)
	}
	f2.Write([]byte("this file should be ignored"))

	// File 3: keep (store method)
	f3, err := w.Create("keep_stored.txt", Store, 0, NoEncryption, "")
	if err != nil {
		t.Fatal(err)
	}
	f3.Write([]byte("this file should also be kept"))

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	originalBytes := buf.Bytes()
	r, err := NewReader(bytes.NewReader(originalBytes), int64(len(originalBytes)))
	if err != nil {
		t.Fatal(err)
	}

	// Filter
	outBuf := new(bytes.Buffer)
	stream := bytes.NewReader(originalBytes)

	err = FilterZipStream(r, stream, outBuf, func(f *File) bool {
		return strings.HasPrefix(f.Name, "keep")
	})
	if err != nil {
		t.Fatal(err)
	}

	// Verify Output
	filteredBytes := outBuf.Bytes()
	r2, err := NewReader(bytes.NewReader(filteredBytes), int64(len(filteredBytes)))
	if err != nil {
		t.Fatal(err)
	}

	if len(r2.File) != 2 {
		t.Fatalf("expected 2 files, got %d", len(r2.File))
	}

	if r2.File[0].Name != "keep.txt" {
		t.Errorf("expected keep.txt, got %s", r2.File[0].Name)
	}
	if r2.File[1].Name != "keep_stored.txt" {
		t.Errorf("expected keep_stored.txt, got %s", r2.File[1].Name)
	}

	// Check content
	rc, err := r2.File[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	content, _ := io.ReadAll(rc)
	rc.Close()
	if string(content) != "this file should be kept" {
		t.Errorf("content mismatch: %s", string(content))
	}
}
