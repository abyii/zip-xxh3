## zip-xxh3

`yeka/zip` is a fork of Go's `archive/zip` that adds support for Standard Zip Encryption.
This is a fork of `yeka/zip` that:
 - supports specifying compression level.
 - replaces compress/flate with klauspost/compress/flate which is an optimised version of compress/flate, and implements better gradient accross different compression levels.
 - adds support for XXH3 64 bit checksum (using zeebo/xxh3).

> XXhash3 is a extremely fast, non-cryptographic hash function. It is designed to be used in high-performance applications where speed is important. It has excellent collision distribution. XXhash3 is so fast that it is often bottlenecked by how fast you can read bytes off the disk and not the algorithm itself.

## Installation

```bash
go get github.com/abyii/zip-xxh3
```

## Usage


this package maintains a similar API to the standard `archive/zip` library but extends it with encryption capabilities via the `Create` method.

### `Create` function

You can add files to the archive using the `Create` method on a `zip.Writer`.

```go
func (w *Writer) Create(name string, method uint16, level int, enc EncryptionMethod, password string) (io.Writer, error)
```

**Arguments:**

*   `name`: The name of the file within the zip archive (e.g., "my_file.txt").
*   `method`: The compression method to use.
    *   `zip.Store`: No compression.
    *   `zip.Deflate`: Compresses the file data.
*   `level`: The compression level for the `Deflate` method. It ranges from -1 (default) to 9 (best compression). For `zip.Store`, this should be 0.
*   `enc`: The encryption method.
    *   `zip.NoEncryption`: No encryption.
    *   `zip.StandardEncryption`: Standard Zip 2.0 encryption.
    *   `zip.AES128Encryption`: AES-128 encryption.
    *   `zip.AES192Encryption`: AES-192 encryption.
    *   `zip.AES256Encryption`: AES-256 encryption.
*   `password`: The password to use for encryption. This is required if an encryption method other than `NoEncryption` is chosen.

**Example:**

This example shows how to create a zip file with one compressed and encrypted file.

```go
package main

import (
	"bytes"
	"io"
	"log"
	"os"

	"github.com/abyii/zip-xxh3"
)

func main() {
	// Create a buffer to write our archive to.
	buf := new(bytes.Buffer)

	// Create a new zip archive.
	zipWriter := zip.NewWriter(buf)

	// Add a file to the archive.
	// The file will be named "hello.txt", compressed with Deflate,
	// and encrypted with AES-256.
	writer, err := zipWriter.Create("hello.txt", zip.Deflate, -1, zip.AES256Encryption, "supersecret")
	if err != nil {
		log.Fatal(err)
	}

	// Write content to the file.
	_, err = io.WriteString(writer, "Hello, World!")
	if err != nil {
		log.Fatal(err)
	}

	// Close the zip writer to finalize the archive.
	err = zipWriter.Close()
	if err != nil {
		log.Fatal(err)
	}

	// Write the resulting zip file to disk.
	err = os.WriteFile("encrypted.zip", buf.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Created encrypted.zip")
}
```

### Detached Mode

Detached mode allows you to create a zip file from parts that can be processed concurrently. This is useful when you need to generate file parts in parallel and then assemble them into a single zip archive at the end. The process involves creating individual file parts, generating a central directory, and then appending all the pieces together.

**Functions:**

*   `CreateFilePart(name string, method uint16, level int, enc EncryptionMethod, password string, order int, partWriter io.Writer) (io.WriteCloser, error)`: Creates a new file part in the zip archive. It returns a writer to which the file contents should be written.
*   `GetCentralDirectoryBytes() ([]byte, error)`: Returns the central directory for the zip archive. This should be called after all file parts have been created and closed.

**Example:**

This example demonstrates how to create a zip file with multiple file parts, including one that is encrypted. The file parts are created in memory and then assembled into a final zip file.

```go
package main

import (
	"bytes"
	"io"
	"log"
	"os"

	"github.com/abyii/zip-xxh3"
)

func main() {
	// Create a new detached writer.
	zipw := zip.NewWriter()

	// Define the files to be added to the zip archive.
	testFiles := []struct {
		Name     string
		Content  []byte
		Password string
	}{
		{"hello.txt", []byte("Hello, World!"), ""},
		{"secret.txt", []byte("This is a secret."), "supersecret"},
	}

	// Create file parts and write content.
	var fileParts [][]byte
	for i, tf := range testFiles {
		buf := new(bytes.Buffer)
		encMethod := zip.NoEncryption
		if tf.Password != "" {
			encMethod = zip.AES256Encryption
		}
		w, err := zipw.CreateFilePart(tf.Name, zip.Deflate, -1, encMethod, tf.Password, i, buf)
		if err != nil {
			log.Fatalf("Failed to create file part for %s: %v", tf.Name, err)
		}
		_, err = w.Write(tf.Content)
		if err != nil {
			log.Fatalf("Failed to write to file part for %s: %v", tf.Name, err)
		}
		if err := w.Close(); err != nil {
			log.Fatalf("Failed to close file part for %s: %v", tf.Name, err)
		}
		fileParts = append(fileParts, buf.Bytes())
	}

	// Get the central directory.
	cd, err := zipw.GetCentralDirectoryBytes()
	if err != nil {
		log.Fatalf("Failed to get central directory: %v", err)
	}

	// Assemble the zip file.
	var finalZip bytes.Buffer
	for _, part := range fileParts {
		finalZip.Write(part)
	}
	finalZip.Write(cd)

	// Write the resulting zip file to disk.
	err = os.WriteFile("detached.zip", finalZip.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Created detached.zip")
}
```
