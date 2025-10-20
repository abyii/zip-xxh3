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
