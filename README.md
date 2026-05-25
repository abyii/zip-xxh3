## zip-xxh3

`yeka/zip` is a fork of Go's `archive/zip` that adds support for Standard Zip Encryption.
This is a fork of `yeka/zip` that:
 - supports specifying compression level.
 - replaces compress/flate with klauspost/compress/flate which is an optimised version of compress/flate, and implements better gradient accross different compression levels.
 - adds support for filtering files from a zip archive file stream (stream filtering).
 - adds support for XXH3 64 bit checksum (using zeebo/xxh3).
 - adds support for detached mode (concurrent processing and parallel assembly of file parts).
 - adds support for raw copying and streaming re-keying (re-keying chopped zip file parts with safe metadata overrides under $O(1)$ memory).

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

*   `CreateFilePartSimple(name string, method uint16, level int, enc EncryptionMethod, password string, order int, partWriter io.Writer) (io.WriteCloser, error)`: Creates a new file part in the zip archive. It returns a writer to which the file contents should be written.
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
		w, err := zipw.CreateFilePartSimple(tf.Name, zip.Deflate, -1, encMethod, tf.Password, i, buf)
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

### Stream Filtering

Stream Filtering allows you to parse a zip archive and efficiently filter out files on-the-fly, writing to a new output stream without fully decompressing or decrypting the target files. This acts as a highly optimized raw byte-copy engine that natively recalculates offsets and flawlessly regenerates the Central Directory.

**Functions:**

*   `FilterZipStream(r *Reader, stream io.Reader, w io.Writer, filter func(*File) bool) error`: Processes the files inside the `zip.Reader` and efficiently streams the exact original bytes from `stream` into `w` if they evaluate to true using the `filter` function.

**Example:**

This example demonstrates filtering an existing zip file, retaining only `.txt` files without suffering the heavy cost of decompression and re-compression.

```go
package main

import (
	"io"
	"log"
	"os"
	"strings"

	"github.com/abyii/zip-xxh3"
)

func main() {
	// Open an existing zip file
	f, err := os.Open("large_archive.zip")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	stat, _ := f.Stat()
	
	// Parse the central directory
	zr, err := zip.NewReader(f, stat.Size())
	if err != nil {
		log.Fatal(err)
	}

	out, err := os.Create("filtered_archive.zip")
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()

	// Reset stream to beginning since NewReader parses from the tail
	f.Seek(0, io.SeekStart)

	// Filter files efficiently (e.g., keep only .txt files)
	err = zip.FilterZipStream(zr, f, out, func(file *zip.File) bool {
		return strings.HasSuffix(file.Name, ".txt")
	})
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Created filtered_archive.zip")
}
```

### Raw Copying and Re-Keying (Streaming Re-Keying)

This package supports raw copying and re-keying of "chopped" zip file parts (individual objects containing a local file header + compressed data + optional data descriptor) with $O(1)$ constant memory overhead under backpressure. This allows you to decrypt ZipCrypto-encrypted, compressed parts on-the-fly and re-encrypt/write them into a single consolidated ZIP archive under a common password without suffering the heavy CPU and memory cost of full decompression and re-compression.

You can also dynamically override metadata fields (such as file names, comments, and modification times) or inject custom `XXH3` checksums via a callback.

#### Functions

*   `CopyRawPart(src io.Reader, oldPassword, newPassword string, modifyHeader func(*OverridableFileHeader)) error`: Reads a raw file part from `src`, decrypts it using `oldPassword` (if encrypted with ZipCrypto), re-encrypts it using `newPassword` (if provided), and streams it directly to the writer. It uses the `modifyHeader` callback to allow safe metadata overrides before writing.
*   `CreateRaw(fh *FileHeader) (io.Writer, error)`: Low-level API that registers a file entry from pre-compressed metadata and returns a writer to which raw/compressed payload bytes can be written (encrypting them on-the-fly if a password is set on the header).
*   `ReadLocalFileHeader(r io.Reader) (*FileHeader, error)`: Decodes a Local File Header directly from a stream, returning a partially populated `FileHeader` with the metadata (name, flags, method, extra) of the part.
*   `NewZipCryptoDecryptReader(r io.Reader, password []byte) io.Reader`: Returns a stateful streaming decryptor that consumes standard ZipCrypto encrypted bytes from `r` and decrypts them on the fly.

#### Overridable File Header Struct

The `OverridableFileHeader` callback restricts modifications to safe metadata properties only, protecting critical data-dependent properties (like compression method and data sizes) from corruption:

```go
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
```

#### Example: Consolidating and Re-Keying Raw File Parts

This example demonstrates reading individual raw file parts, overriding their filenames and comments, injecting original `XXH3` hashes, and merging/re-keying them into a single output ZIP archive:

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
	// Suppose we have raw part streams from different files/passwords
	var part1 io.Reader // local file header + data + descriptor of file1 (encrypted with "pass1")
	var part2 io.Reader // local file header + data + descriptor of file2 (encrypted with "pass2")

	// Create the output zip file
	out, err := os.Create("merged_and_rekeyed.zip")
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()

	zw := zip.NewWriter(out)

	// Rekey part1 (from "pass1" -> "commonSecret") and override filename and XXH3
	err = zw.CopyRawPart(part1, "pass1", "commonSecret", func(override *zip.OverridableFileHeader) {
		override.Name = "renamed_file1.txt"
		override.Comment = "Re-keyed from source 1"
		override.XXH3 = 0xabcdef1234567890 // Restore original XXH3 hash from metadata DB
	})
	if err != nil {
		log.Fatal(err)
	}

	// Rekey part2 (from "pass2" -> "commonSecret") and override filename
	err = zw.CopyRawPart(part2, "pass2", "commonSecret", func(override *zip.OverridableFileHeader) {
		override.Name = "renamed_file2.txt"
		override.Comment = "Re-keyed from source 2"
	})
	if err != nil {
		log.Fatal(err)
	}

	// Close the writer to write the Central Directory at the tail
	if err := zw.Close(); err != nil {
		log.Fatal(err)
	}

	log.Println("Successfully consolidated and re-keyed raw file parts.")
}
```

