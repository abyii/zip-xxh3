## zip-xxh3

`yeka/zip` is a fork of Go's `archive/zip` that adds support for Standard Zip Encryption.
This is a fork of `yeka/zip` that adds zlib Compression & Decompression methods (using `4kills/go-zlib`) for optimised zipping, and adds support for XXH3 64 bit checksum (using zeebo/xxh3).

> XXhash3 is a extremely fast, non-cryptographic hash function. It is designed to be used in high-performance applications where speed is important. It has excellent collision distribution. XXhash3 is so fast that it is often bottlenecked by how fast you can read bytes off the disk and not the algorithm itself.

> from 4kills/go-zlib:
> This ultra fast Go zlib library wraps the original zlib library written in C by Jean-loup Gailly and Mark Adler using cgo.

For the library to work, you need cgo, zlib (which is used by this library under the hood), and pkg-config (to link zlib).
You must build your application with the `zlib_c` build tag to enable the CGo-based implementation.

```bash
go build -tags=zlib_c
```

## Example Usage

### Writing a zip file:

```go
package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/abyii/zip-xxh3"
)

func main() {
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)

	content := []byte("This is the content of the file, compressed with zlib-ng!")

	f, err := w.CreateHeader(&zip.FileHeader{
		Name:   "my-file.txt",
		Method: zip.Zlib, // Use Zlib compression
	})
	if err != nil {
		log.Fatal(err)
	}

	_, err = f.Write(content)
	if err != nil {
		log.Fatal(err)
	}

	if err := w.Close(); err != nil {
		log.Fatal(err)
	}

	// You can now write buf to a file, e.g., ioutil.WriteFile("archive.zip", buf.Bytes(), 0644)
	fmt.Println("Zip file created successfully.")
}
```

### Reading and Verifying a Zip File

```go
package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/abyii/zip-xxh3"
)

func main() {
	// Assume 'zipData' is a []byte containing the zip archive from the previous example
	var zipData []byte // In a real scenario, you would read this from a file

	r, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		log.Fatal(err)
	}

	for _, f := range r.File {
		fmt.Printf("File: %s\n", f.Name)

		// Verify the xxh3 checksum if it exists
		if f.XXH3 != 0 {
			if err := f.VerifyXXH3(); err != nil {
				log.Fatalf("XXH3 checksum for %s failed: %v", f.Name, err)
			}
			fmt.Printf("  - XXH3 checksum verified!\n")
		}

		rc, err := f.Open()
		if err != nil {
			log.Fatal(err)
		}

		content, err := ioutil.ReadAll(rc)
		if err != nil {
			log.Fatal(err)
		}
		rc.Close()

		fmt.Printf("  - Content: %s\n", content)
	}
}
```

### Encrypting a zip file

```go
// ...
f, err := w.CreateHeader(&zip.FileHeader{
    Name: "my-super-secret-file.txt",
    Method: zip.Deflate,
    Encryption: zip.AES256Encryption,
})
// ...
```

### Decrypting a zip file

```go
// ...
f.SetPassword("my-super-secret-password")
r, err := f.Open()
// ...
```

for more info, pls refer to the original `yeka/zip` README.md