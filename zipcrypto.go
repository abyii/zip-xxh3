package zip

import (
	"bytes"
	"crypto/rand"
	"errors"
	"hash/crc32"
	"io"
)

// zipCryptoHeaderLen is the length of the PKWARE ZipCrypto encryption header
// that prefixes every encrypted payload (APPNOTE 6.1.3).
const zipCryptoHeaderLen = 12

// zipCryptoChunkSize bounds the scratch buffer used to encrypt writes.
const zipCryptoChunkSize = 32 * 1024

type ZipCrypto struct {
	password []byte
	Keys     [3]uint32
}

func NewZipCrypto(passphrase []byte) *ZipCrypto {
	z := &ZipCrypto{}
	z.password = passphrase
	z.init()
	return z
}

func (z *ZipCrypto) init() {
	z.Keys[0] = 0x12345678
	z.Keys[1] = 0x23456789
	z.Keys[2] = 0x34567890

	for _, b := range z.password {
		z.updateKeys(b)
	}
}

func (z *ZipCrypto) updateKeys(byteValue byte) {
	z.Keys[0] = crc32update(z.Keys[0], byteValue)
	z.Keys[1] += z.Keys[0] & 0xff
	z.Keys[1] = z.Keys[1]*134775813 + 1
	z.Keys[2] = crc32update(z.Keys[2], (byte)(z.Keys[1]>>24))
}

func (z *ZipCrypto) magicByte() byte {
	var t uint32 = z.Keys[2] | 2
	return byte((t * (t ^ 1)) >> 8)
}

// encryptTo encrypts src into dst, which must be at least len(src) bytes.
// dst and src may overlap entirely.
func (z *ZipCrypto) encryptTo(dst, src []byte) {
	for i, v := range src {
		dst[i] = v ^ z.magicByte()
		z.updateKeys(v)
	}
}

// decryptTo decrypts src into dst, which must be at least len(src) bytes.
// dst and src may overlap entirely.
func (z *ZipCrypto) decryptTo(dst, src []byte) {
	for i, c := range src {
		v := c ^ z.magicByte()
		z.updateKeys(v)
		dst[i] = v
	}
}

func (z *ZipCrypto) Encrypt(data []byte) []byte {
	chiper := make([]byte, len(data))
	z.encryptTo(chiper, data)
	return chiper
}

func (z *ZipCrypto) Decrypt(chiper []byte) []byte {
	plain := make([]byte, len(chiper))
	z.decryptTo(plain, chiper)
	return plain
}

func crc32update(pCrc32 uint32, bval byte) uint32 {
	return crc32.IEEETable[(pCrc32^uint32(bval))&0xff] ^ (pCrc32 >> 8)
}

// zipCryptoCheckBytes returns the two password check bytes stored at the end
// of the ZipCrypto encryption header (APPNOTE 6.1.6). When bit 3 (data
// descriptor) is set the CRC is not known up front, so the high word of the
// DOS modification time is used instead of the high word of the CRC-32.
// Readers verify only the last byte.
func zipCryptoCheckBytes(flags, modTime uint16, crc uint32) (lo, hi byte) {
	if flags&0x8 != 0 {
		return byte(modTime), byte(modTime >> 8)
	}
	return byte(crc >> 16), byte(crc >> 24)
}

// ZipCryptoDecryptor decrypts the whole ZipCrypto payload held in r and
// returns a reader over the plaintext that follows the 12-byte encryption
// header. It buffers the entire payload in memory and does not verify the
// password check byte; prefer NewZipCryptoDecryptReader.
func ZipCryptoDecryptor(r *io.SectionReader, password []byte) (*io.SectionReader, error) {
	size := r.Size()
	if size < zipCryptoHeaderLen {
		return nil, io.ErrUnexpectedEOF
	}
	b := make([]byte, size)
	if _, err := r.ReadAt(b, 0); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	NewZipCrypto(password).decryptTo(b, b)
	return io.NewSectionReader(bytes.NewReader(b), zipCryptoHeaderLen, size-zipCryptoHeaderLen), nil
}

type zipCryptoWriter struct {
	w     io.Writer
	z     *ZipCrypto
	first bool
	fw    *fileWriter
	buf   []byte // scratch space for ciphertext; never aliases caller data
	err   error  // sticky: the key stream cannot be rewound after a failed write
}

func (z *zipCryptoWriter) writeHeader() error {
	if !z.first {
		return z.err
	}
	z.first = false

	// PKWARE ZipCrypto requires a 12-byte encryption header at the start of each payload
	// (APPNOTE 6.1.3). The first 10 bytes must be unpredictable, otherwise the known
	// plaintext weakens the cipher; bytes 10 and 11 are the password check bytes that
	// readers compare after decrypting the header.
	var header [zipCryptoHeaderLen]byte
	if _, z.err = rand.Read(header[:zipCryptoHeaderLen-2]); z.err != nil {
		return z.err
	}

	var flags uint16
	var modTime uint16
	var crc32Val uint32
	if z.fw != nil {
		flags = z.fw.Flags
		modTime = z.fw.ModifiedTime
		crc32Val = z.fw.CRC32
	}
	header[10], header[11] = zipCryptoCheckBytes(flags, modTime, crc32Val)

	z.z.encryptTo(header[:], header[:])
	_, z.err = z.w.Write(header[:])
	return z.err
}

func (z *zipCryptoWriter) Write(p []byte) (n int, err error) {
	if err := z.writeHeader(); err != nil {
		return 0, err
	}
	for len(p) > 0 {
		chunk := min(len(p), zipCryptoChunkSize)
		if cap(z.buf) < chunk {
			z.buf = make([]byte, chunk)
		}
		out := z.buf[:chunk]
		z.z.encryptTo(out, p[:chunk])
		nn, err := z.w.Write(out)
		n += nn
		if err != nil {
			z.err = err
			return n, err
		}
		p = p[chunk:]
	}
	return n, nil
}

func (z *zipCryptoWriter) Close() error {
	return z.writeHeader()
}

func ZipCryptoEncryptor(i io.Writer, pass passwordFn, fw *fileWriter) (io.Writer, error) {
	z := NewZipCrypto(pass())
	zc := &zipCryptoWriter{w: i, z: z, first: true, fw: fw}
	return zc, nil
}

type zipCryptoDecryptReader struct {
	r          io.Reader
	z          *ZipCrypto
	check      byte
	verify     bool // compare the header check byte against check
	headerDone bool
	err        error // sticky header error
}

func newZipCryptoDecryptReader(r io.Reader, password []byte, check byte, verify bool) *zipCryptoDecryptReader {
	return &zipCryptoDecryptReader{
		r:      r,
		z:      NewZipCrypto(password),
		check:  check,
		verify: verify,
	}
}

// readHeader consumes and decrypts the 12-byte encryption header and verifies
// the password check byte. It runs once; its error is sticky.
func (zd *zipCryptoDecryptReader) readHeader() error {
	if zd.headerDone {
		return zd.err
	}
	zd.headerDone = true
	var header [zipCryptoHeaderLen]byte
	if _, err := io.ReadFull(zd.r, header[:]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		zd.err = err
		return err
	}
	zd.z.decryptTo(header[:], header[:])
	if zd.verify && header[zipCryptoHeaderLen-1] != zd.check {
		zd.err = ErrPassword
	}
	return zd.err
}

func (zd *zipCryptoDecryptReader) Read(p []byte) (n int, err error) {
	if err := zd.readHeader(); err != nil {
		return 0, err
	}
	n, err = zd.r.Read(p)
	zd.z.decryptTo(p[:n], p[:n])
	return n, err
}

var errNilFileHeader = errors.New("zip: NewVerifiedZipCryptoDecryptReader requires a non-nil FileHeader")

// NewZipCryptoDecryptReader returns a streaming decryptor for a ZipCrypto
// payload (12-byte encryption header followed by the encrypted data) read
// from r. The header is consumed on the first Read but the password is NOT
// verified; prefer NewVerifiedZipCryptoDecryptReader.
func NewZipCryptoDecryptReader(r io.Reader, password []byte) io.Reader {
	return newZipCryptoDecryptReader(r, password, 0, false)
}

// NewVerifiedZipCryptoDecryptReader is like NewZipCryptoDecryptReader but
// verifies the password check byte. fh supplies the Flags, ModifiedTime and
// CRC32 of the entry, as returned by ReadLocalFileHeader, which determine the
// expected check byte (APPNOTE 6.1.6).
//
// The header is consumed and verified on the first Read, which returns
// ErrPassword if the check byte does not match. The check byte only rejects
// 255/256 of wrong passwords; callers must still verify the CRC-32 of the
// decompressed output.
func NewVerifiedZipCryptoDecryptReader(r io.Reader, password []byte, fh *FileHeader) io.Reader {
	if fh == nil {
		return &zipCryptoDecryptReader{headerDone: true, err: errNilFileHeader}
	}
	_, check := zipCryptoCheckBytes(fh.Flags, fh.ModifiedTime, fh.CRC32)
	return newZipCryptoDecryptReader(r, password, check, true)
}
