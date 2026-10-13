// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package zip

import (
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/klauspost/compress/flate"
)

// A Compressor returns a compressing writer, writing to the
// provided writer. On Close, any pending data should be flushed.
type Compressor func(io.Writer) (io.WriteCloser, error)

// Decompressor is a function that wraps a Reader with a decompressing Reader.
// The decompressed ReadCloser is returned to callers who open files from
// within the archive.  These callers are responsible for closing this reader
// when they're finished reading.
type Decompressor func(io.Reader) io.ReadCloser

// flateWriterPools holds one pool per compression level: flate.Writer.Reset
// keeps the level the writer was created with, so writers must not be shared
// across levels.
var flateWriterPools [flate.BestCompression - flate.HuffmanOnly + 1]sync.Pool

func newFlateWriter(w io.Writer, level int) (io.WriteCloser, error) {
	if level < flate.HuffmanOnly || level > flate.BestCompression {
		return nil, fmt.Errorf("zip: invalid compression level %d", level)
	}
	pool := &flateWriterPools[level-flate.HuffmanOnly]
	fw, ok := pool.Get().(*flate.Writer)
	if ok {
		fw.Reset(w)
	} else {
		var err error
		if fw, err = flate.NewWriter(w, level); err != nil {
			return nil, err
		}
	}
	return &pooledFlateWriter{fw: fw, pool: pool}, nil
}

type pooledFlateWriter struct {
	mu   sync.Mutex // guards Close and Write
	fw   *flate.Writer
	pool *sync.Pool
}

func (w *pooledFlateWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.fw == nil {
		return 0, errors.New("Write after Close")
	}
	return w.fw.Write(p)
}

func (w *pooledFlateWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	var err error
	if w.fw != nil {
		err = w.fw.Close()
		w.pool.Put(w.fw)
		w.fw = nil
	}
	return err
}

var flateReaderPool sync.Pool

func newFlateReader(r io.Reader) io.ReadCloser {
	fr, ok := flateReaderPool.Get().(io.ReadCloser)
	if ok {
		fr.(flate.Resetter).Reset(r, nil)
	} else {
		fr = flate.NewReader(r)
	}
	return &pooledFlateReader{fr: fr}
}

type pooledFlateReader struct {
	mu sync.Mutex // guards Close and Read
	fr io.ReadCloser
}

func (r *pooledFlateReader) Read(p []byte) (n int, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fr == nil {
		return 0, errors.New("Read after Close")
	}
	return r.fr.Read(p)
}

func (r *pooledFlateReader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var err error
	if r.fr != nil {
		err = r.fr.Close()
		flateReaderPool.Put(r.fr)
		r.fr = nil
	}
	return err
}

var (
	mu sync.RWMutex // guards compressor and decompressor maps

	compressors = map[uint16]Compressor{
		// empty map to allow for custom compressors
	}

	decompressors = map[uint16]Decompressor{
		// empty map to allow for custom decompressors
	}
)

// RegisterDecompressor allows custom decompressors for a specified method ID.
func RegisterDecompressor(method uint16, d Decompressor) {
	mu.Lock()
	defer mu.Unlock()

	if _, ok := decompressors[method]; ok {
		panic("decompressor already registered")
	}
	decompressors[method] = d
}

// RegisterCompressor registers custom compressors for a specified method ID.
// The common methods Store and Deflate are built in.
func RegisterCompressor(method uint16, comp Compressor) {
	mu.Lock()
	defer mu.Unlock()

	if _, ok := compressors[method]; ok {
		panic("compressor already registered")
	}
	compressors[method] = comp
}

func compressor(method uint16, level int) Compressor {
	mu.RLock()
	defer mu.RUnlock()
	switch method {
	case Store:
		return func(w io.Writer) (io.WriteCloser, error) { return &nopCloser{w}, nil }
	case Deflate:
		return func(w io.Writer) (io.WriteCloser, error) { return newFlateWriter(w, level) }
	default:
		return compressors[method]
	}
}

func decompressor(method uint16) Decompressor {
	mu.RLock()
	defer mu.RUnlock()
	switch method {
	case Store:
		return io.NopCloser
	case Deflate:
		return newFlateReader
	default:
		return decompressors[method]
	}
}
