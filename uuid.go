// Package uuid provides a simple implementation of Universally Unique Identifiers (UUIDs).
// It is based on the specification described in RFC 4122.
package uuid

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
)

// defaultGenerator is singleton of generator, it's used as default generator.
var (
	defaultGenerator Generator
	defaultInitiator sync.Once
)

// IsV4 returns true if the given UUID is a valid UUID v4.
func IsV4(uid UUID) bool {
	if uid == Nil {
		return true
	}

	// check the version bits (0100 in binary, or 0x40 in hex).
	if uid[6]>>4 != 4 {
		return false
	}

	// check the variant bits (1010 in binary, or 0x80 in hex).
	if uid[8]>>6 != 2 {
		return false
	}
	return true
}

func init() {
	defaultInitiator.Do(func() { defaultGenerator = NewV4Generator(SecureReader) })
}

// Generator knows how to generate UUID.
type Generator interface {
	// GenUUID generates a new UUID.
	GenUUID() (UUID, error)
}

// Nil is nil value of UUID.
var Nil UUID

// UUID is a 128 bit (16 byte) Universal Unique Identifier
// as defined in RFC 4122.
type UUID [16]byte

// String returns uuid as a formatted string.
func (id UUID) String() string {
	var buf [36]byte
	encodeHex(buf[:], id)
	return string(buf[:])
}

func (id UUID) MarshalText() (text []byte, err error) {
	text = make([]byte, 36)
	encodeHex(text, id)
	return
}

func (id *UUID) UnmarshalText(text []byte) error {
	uid, err := Parse(string(text))
	if err != nil {
		return err
	}
	*id = uid
	return nil
}

// encodeHex encodes uuid to hexadecimal string.
func encodeHex(dst []byte, id UUID) {
	hex.Encode(dst, id[:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], id[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], id[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], id[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:], id[10:])
}

// New generates a new UUID v4 with random generator rand.Reader.
func New() (UUID, error) { return defaultGenerator.GenUUID() }

// fillUUID fills uuid with random byte from the given reader.
func fillUUID(reader io.Reader) (UUID, error) {
	var uid UUID
	_, err := io.ReadFull(reader, uid[:])
	if err != nil {
		return Nil, err
	}

	return uid, nil
}

// ReaderFactory is a type for reader factory to create random reader.
type ReaderFactory func() io.Reader

// SecureReader is ReaderFactory that's returns rand.Reader for each call.
func SecureReader() io.Reader { return rand.Reader }

// StaticUUID is an uuid that produce by StaticReader.
const StaticUUID = "00010203-0405-4607-8809-0a0b0c0d0e0f"

// StaticReader returns a reader that always returns the same value when Read
// is called. The generator with given this reader always produce StaticUUID.
// This is useful only for testing.
func StaticReader() io.Reader {
	return bytes.NewReader([]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	})
}

type eofReader struct{}

func (*eofReader) Read(_ []byte) (n int, err error) { return 0, io.EOF }

// ErrorsReader returns a reader that always returns io.EOF when Read is called.
// This is useful only for testing.
func ErrorsReader() io.Reader { return &eofReader{} }

// V4Generator generates version 4 UUIDs using a random number generator factory.
type V4Generator struct {
	factory ReaderFactory
}

// NewV4Generator creates a new instance of V4Generator with the given
// random number generator factory.
func NewV4Generator(factory ReaderFactory) *V4Generator {
	return &V4Generator{
		factory: factory,
	}
}

// GenUUID generates a new UUID by filling it with random data using the
// factory and setting the version and variant bits to satisfy the UUID v4
// standard.
func (v *V4Generator) GenUUID() (UUID, error) {
	uid, err := fillUUID(v.factory())
	if err != nil {
		return Nil, err
	}

	uid[6] = (uid[6] & 0x0f) | 0x40 // Version 4
	uid[8] = (uid[8] & 0x3f) | 0x80 // Variant is 10
	return uid, err
}

// hexValues returns the value of a byte as a hexadecimal digit or 0xff.
var hexValues = [256]byte{
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
}

// hexStartedIndex is the index of the first hex digit in each byte of a UUID.
// To get one hex digit, use the first index and add 1.
// aabbccdd-eeff-gghh-iijj-kkllmmnnoopp
var hexStartedIndex = [16]int{
	0, 2, 4, 6, // aa, bb, cc, dd
	9, 11, // ee, ff
	14, 16, // gg, hh
	19, 21, // ii, jj
	24, 26, 28, 30, 32, 34, // kk, ll, mm, nn, oo, pp
}

// Parse parses a UUID from a string.
// The string may be in any of the following formats:
//
//	xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
func Parse(s string) (UUID, error) {
	if len(s) != 36 {
		return Nil, fmt.Errorf("uuid: incorrect UUID length: %s", s)
	}

	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return Nil, fmt.Errorf("uuid: expected dashes at positions 8, 13, 18, and 23")
	}

	return parse(s, hexStartedIndex)
}

// parse do the actual parsing of a UUID from a string.
func parse(s string, indexes [16]int) (UUID, error) {
	var uid UUID
	for i, start := range indexes {
		// start+1 is the index of the second hex character.
		// for hex, it's take 2 bytes for 1 hex character.
		v, ok := hexToByte(s[start], s[start+1])
		if !ok {
			return Nil, fmt.Errorf("uuid: invalid UUID string: %s", s)
		}

		uid[i] = v
	}

	return uid, nil
}

// hexToByte converts hex characters x1 and x2 into one byte.
func hexToByte(x1, x2 byte) (byte, bool) {
	b1 := hexValues[x1]
	b2 := hexValues[x2]
	return (b1 << 4) | b2, b1 != 0xff && b2 != 0xff
}
