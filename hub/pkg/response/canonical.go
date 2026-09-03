package response

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// CanonicalEncoder builds a deterministic length-prefixed byte stream for cryptographic signatures.
// Domain separation labels and all variable-length fields carry 4-byte big-endian length prefixes.
// Fixed-width integers are encoded as big-endian.
// Field boundary shifting and delimiter injection are mathematically prevented.
type CanonicalEncoder struct {
	buf bytes.Buffer
}

// NewCanonicalEncoder initializes an encoder with the domain separation tag.
func NewCanonicalEncoder(domainTag string) *CanonicalEncoder {
	e := &CanonicalEncoder{}
	e.WriteString(domainTag)
	return e
}

// WriteUint32 writes a 4-byte big-endian unsigned integer.
func (e *CanonicalEncoder) WriteUint32(val uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], val)
	e.buf.Write(b[:])
}

// WriteInt64 writes an 8-byte big-endian signed integer.
func (e *CanonicalEncoder) WriteInt64(val int64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(val))
	e.buf.Write(b[:])
}

// WriteBytes writes a 4-byte big-endian length followed by the raw bytes.
func (e *CanonicalEncoder) WriteBytes(val []byte) {
	e.WriteUint32(uint32(len(val)))
	e.buf.Write(val)
}

// WriteString writes a 4-byte big-endian length followed by UTF-8 string bytes.
func (e *CanonicalEncoder) WriteString(val string) {
	e.WriteBytes([]byte(val))
}

// WriteHexNormalized writes a 4-byte big-endian length followed by lowercase hex bytes.
func (e *CanonicalEncoder) WriteHexNormalized(val string) {
	e.WriteString(strings.ToLower(strings.TrimSpace(val)))
}

// WriteStringSlice writes a 4-byte big-endian count followed by each length-prefixed string.
func (e *CanonicalEncoder) WriteStringSlice(slice []string) {
	e.WriteUint32(uint32(len(slice)))
	for _, s := range slice {
		e.WriteString(s)
	}
}

// Bytes returns the accumulated canonical byte slice.
func (e *CanonicalEncoder) Bytes() []byte {
	return e.buf.Bytes()
}
