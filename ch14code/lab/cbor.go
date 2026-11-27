// cbor.go
// A deliberately minimal CBOR codec (RFC 8949) for the passkey lab: unsigned and negative
// integers, byte strings, text strings, arrays and maps. Enough for attestation objects and
// COSE keys; nothing else (no floats, tags, indefinite lengths). Production code uses a library.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

const maxDepth = 16

// cborDecode returns the first data item in b and the bytes that follow it.
// Integers decode as int64, byte strings as []byte, text as string,
// arrays as []any and maps as map[any]any.
func cborDecode(b []byte) (any, []byte, error) { return decode(b, 0) }

func head(b []byte) (major byte, arg uint64, rest []byte, err error) {
	if len(b) == 0 {
		return 0, 0, nil, errors.New("cbor: truncated")
	}
	major, info := b[0]>>5, b[0]&0x1f
	b = b[1:]
	switch {
	case info < 24:
		return major, uint64(info), b, nil
	case info <= 27:
		n := 1 << (info - 24) // 1, 2, 4 or 8 bytes
		if len(b) < n {
			return 0, 0, nil, errors.New("cbor: truncated argument")
		}
		var v uint64
		for _, c := range b[:n] {
			v = v<<8 | uint64(c)
		}
		return major, v, b[n:], nil
	}
	return 0, 0, nil, fmt.Errorf("cbor: unsupported additional info %d", info)
}

func decode(b []byte, depth int) (any, []byte, error) {
	if depth > maxDepth {
		return nil, nil, errors.New("cbor: nested too deeply")
	}
	major, arg, rest, err := head(b)
	if err != nil {
		return nil, nil, err
	}
	switch major {
	case 0: // unsigned integer
		if arg > 1<<63-1 {
			return nil, nil, errors.New("cbor: integer overflow")
		}
		return int64(arg), rest, nil
	case 1: // negative integer: -1 - arg
		if arg > 1<<63-1 {
			return nil, nil, errors.New("cbor: integer overflow")
		}
		return -1 - int64(arg), rest, nil
	case 2, 3: // byte string, text string
		if arg > uint64(len(rest)) {
			return nil, nil, errors.New("cbor: truncated string")
		}
		s := append([]byte{}, rest[:arg]...)
		if major == 3 {
			return string(s), rest[arg:], nil
		}
		return s, rest[arg:], nil
	case 4: // array
		if arg > uint64(len(rest)) { // each item takes at least one byte
			return nil, nil, errors.New("cbor: truncated array")
		}
		out := make([]any, 0, arg)
		for i := uint64(0); i < arg; i++ {
			var v any
			if v, rest, err = decode(rest, depth+1); err != nil {
				return nil, nil, err
			}
			out = append(out, v)
		}
		return out, rest, nil
	case 5: // map
		if arg > uint64(len(rest))/2 {
			return nil, nil, errors.New("cbor: truncated map")
		}
		out := make(map[any]any, arg)
		for i := uint64(0); i < arg; i++ {
			var k, v any
			if k, rest, err = decode(rest, depth+1); err != nil {
				return nil, nil, err
			}
			switch k.(type) {
			case int64, string:
			default:
				return nil, nil, errors.New("cbor: map key must be integer or text")
			}
			if _, dup := out[k]; dup {
				return nil, nil, fmt.Errorf("cbor: duplicate map key %v", k)
			}
			if v, rest, err = decode(rest, depth+1); err != nil {
				return nil, nil, err
			}
			out[k] = v
		}
		return out, rest, nil
	}
	return nil, nil, fmt.Errorf("cbor: unsupported major type %d", major)
}

// cborEncode encodes v using CTAP2 canonical form: shortest argument encodings and
// map keys sorted by their encoded bytes (shorter first, then bytewise).
// It panics on a type it does not support: the lab only encodes values it builds itself.
func cborEncode(v any) []byte {
	var buf bytes.Buffer
	encode(&buf, v)
	return buf.Bytes()
}

func putHead(buf *bytes.Buffer, major byte, arg uint64) {
	m := major << 5
	switch {
	case arg < 24:
		buf.WriteByte(m | byte(arg))
	case arg <= 0xff:
		buf.Write([]byte{m | 24, byte(arg)})
	case arg <= 0xffff:
		buf.WriteByte(m | 25)
		buf.Write(binary.BigEndian.AppendUint16(nil, uint16(arg)))
	case arg <= 0xffffffff:
		buf.WriteByte(m | 26)
		buf.Write(binary.BigEndian.AppendUint32(nil, uint32(arg)))
	default:
		buf.WriteByte(m | 27)
		buf.Write(binary.BigEndian.AppendUint64(nil, arg))
	}
}

func encode(buf *bytes.Buffer, v any) {
	switch x := v.(type) {
	case int:
		encodeInt(buf, int64(x))
	case int64:
		encodeInt(buf, x)
	case []byte:
		putHead(buf, 2, uint64(len(x)))
		buf.Write(x)
	case string:
		putHead(buf, 3, uint64(len(x)))
		buf.WriteString(x)
	case []any:
		putHead(buf, 4, uint64(len(x)))
		for _, e := range x {
			encode(buf, e)
		}
	case map[any]any:
		type kv struct{ k, v []byte }
		pairs := make([]kv, 0, len(x))
		for k, e := range x {
			pairs = append(pairs, kv{cborEncode(k), cborEncode(e)})
		}
		sort.Slice(pairs, func(i, j int) bool {
			a, b := pairs[i].k, pairs[j].k
			if len(a) != len(b) {
				return len(a) < len(b)
			}
			return bytes.Compare(a, b) < 0
		})
		putHead(buf, 5, uint64(len(pairs)))
		for _, p := range pairs {
			buf.Write(p.k)
			buf.Write(p.v)
		}
	default:
		panic(fmt.Sprintf("cbor: cannot encode %T", v))
	}
}

func encodeInt(buf *bytes.Buffer, n int64) {
	if n >= 0 {
		putHead(buf, 0, uint64(n))
	} else {
		putHead(buf, 1, uint64(-1-n))
	}
}
