// envelope.go
// Murmur envelope v1 (the outer format the relay and clients parse —
// attacker-controlled input): "MR" | version u8 (=1) | type u8 (1=message,
// 2=receipt, 3=sealed) | recipient_len u8 | recipient | header_len u16 | header
// | body_len u32 | body Parsing rules: exact lengths, no trailing bytes,
// bounded sizes, canonical encoding.
package envelope

import (
    "encoding/binary"
    "errors"
)

type Envelope struct {
    Type      uint8
    Recipient string
    Header    []byte
    Body      []byte
}

const MaxBody = 256 * 1024

var ErrFormat = errors.New("malformed envelope")

func Parse(b []byte) (*Envelope, error) {
    if len(b) < 5 || b[0] != 'M' || b[1] != 'R' || b[2] != 1 {
        return nil, ErrFormat
    }
    e := &Envelope{Type: b[3]}
    if e.Type < 1 || e.Type > 3 {
        return nil, ErrFormat
    }
    rest := b[4:]
    rl := int(rest[0])
    rest = rest[1:]
    if rl == 0 || len(rest) < rl {
        return nil, ErrFormat
    }
    e.Recipient, rest = string(rest[:rl]), rest[rl:]
    if len(rest) < 2 {
        return nil, ErrFormat
    }
    hl := int(binary.BigEndian.Uint16(rest))
    rest = rest[2:]
    if len(rest) < hl {
        return nil, ErrFormat
    }
    e.Header, rest = append([]byte(nil), rest[:hl]...), rest[hl:]
    if len(rest) < 4 {
        return nil, ErrFormat
    }
    bl := binary.BigEndian.Uint32(rest)
    rest = rest[4:]
    // exact: no trailing bytes
    if bl > MaxBody || uint64(len(rest)) != uint64(bl) {
        return nil, ErrFormat
    }
    e.Body = append([]byte(nil), rest...)
    return e, nil
}

func (e *Envelope) Encode() []byte {
    b := []byte{'M', 'R', 1, e.Type, byte(len(e.Recipient))}
    b = append(b, e.Recipient...)
    b = binary.BigEndian.AppendUint16(b, uint16(len(e.Header)))
    b = append(b, e.Header...)
    b = binary.BigEndian.AppendUint32(b, uint32(len(e.Body)))
    return append(b, e.Body...)
}

// ParseV0 is an EARLIER version of the parser, kept for the lab: it trusts
// header_len.
func ParseV0(b []byte) (*Envelope, error) {
    if len(b) < 5 || b[0] != 'M' || b[1] != 'R' {
        return nil, ErrFormat
    }
    e := &Envelope{Type: b[3]}
    rl := int(b[4])
    rest := b[5:]
    if len(rest) < rl+2 {
        return nil, ErrFormat
    }
    e.Recipient, rest = string(rest[:rl]), rest[rl:]
    hl := int(binary.BigEndian.Uint16(rest))
    // ⚠️ no check that 2+hl ≤ len(rest)
    e.Header, rest = rest[2:2+hl], rest[2+hl:]
    if len(rest) < 4 {
        return nil, ErrFormat
    }
    e.Body = rest[4:]
    return e, nil
}
