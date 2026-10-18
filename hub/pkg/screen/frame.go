package screen

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"unicode/utf8"
)

// Operator and watcher frames are parsed once, strictly, and the hub forwards
// only what it re-encodes from that parse - never the bytes it was sent.
//
// Why: Go's encoding/json matches keys case-insensitively and lets the last
// duplicate win, while the helper's serde is case-sensitive, takes the first
// tag it sees and ignores unknown keys. A frame such as
// {"type":"input","ev":"text","Type":"ack"} would be an ack to a lenient Go
// parse and an input to the helper. So every key must be one of the exact,
// lower-case members its type allows, no key may repeat, and the agent only
// ever sees the canonical encoding below (lower-case keys, known fields only,
// in the helper's field order). The audit reads the same parse that is
// forwarded.

var errFrame = errors.New("malformed frame")

// errForbiddenType is a well-formed object whose type the sender may not send.
var errForbiddenType = errors.New("forbidden frame type")

// opFrame is one parsed operator/watcher frame.
type opFrame struct {
	Type  string
	Input *wireInput // opInput
	// opAck
	AckMonitor, AckFrame int64
	// opSetMonitor
	Monitor int64
	// opQuality: nil when absent
	FPS, JPEGQ *float64
}

// wireInput is an input frame as the agent receives it. Field order and
// names are the helper's RawInput (REMOTE_SCREEN.md 4.2).
type wireInput struct {
	Type    string       `json:"type"`
	Ev      string       `json:"ev"`
	X       *int64       `json:"x,omitempty"`
	Y       *int64       `json:"y,omitempty"`
	Buttons *wireButtons `json:"buttons,omitempty"`
	Monitor *int64       `json:"monitor,omitempty"`
	DX      *int64       `json:"dx,omitempty"`
	DY      *int64       `json:"dy,omitempty"`
	Code    *int64       `json:"code,omitempty"`
	Down    *bool        `json:"down,omitempty"`
	Ext     *bool        `json:"ext,omitempty"`
	Ch      *string      `json:"ch,omitempty"`
}

type wireButtons struct {
	L bool `json:"l"`
	R bool `json:"r"`
	M bool `json:"m"`
}

// inputKeys is the exact member set of each input event kind.
var inputKeys = map[string]map[string]bool{
	"mouse": {"type": true, "ev": true, "x": true, "y": true, "buttons": true, "monitor": true},
	"wheel": {"type": true, "ev": true, "dx": true, "dy": true, "monitor": true},
	"key":   {"type": true, "ev": true, "code": true, "down": true, "ext": true},
	"text":  {"type": true, "ev": true, "ch": true},
	"sas":   {"type": true, "ev": true},
}

var frameKeys = map[string]map[string]bool{
	opAck:        {"type": true, "monitor": true, "frame": true},
	opSetMonitor: {"type": true, "monitor": true},
	opQuality:    {"type": true, "fps": true, "jpeg_q": true},
	opClose:      {"type": true},
}

// strictObject decodes one JSON object into its members, refusing anything
// but a single object, invalid UTF-8 and a repeated key (compared after
// unescaping, as serde compares them).
func strictObject(data []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(data) {
		return nil, errFrame
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return nil, errFrame
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errFrame
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, errFrame
		}
		k, ok := tok.(string)
		if !ok {
			return nil, errFrame
		}
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("%w: duplicate key", errFrame)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, errFrame
		}
		out[k] = v
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, errFrame
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("%w: trailing data", errFrame)
	}
	return out, nil
}

func onlyKeys(m map[string]json.RawMessage, allowed map[string]bool) error {
	for k := range m {
		if !allowed[k] {
			return fmt.Errorf("%w: unexpected key", errFrame)
		}
	}
	return nil
}

// jsonInt reads an integer member: a plain JSON integer (no fraction, no
// exponent, no null), as serde reads an integer field.
func jsonInt(raw json.RawMessage, lo, hi int64) (int64, error) {
	n, err := strconv.ParseInt(string(bytes.TrimSpace(raw)), 10, 64)
	if err != nil || n < lo || n > hi {
		return 0, errFrame
	}
	return n, nil
}

func optInt(m map[string]json.RawMessage, k string) (*int64, error) {
	raw, ok := m[k]
	if !ok {
		return nil, nil
	}
	n, err := jsonInt(raw, math.MinInt64, math.MaxInt64)
	if err != nil {
		return nil, err
	}
	return &n, nil
}

func optBool(m map[string]json.RawMessage, k string) (*bool, error) {
	raw, ok := m[k]
	if !ok {
		return nil, nil
	}
	switch string(bytes.TrimSpace(raw)) {
	case "true":
		b := true
		return &b, nil
	case "false":
		b := false
		return &b, nil
	}
	return nil, errFrame
}

func jsonString(raw json.RawMessage) (string, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '"' {
		return "", errFrame
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", errFrame
	}
	return s, nil
}

func jsonNumber(raw json.RawMessage) (float64, error) {
	f, err := strconv.ParseFloat(string(bytes.TrimSpace(raw)), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, errFrame
	}
	return f, nil
}

// parseOperatorFrame strictly parses one operator or watcher text frame.
// errFrame: malformed (bad JSON, unknown or repeated key, wrong value type);
// errForbiddenType: well formed, but a type operators never send (including
// the hub's own pause/resume).
func parseOperatorFrame(data []byte) (*opFrame, error) {
	m, err := strictObject(data)
	if err != nil {
		return nil, err
	}
	rawType, ok := m["type"]
	if !ok {
		return nil, errFrame
	}
	typ, err := jsonString(rawType)
	if err != nil {
		return nil, err
	}
	f := &opFrame{Type: typ}
	switch typ {
	case opInput:
		in, err := parseInput(m)
		if err != nil {
			return nil, err
		}
		f.Input = in
		return f, nil
	case opAck, opSetMonitor, opQuality, opClose:
	default:
		return nil, errForbiddenType
	}
	if err := onlyKeys(m, frameKeys[typ]); err != nil {
		return nil, err
	}
	switch typ {
	case opAck:
		raw, ok := m["frame"]
		if !ok {
			return nil, errFrame
		}
		if f.AckFrame, err = jsonInt(raw, 0, math.MaxInt64); err != nil {
			return nil, err
		}
		if raw, ok := m["monitor"]; ok {
			if f.AckMonitor, err = jsonInt(raw, 0, math.MaxUint32); err != nil {
				return nil, err
			}
		}
	case opSetMonitor:
		raw, ok := m["monitor"]
		if !ok {
			return nil, errFrame
		}
		if f.Monitor, err = jsonInt(raw, 0, math.MaxUint32); err != nil {
			return nil, err
		}
	case opQuality:
		for k, dst := range map[string]**float64{"fps": &f.FPS, "jpeg_q": &f.JPEGQ} {
			if raw, ok := m[k]; ok {
				v, err := jsonNumber(raw)
				if err != nil {
					return nil, err
				}
				*dst = &v
			}
		}
	}
	return f, nil
}

func parseInput(m map[string]json.RawMessage) (*wireInput, error) {
	rawEv, ok := m["ev"]
	if !ok {
		return nil, errFrame
	}
	ev, err := jsonString(rawEv)
	if err != nil {
		return nil, err
	}
	allowed, ok := inputKeys[ev]
	if !ok {
		return nil, errFrame
	}
	if err := onlyKeys(m, allowed); err != nil {
		return nil, err
	}
	in := &wireInput{Type: opInput, Ev: ev}
	for k, dst := range map[string]**int64{"x": &in.X, "y": &in.Y, "monitor": &in.Monitor, "dx": &in.DX, "dy": &in.DY, "code": &in.Code} {
		if *dst, err = optInt(m, k); err != nil {
			return nil, err
		}
	}
	for k, dst := range map[string]**bool{"down": &in.Down, "ext": &in.Ext} {
		if *dst, err = optBool(m, k); err != nil {
			return nil, err
		}
	}
	if raw, ok := m["ch"]; ok {
		s, err := jsonString(raw)
		if err != nil {
			return nil, err
		}
		in.Ch = &s
	}
	if raw, ok := m["buttons"]; ok {
		bm, err := strictObject(raw)
		if err != nil {
			return nil, err
		}
		if err := onlyKeys(bm, map[string]bool{"l": true, "r": true, "m": true}); err != nil {
			return nil, err
		}
		var b wireButtons
		for k, dst := range map[string]*bool{"l": &b.L, "r": &b.R, "m": &b.M} {
			v, err := optBool(bm, k)
			if err != nil {
				return nil, err
			}
			if v != nil {
				*dst = *v
			}
		}
		in.Buttons = &b
	}
	return in, nil
}

// encode is the canonical form of a parsed frame: the only bytes the hub
// sends on to the agent.
func (f *opFrame) encode() []byte {
	var v interface{}
	switch f.Type {
	case opInput:
		v = f.Input
	case opAck:
		v = struct {
			Type    string `json:"type"`
			Monitor int64  `json:"monitor"`
			Frame   int64  `json:"frame"`
		}{opAck, f.AckMonitor, f.AckFrame}
	case opSetMonitor:
		v = struct {
			Type    string `json:"type"`
			Monitor int64  `json:"monitor"`
		}{opSetMonitor, f.Monitor}
	case opQuality:
		v = struct {
			Type  string `json:"type"`
			FPS   int    `json:"fps"`
			JPEGQ int    `json:"jpeg_q"`
		}{opQuality, clampInt(f.FPS, 1, MaxFPS, MaxFPS), clampInt(f.JPEGQ, MinJPEGQuality, MaxJPEGQuality, DefaultJPEGQuality)}
	case opClose:
		v = struct {
			Type string `json:"type"`
		}{opClose}
	default:
		return nil
	}
	out, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return out
}
