// Package strictjson implements the bounded unambiguous protocol framing in JON-1.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

var ErrDocument = errors.New("invalid or ambiguous JSON document")

// Decode rejects ambiguous keys even in nested objects before assigning any fields.
// Case-distinct object keys are deliberately rejected because Go matches struct
// fields without regard to case. Values in arrays retain their original case.
func Decode(b []byte, max int, dst any) error {
	if len(b) > max || max <= 0 || !validUnicode(b) {
		return ErrDocument
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := value(d, 0); err != nil {
		return ErrDocument
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return ErrDocument
	}
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return ErrDocument
	}
	return nil
}

func value(d *json.Decoder, depth int) error {
	t, err := d.Token()
	if err != nil {
		return ErrDocument
	}
	delim, container := t.(json.Delim)
	if !container {
		return nil
	}
	if depth >= 64 {
		return ErrDocument
	}
	switch delim {
	case '{':
		seen := make(map[string]bool)
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return ErrDocument
			}
			s, ok := key.(string)
			if !ok {
				return ErrDocument
			}
			// Canonicalize the complete Unicode simple-fold orbit in linear time.
			folded := strings.Map(func(r rune) rune {
				least := r
				for next := unicode.SimpleFold(r); next != r; next = unicode.SimpleFold(next) {
					if next < least {
						least = next
					}
				}
				return least
			}, s)
			if seen[folded] {
				return ErrDocument
			}
			seen[folded] = true
			if err := value(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := value(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return ErrDocument
	}
	end, err := d.Token()
	if err != nil || (delim == '{' && end != json.Delim('}')) || (delim == '[' && end != json.Delim(']')) {
		return ErrDocument
	}
	return nil
}

// encoding/json otherwise replaces malformed Unicode with U+FFFD. JON-1
// rejects it instead so evidence and identifiers cannot silently change.
func validUnicode(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for i := 0; i < len(b); i++ {
		if b[i] != '\\' {
			continue
		}
		i++
		if i >= len(b) {
			return false
		}
		if b[i] != 'u' {
			continue
		}
		if i+4 >= len(b) {
			return false
		}
		n, err := strconv.ParseUint(string(b[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(b) || b[i+1] != '\\' || b[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(b[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}
