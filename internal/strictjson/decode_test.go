package strictjson

import (
	"strings"
	"testing"
)

func TestFraming(t *testing.T) {
	for _, s := range []string{
		`{"a":1,"a":2}`, `{"a":1,"\u0061":2}`, `"\uD800"`, `"\uDC00"`, string([]byte{34, 255, 34}), `{"a":1,"A":2}`, `{"k":1,"K":2}`,
		`{"nested":{"x":1,"X":2}}`, `{"a":1} {}`, `{"a":1}garbage`,
		``, `{"a":`, strings.Repeat("[", 65) + strings.Repeat("]", 65),
	} {
		var v any
		if Decode([]byte(s), 4096, &v) == nil {
			t.Errorf("accepted malformed input %q", s)
		}
	}
	for _, s := range []string{`{"a":1,"nested":{"a":2}}`, `["a","A"]`, `"\uD83D\uDE00"`, `"\\uD800"`, strings.Repeat("[", 64) + strings.Repeat("]", 64)} {
		var v any
		if err := Decode([]byte(s), 4096, &v); err != nil {
			t.Errorf("rejected canonical input: %v", err)
		}
	}
}

func TestBoundsAndUnknown(t *testing.T) {
	var v struct {
		A int `json:"a"`
	}
	for _, s := range []string{`{"b":1}`, `{"a":"private-marker"}`, `{"a":1} `} {
		max := len(s)
		if s == `{"a":1} ` {
			max--
		}
		if err := Decode([]byte(s), max, &v); err == nil || strings.Contains(err.Error(), "private-marker") {
			t.Fatal("unsafe error or accepted input")
		}
	}
}

func FuzzDecode(f *testing.F) {
	for _, s := range []string{`{}`, `{"a":1}`, `{"x":1,"X":2}`, `[]`, `null`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var dst any
		err := Decode(b, 1<<20, &dst)
		if err == nil {
			var other any
			if Decode(append(append([]byte{}, b...), []byte(" {}")...), 1<<20, &other) == nil {
				t.Fatal("trailing value accepted")
			}
			if len(b) > 1 && Decode(b, len(b)-1, &other) == nil {
				t.Fatal("size bound ignored")
			}
		}
	})
}
