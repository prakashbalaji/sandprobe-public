package canarycontrol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"sandprobe/internal/canary"
	"strings"
	"testing"
)

func TestMaintenanceRoutesAreNotPublic(t *testing.T) {
	c, err := canary.New("sandprobe.test")
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	handler := Handler(c, key)
	for _, op := range []string{"maintenance", "drain", "resume"} {
		q := httptest.NewRequest(http.MethodPost, "https://control.sandprobe.test/v1/"+op, strings.NewReader(`{}`))
		q.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, q)
		if w.Code != http.StatusNotFound {
			t.Fatal("private operation exposed", op, w.Code)
		}
	}
	a := c.Handle(canary.Request{Op: "maintenance"})
	if a.Maintenance == nil || a.Maintenance.Draining {
		t.Fatal("public handler changed maintenance state")
	}
}
