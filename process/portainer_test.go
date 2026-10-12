package process

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPortainerAuthenticatesAndControlsContainer(t *testing.T) {
	authentications, starts, stops := 0, 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/auth":
			authentications++
			fmt.Fprint(w, `{"jwt":"test-token"}`)
		case strings.HasSuffix(r.URL.Path, "/_ping"):
			w.Header().Set("API-Version", "1.44")
			fmt.Fprint(w, "OK")
		case r.Header.Get("Authorization") != "Bearer test-token":
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"message":"authenticate"}`)
		case strings.HasSuffix(r.URL.Path, "/containers/json"):
			fmt.Fprint(w, `[{"Id":"target","Names":["/server"]}]`)
		case strings.HasSuffix(r.URL.Path, "/containers/target/start"):
			starts++
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/containers/target/stop"):
			stops++
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/containers/target/json"):
			fmt.Fprint(w, `{"Id":"target","State":{"Running":true}}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	proc, err := NewPortainer("server", strings.TrimPrefix(server.URL, "http://"), "1", "user", "password")
	if err != nil {
		t.Fatal(err)
	}
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	running, err := proc.IsRunning()
	if err != nil || !running {
		t.Fatalf("running=%v error=%v", running, err)
	}
	if err := proc.Stop(); err != nil {
		t.Fatal(err)
	}
	if authentications != 1 || starts != 1 || stops != 1 {
		t.Fatalf("authentications=%d starts=%d stops=%d", authentications, starts, stops)
	}
}
