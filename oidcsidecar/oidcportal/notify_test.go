package oidcportal

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNoNotifierWhenNoneIsConfigured(t *testing.T) {
	if NewNotifier(NotifyConfig{}) != nil {
		t.Fatal("a notifier exists without a webhook")
	}
}

// A generic webhook receives the event itself; a Feishu bot receives a text
// message in its own envelope.
func TestNotifiers(t *testing.T) {
	type got struct {
		path string
		body map[string]any
	}
	recv := make(chan got, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Errorf("body = %q: %v", b, err)
		}
		recv <- got{path: r.URL.Path, body: m}
	}))
	defer srv.Close()

	event := Event{Kind: "application", Sub: "bob", Email: "bob@example.com", Name: "Bob", Text: "Bob applied", At: time.Now()}

	if err := NewNotifier(NotifyConfig{Webhook: srv.URL + "/generic"}).Notify(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	g := <-recv
	if g.path != "/generic" || g.body["kind"] != "application" || g.body["sub"] != "bob" || g.body["text"] != "Bob applied" {
		t.Fatalf("generic = %+v", g)
	}
	if _, ok := g.body["at"]; !ok {
		t.Fatalf("the event's time is missing: %+v", g.body)
	}

	if err := NewNotifier(NotifyConfig{Feishu: srv.URL + "/feishu"}).Notify(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	g = <-recv
	if g.path != "/feishu" || g.body["msg_type"] != "text" {
		t.Fatalf("feishu = %+v", g)
	}
	content, _ := g.body["content"].(map[string]any)
	if content["text"] != "Bob applied" {
		t.Fatalf("feishu content = %+v", g.body)
	}
}

// Both configured means both told; one failing does not stop the other.
func TestBothNotifiersAndAFailureDoesNotBlock(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	defer failing.Close()
	calls := 0
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer good.Close()

	n := NewNotifier(NotifyConfig{Webhook: failing.URL, Feishu: good.URL})
	if err := n.Notify(context.Background(), Event{Kind: "approved", Sub: "bob", Text: "approved"}); err == nil {
		t.Fatal("a 500 from the webhook was not reported")
	}
	if calls != 1 {
		t.Fatalf("the second webhook was called %d times", calls)
	}
}

func TestAuditIsAppendedLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oidc-audit.jsonl")
	a := OpenAudit(path)
	a.Log("boss@example.com", "approve", "bob", "a/* $10/month")
	a.Log("boss@example.com", "rotate", "alice", "")

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("audit = %q", b)
	}
	var e auditEntry
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil {
		t.Fatal(err)
	}
	if e.Actor != "boss@example.com" || e.Action != "approve" || e.Sub != "bob" || e.Detail == "" || e.At.IsZero() {
		t.Fatalf("entry = %+v", e)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v", fi.Mode().Perm())
	}

	// An empty path is a log that keeps nothing, and a nil one is harmless.
	OpenAudit("").Log("boss", "x", "y", "z")
	var nilAudit *Audit
	nilAudit.Log("boss", "x", "y", "z")
}
