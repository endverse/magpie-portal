package oidcportal

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSignedCookies(t *testing.T) {
	s := NewSigner(strings.Repeat("s", 32), false)
	w := httptest.NewRecorder()
	s.SetSession(w, Session{Subject: "alice", Email: "alice@example.com"}, time.Hour)

	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range w.Result().Cookies() {
		req.AddCookie(c)
	}
	got, ok := s.Session(req)
	if !ok || got.Subject != "alice" || got.Email != "alice@example.com" {
		t.Fatalf("session = %+v, %v", got, ok)
	}

	// A cookie changed in the browser is not one the portal wrote.
	bad := httptest.NewRequest("GET", "/", nil)
	c := w.Result().Cookies()[0]
	bad.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value + "x"})
	if _, ok := s.Session(bad); ok {
		t.Fatal("accepted a tampered cookie")
	}

	// Nor is one from another signer.
	other := NewSigner(strings.Repeat("o", 32), false)
	if _, ok := other.Session(req); ok {
		t.Fatal("accepted another signer's cookie")
	}

	// And an expired one is no cookie.
	s.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, ok := s.Session(req); ok {
		t.Fatal("accepted an expired cookie")
	}
}

func TestFlowCookie(t *testing.T) {
	s := NewSigner(strings.Repeat("s", 32), false)
	w := httptest.NewRecorder()
	s.SetFlow(w, Flow{State: "st", Nonce: "no", Verifier: "ve", Next: "/admin"}, flowTTL)
	req := httptest.NewRequest("GET", "/", nil)
	for _, c := range w.Result().Cookies() {
		req.AddCookie(c)
	}
	f, ok := s.Flow(req)
	if !ok || f.State != "st" || f.Nonce != "no" || f.Verifier != "ve" || f.Next != "/admin" {
		t.Fatalf("flow = %+v, %v", f, ok)
	}
	if _, ok := s.Session(req); ok {
		t.Fatal("a flow cookie read as a session")
	}
}
