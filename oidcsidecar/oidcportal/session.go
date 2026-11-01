package oidcportal

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

const (
	sessionCookie = "magpie_oidc_session"
	flowCookie    = "magpie_oidc_flow"
)

// Session is who the portal's browser is signed in as. It lives in a cookie
// signed with the portal's secret: the browser can read it, not change it.
type Session struct {
	Subject string    `json:"sub"`
	Email   string    `json:"email,omitempty"`
	Name    string    `json:"name,omitempty"`
	Groups  []string  `json:"groups,omitempty"`
	Expires time.Time `json:"exp"`
}

// Flow is a login in progress: the state and nonce the callback must match,
// the PKCE verifier the code exchange needs, and where to go after.
type Flow struct {
	State    string    `json:"state"`
	Nonce    string    `json:"nonce"`
	Verifier string    `json:"verifier"`
	Next     string    `json:"next,omitempty"`
	Expires  time.Time `json:"exp"`
}

// Signer reads and writes the portal's two cookies. A cookie that does not
// carry this signer's signature, or has expired, is no cookie at all.
type Signer struct {
	key    []byte
	secure bool
	now    func() time.Time
}

// NewSigner signs with secret; secure marks the cookies Secure, as a portal
// behind HTTPS wants.
func NewSigner(secret string, secure bool) *Signer {
	return &Signer{key: []byte(secret), secure: secure, now: time.Now}
}

func (s *Signer) SetSession(w http.ResponseWriter, v Session, ttl time.Duration) {
	v.Expires = s.now().Add(ttl).UTC()
	s.set(w, sessionCookie, v, ttl)
}

func (s *Signer) Session(r *http.Request) (Session, bool) {
	var v Session
	if !s.get(r, sessionCookie, &v) {
		return Session{}, false
	}
	return v, true
}

func (s *Signer) SetFlow(w http.ResponseWriter, v Flow, ttl time.Duration) {
	v.Expires = s.now().Add(ttl).UTC()
	s.set(w, flowCookie, v, ttl)
}

func (s *Signer) Flow(r *http.Request) (Flow, bool) {
	var v Flow
	if !s.get(r, flowCookie, &v) {
		return Flow{}, false
	}
	return v, true
}

func (s *Signer) ClearSession(w http.ResponseWriter) { s.clear(w, sessionCookie) }
func (s *Signer) ClearFlow(w http.ResponseWriter)    { s.clear(w, flowCookie) }

func (s *Signer) set(w http.ResponseWriter, name string, v any, ttl time.Duration) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	payload := base64.RawURLEncoding.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    payload + "." + s.sign(payload),
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Signer) get(r *http.Request, name string, v any) bool {
	c, err := r.Cookie(name)
	if err != nil {
		return false
	}
	payload, sig, ok := strings.Cut(c.Value, ".")
	if !ok || subtle.ConstantTimeCompare([]byte(sig), []byte(s.sign(payload))) != 1 {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return false
	}
	var exp struct {
		Expires time.Time `json:"exp"`
	}
	if json.Unmarshal(b, &exp) != nil || exp.Expires.IsZero() || !s.now().Before(exp.Expires) {
		return false
	}
	return json.Unmarshal(b, v) == nil
}

func (s *Signer) clear(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Signer) sign(payload string) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
