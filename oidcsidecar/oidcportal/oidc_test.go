package oidcportal

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

func TestClaimAt(t *testing.T) {
	claims := map[string]any{
		"groups":       []any{"team-a", "team-c"},
		"one":          "team-b",
		"realm_access": map[string]any{"roles": []any{"offline_access", "magpie"}},
		"not_a_map":    "x",
	}
	cases := []struct {
		path string
		want []string
	}{
		{"groups", []string{"team-a", "team-c"}},
		{"one", []string{"team-b"}},
		{"realm_access.roles", []string{"offline_access", "magpie"}},
		{"realm_access.missing", nil},
		{"missing.path", nil},
		{"not_a_map.path", nil},
		{"", nil},
	}
	for _, tc := range cases {
		if got := stringValues(claimAt(claims, tc.path)); !slices.Equal(got, tc.want) {
			t.Fatalf("claimAt(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestInGroupTrimsThePath(t *testing.T) {
	id := Identity{Groups: []string{"/team-a", "team-c/nested"}}
	for _, g := range []string{"team-a", "/team-a/", "team-c/nested"} {
		if !id.InGroup(g) {
			t.Fatalf("%q not a group of %v", g, id.Groups)
		}
	}
	for _, g := range []string{"team", "team-c", "", "/"} {
		if id.InGroup(g) {
			t.Fatalf("%q read as a group of %v", g, id.Groups)
		}
	}
}

// The real provider against a fake issuer: discovery, PKCE, the code
// exchange, ID token signature and nonce, and the group claim.
func TestProviderExchange(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	var wantNonce string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/auth",
			"token_endpoint":                        srv.URL + "/token",
			"jwks_uri":                              srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
			Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig",
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.Form.Get("code") != "the-code" || r.Form.Get("code_verifier") == "" {
			http.Error(w, "bad exchange", http.StatusBadRequest)
			return
		}
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
			(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		claims, _ := json.Marshal(map[string]any{
			"iss":    srv.URL,
			"aud":    "magpie",
			"sub":    "alice",
			"exp":    time.Now().Add(time.Hour).Unix(),
			"iat":    time.Now().Unix(),
			"nonce":  wantNonce,
			"email":  "alice@example.com",
			"name":   "Alice",
			"groups": []string{"team-a", "team-c"},
		})
		jws, err := signer.Sign(claims)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		raw, _ := jws.CompactSerialize()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer", "id_token": raw,
		})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg, err := (&Config{
		Issuer:       srv.URL,
		ClientID:     "magpie",
		ClientSecret: strings.Repeat("c", 32),
		RedirectURL:  "http://magpie.example.com/callback",
		CookieSecret: strings.Repeat("c", 32),
	}).Prepare()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p, err := NewProvider(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}

	authURL, err := url.Parse(p.AuthCodeURL("the-state", "the-nonce", "the-verifier"))
	if err != nil {
		t.Fatal(err)
	}
	q := authURL.Query()
	sum := sha256.Sum256([]byte("the-verifier"))
	if q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) ||
		q.Get("code_challenge_method") != "S256" || q.Get("nonce") != "the-nonce" ||
		q.Get("state") != "the-state" || q.Get("client_id") != "magpie" {
		t.Fatalf("auth URL = %s", authURL)
	}

	wantNonce = "the-nonce"
	id, err := p.Exchange(ctx, "the-code", "the-verifier", "the-nonce")
	if err != nil {
		t.Fatal(err)
	}
	if id.Subject != "alice" || id.Email != "alice@example.com" || id.Name != "Alice" ||
		!slices.Equal(id.Groups, []string{"team-a", "team-c"}) {
		t.Fatalf("identity = %+v", id)
	}

	if _, err := p.Exchange(ctx, "the-code", "the-verifier", "another-nonce"); err == nil {
		t.Fatal("accepted an id token for another login")
	}
}

func TestIdentityRoles(t *testing.T) {
	if RoleSuper != "magpie-super" || RoleOperator != "magpie-operator" {
		t.Fatalf("role names moved: %q, %q", RoleSuper, RoleOperator)
	}
	id := Identity{Subject: "s", Groups: []string{"magpie-super", "/magpie-operator", "team-a"}}
	if !id.HasRole("magpie-super") {
		t.Fatal("magpie-super not seen")
	}
	if !id.HasRole("magpie-operator") {
		t.Fatal("magpie-operator not seen behind its leading slash")
	}
	if id.HasRole("magpie-none") {
		t.Fatal("an unheld role says held")
	}
	if id.HasRole("") || id.HasRole("/") {
		t.Fatal("an empty role says held")
	}
	plain := Identity{Subject: "s", Groups: []string{"team-a"}}
	if plain.HasRole("magpie-super") || plain.HasRole("magpie-operator") {
		t.Fatal("a plain person reads as a role holder")
	}
}
