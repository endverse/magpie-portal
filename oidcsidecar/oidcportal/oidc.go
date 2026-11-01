package oidcportal

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Identity is who an OIDC login proved: the subject the provider will always
// name them by, and the profile and groups it said.
type Identity struct {
	Subject  string   `json:"subject"`
	Email    string   `json:"email,omitempty"`
	Name     string   `json:"name,omitempty"`
	Username string   `json:"username,omitempty"`
	Groups   []string `json:"groups,omitempty"`
}

// InGroup says whether the identity is a member of the named group, either
// as the provider wrote it or with its leading slash dropped.
func (id Identity) InGroup(group string) bool {
	group = strings.Trim(strings.TrimSpace(group), "/")
	if group == "" {
		return false
	}
	for _, g := range id.Groups {
		if strings.Trim(strings.TrimSpace(g), "/") == group {
			return true
		}
	}
	return false
}

// OIDCProvider is the part of an OpenID Connect provider the portal uses: a
// login URL to send someone to, and the identity their code comes back as.
// The portal's tests give it a fake; NewProvider gives it the real one.
type OIDCProvider interface {
	// AuthCodeURL is where to send the browser: state and nonce are the
	// portal's own, verifier is the PKCE secret whose challenge is in the
	// URL and whose value Exchange needs.
	AuthCodeURL(state, nonce, verifier string) string
	// Exchange redeems a login's code, checks the ID token against the
	// provider's keys and the nonce, and returns who signed in.
	Exchange(ctx context.Context, code, verifier, nonce string) (Identity, error)
}

// Provider is the real OIDCProvider: discovery at the issuer, the
// authorization code flow with PKCE, and ID token verification.
type Provider struct {
	oauth      *oauth2.Config
	verifier   *oidc.IDTokenVerifier
	groupClaim string
}

// NewProvider discovers the issuer's endpoints and signing keys.
func NewProvider(ctx context.Context, c *Config) (*Provider, error) {
	p, err := oidc.NewProvider(ctx, c.Issuer)
	if err != nil {
		return nil, fmt.Errorf("discover %s: %w", c.Issuer, err)
	}
	return &Provider{
		oauth: &oauth2.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			Endpoint:     p.Endpoint(),
			RedirectURL:  c.RedirectURL,
			Scopes:       c.Scopes,
		},
		verifier:   p.Verifier(&oidc.Config{ClientID: c.ClientID}),
		groupClaim: c.GroupClaim,
	}, nil
}

func (p *Provider) AuthCodeURL(state, nonce, verifier string) string {
	return p.oauth.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.S256ChallengeOption(verifier),
	)
}

func (p *Provider) Exchange(ctx context.Context, code, verifier, nonce string) (Identity, error) {
	tok, err := p.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("exchange the login code: %w", err)
	}
	raw, _ := tok.Extra("id_token").(string)
	if raw == "" {
		return Identity{}, errors.New("the token response has no id_token: the openid scope is missing")
	}
	idToken, err := p.verifier.Verify(ctx, raw)
	if err != nil {
		return Identity{}, fmt.Errorf("verify the id token: %w", err)
	}
	if idToken.Nonce != nonce {
		return Identity{}, errors.New("the id token's nonce is not this login's")
	}
	var claims struct {
		Email             string `json:"email"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return Identity{}, fmt.Errorf("read the id token: %w", err)
	}
	var all map[string]any
	if err := idToken.Claims(&all); err != nil {
		return Identity{}, fmt.Errorf("read the id token: %w", err)
	}
	id := Identity{
		Subject:  idToken.Subject,
		Email:    claims.Email,
		Name:     claims.Name,
		Username: claims.PreferredUsername,
		Groups:   stringValues(claimAt(all, p.groupClaim)),
	}
	if id.Subject == "" {
		return Identity{}, errors.New("the id token has no subject")
	}
	return id, nil
}

// claimAt follows a dotted path through the ID token's claims, so a group
// claim can be "groups" or Keycloak's "realm_access.roles".
func claimAt(claims map[string]any, path string) any {
	var cur any = claims
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[part]
	}
	return cur
}

// stringValues reads a claim that may be a list of strings or one string.
func stringValues(v any) []string {
	switch x := v.(type) {
	case string:
		if x == "" {
			return nil
		}
		return []string{x}
	case []string:
		return x
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
