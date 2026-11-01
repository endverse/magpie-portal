package oidcportal

import (
	"os"
	"path/filepath"
)

// readMagpieKeyPage reads magpie's own key page (internal/gateway/keypage.html)
// from the source tree this module replaces, so a test can say the embedded
// copy is that same page. The built program needs no source beside it.
func readMagpieKeyPage() ([]byte, error) {
	for _, p := range []string{
		filepath.Join("..", "..", "internal", "gateway", "keypage.html"),
		filepath.Join("internal", "gateway", "keypage.html"),
	} {
		if b, err := os.ReadFile(p); err == nil {
			return b, nil
		}
	}
	return nil, os.ErrNotExist
}
