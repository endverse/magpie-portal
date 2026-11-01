package oidcportal

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"

	// magpie's own page and its files, embedded in magpie: the portal
	// serves that page itself, as it is (internal/gui/assets)
	"github.com/yetone/magpie/internal/gui"
)

// fsFile says whether name is one of the console page's own files.
func fsFile(name string) bool {
	_, err := fs.Stat(gui.StaticFS(), name)
	return err == nil
}

func readPageFile(name string) ([]byte, error) { return fs.ReadFile(gui.StaticFS(), name) }

// contentHash is the six bytes of sha256 the page names a file by, as
// magpie does.
func contentHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:6])
}
