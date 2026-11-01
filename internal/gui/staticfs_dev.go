//go:build dev

package gui

import "io/fs"

// StaticFS is the page's own files, from the folder when built with -tags
// dev (dev_on.go).
func StaticFS() fs.FS { return staticFS() }
