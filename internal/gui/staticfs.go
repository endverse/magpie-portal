//go:build !dev

package gui

import "io/fs"

// StaticFS is the page's own files, embedded: index.html, its scripts,
// stylesheets and icons, for a process serving the page without this
// package's handler.
func StaticFS() fs.FS { return staticFS() }
