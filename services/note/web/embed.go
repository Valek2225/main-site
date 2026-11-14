// Package web holds the embedded frontend of note.rima.su.
package web

import "embed"

//go:embed static
var Static embed.FS

//go:embed templates
var Templates embed.FS
