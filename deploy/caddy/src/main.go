// Command caddy is the stock Caddy v2 binary (standard modules only), built from
// source so that vulnerable transitive dependencies can be bumped without waiting
// for an upstream release.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	_ "github.com/caddyserver/caddy/v2/modules/standard"
)

func main() {
	caddycmd.Main()
}
