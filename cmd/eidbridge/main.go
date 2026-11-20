// Command eidbridge is a self-hosted Smart-ID RP API v3 to OpenID Connect bridge.
package main

import (
	"fmt"
	"os"

	"github.com/tomkabel/eidbridge/internal/version"
)

func main() {
	fmt.Fprintln(os.Stderr, version.String())
}
