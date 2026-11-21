// Package version reports the build version. Release builds set Version via
// -ldflags "-X github.com/tomkabel/eidbridge/internal/version.Version=v1.2.3".
package version

// Version is "dev" unless set at link time.
var Version = "dev"

// String returns the version with the unofficial-project marker.
func String() string { return "eidbridge " + Version + " (unofficial)" }
