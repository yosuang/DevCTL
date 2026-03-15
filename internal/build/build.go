package build

import "fmt"

// Set at build time via ldflags.
var (
	Version   = "DEV"
	BuildDate = ""
)

func FormatVersion() string {
	if BuildDate != "" {
		return fmt.Sprintf("%s (%s)", Version, BuildDate)
	}
	return Version
}
