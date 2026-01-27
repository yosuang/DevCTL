package version

import (
	"strings"

	"golang.org/x/mod/semver"
)

// Normalize standardizes a version string by ensuring it has a "v" prefix.
// If the version is empty, it returns an empty string.
// If the version already has a "v" prefix, it returns the version as-is.
// Otherwise, it adds a "v" prefix to the version.
func Normalize(v string) string {
	if v == "" {
		return ""
	}
	if strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}

// Equal compares two version strings for equality.
// It normalizes both versions before comparison using semver.Canonical.
// Returns true if the versions are semantically equal, false otherwise.
func Equal(v1, v2 string) bool {
	if v1 == "" && v2 == "" {
		return true
	}
	if v1 == "" || v2 == "" {
		return false
	}

	norm1 := Normalize(v1)
	norm2 := Normalize(v2)

	canon1 := semver.Canonical(norm1)
	canon2 := semver.Canonical(norm2)

	return canon1 == canon2
}

// IsEmpty checks if a version string is empty.
// Returns true if the version is an empty string, false otherwise.
func IsEmpty(v string) bool {
	return v == ""
}
