package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParsePackageArg(t *testing.T) {
	tests := []struct {
		arg     string
		name    string
		version string
	}{
		// #given: a plain package name
		// #then: version is empty
		{arg: "git", name: "git", version: ""},

		// #given: name@version syntax
		// #then: splits correctly
		{arg: "git@2.40", name: "git", version: "2.40"},

		// #given: multi-part version
		// #then: full version is captured
		{arg: "node@18.12.0", name: "node", version: "18.12.0"},

		// #given: trailing @ with no version
		// #then: version is empty string
		{arg: "git@", name: "git", version: ""},

		// #given: scoped name with @
		// #then: splits on last @
		{arg: "@scope/pkg@1.0", name: "@scope/pkg", version: "1.0"},
	}

	for _, tt := range tests {
		t.Run(tt.arg, func(t *testing.T) {
			// #when: parsing the argument
			name, version := parsePackageArg(tt.arg)

			// #then: name and version match expectations
			require.Equal(t, tt.name, name)
			require.Equal(t, tt.version, version)
		})
	}
}
