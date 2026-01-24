package executil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLookPath(t *testing.T) {
	t.Run("finds existing executable", func(t *testing.T) {
		path := LookPath("go")
		assert.NotEmpty(t, path)
	})

	t.Run("returns empty for non-existent executable", func(t *testing.T) {
		path := LookPath("nonexistent-executable-12345")
		assert.Empty(t, path)
	})
}

func TestIsInstalled(t *testing.T) {
	t.Run("returns true for existing executable", func(t *testing.T) {
		installed := IsInstalled("go")
		assert.True(t, installed)
	})

	t.Run("returns false for non-existent executable", func(t *testing.T) {
		installed := IsInstalled("nonexistent-executable-12345")
		assert.False(t, installed)
	})
}
