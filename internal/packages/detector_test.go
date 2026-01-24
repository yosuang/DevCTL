package packages

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDetectPackageManagers(t *testing.T) {
	t.Run("detects package managers", func(t *testing.T) {
		managers := DetectPackageManagers()

		assert.NotEmpty(t, managers)
		assert.Len(t, managers, 2)

		for _, mgr := range managers {
			assert.NotEmpty(t, mgr.ID)
			if mgr.Installed {
				assert.NotEmpty(t, mgr.ExecutablePath)
			}
		}
	})
}
