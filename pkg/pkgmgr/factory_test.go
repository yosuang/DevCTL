package pkgmgr

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name       string
		goos       string
		registered bool
		wantErr    error
	}{
		{
			name:       "registered platform returns manager",
			goos:       "windows",
			registered: true,
			wantErr:    nil,
		},
		{
			name:       "unregistered platform returns unsupported error",
			goos:       "linux",
			registered: false,
			wantErr:    ErrUnsupported,
		},
		{
			name:       "darwin returns unsupported error",
			goos:       "darwin",
			registered: false,
			wantErr:    ErrUnsupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// #given: a specific operating system and registration state
			originalGOOS := testGOOS
			originalRegistry := registry
			registry = make(map[string]func() Manager)
			testGOOS = tt.goos
			defer func() {
				testGOOS = originalGOOS
				registry = originalRegistry
			}()

			if tt.registered {
				Register(tt.goos, func() Manager {
					return &mockManager{}
				})
			}

			// #when: calling New()
			mgr, err := New()

			// #then: should return expected manager or error
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				require.Nil(t, mgr)
			} else {
				require.NoError(t, err)
				require.NotNil(t, mgr)
				require.Implements(t, (*Manager)(nil), mgr)
			}
		})
	}
}
