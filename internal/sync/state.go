// state.go manages the .sync-state.json file that tracks the last successful sync timestamp.
package sync

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const stateFile = ".sync-state.json"

// SyncState holds the persistent state written after each successful sync.
type SyncState struct {
	LastSyncedAt time.Time `json:"last_synced_at"`
}

func (r *Repo) statePath() string {
	return filepath.Join(r.configDir, stateFile)
}

// readState reads the sync state from disk. Returns nil if the file does not exist.
func (r *Repo) readState() (*SyncState, error) {
	data, err := os.ReadFile(r.statePath())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var state SyncState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

// writeState persists the sync state to disk.
func (r *Repo) writeState(state *SyncState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return os.WriteFile(r.statePath(), data, 0644)
}
