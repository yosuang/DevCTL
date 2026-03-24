package sync

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStatus_NotInitialized(t *testing.T) {
	// #given: a non-git directory
	configDir := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	// #when: check status
	r := New(configDir)
	result, err := r.Status()

	// #then: returns not initialized
	require.NoError(t, err)
	require.Equal(t, StatusNotInitialized, result.State)
}

func TestStatus_UpToDate(t *testing.T) {
	// #given: an initialized repo with no changes
	bare := helperBareRemote(t)
	configDir := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	r := New(configDir)
	require.NoError(t, os.MkdirAll(filepath.Join(configDir, "kit"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "kit", "kit.json"), []byte(`{}`), 0644))
	require.NoError(t, r.Sync(bare, ""))

	// #when: check status
	result, err := r.Status()

	// #then: up to date with a last synced timestamp
	require.NoError(t, err)
	require.Equal(t, StatusUpToDate, result.State)
	require.NotNil(t, result.LastSyncedAt)
	require.WithinDuration(t, time.Now(), *result.LastSyncedAt, 5*time.Second)
	require.Empty(t, result.LocalChanges)
	require.Equal(t, 0, result.RemoteBehind)
}

func TestStatus_OutOfDate_LocalChanges(t *testing.T) {
	// #given: an initialized repo with a local modification
	bare := helperBareRemote(t)
	configDir := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	r := New(configDir)
	kitDir := filepath.Join(configDir, "kit")
	require.NoError(t, os.MkdirAll(kitDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(kitDir, "kit.json"), []byte(`{}`), 0644))
	require.NoError(t, r.Sync(bare, ""))

	// Modify a tracked file
	require.NoError(t, os.WriteFile(filepath.Join(kitDir, "kit.json"), []byte(`{"updated":true}`), 0644))

	// #when: check status
	result, err := r.Status()

	// #then: out of date with local changes listed
	require.NoError(t, err)
	require.Equal(t, StatusOutOfDate, result.State)
	require.Len(t, result.LocalChanges, 1)
	require.Equal(t, ChangeModified, result.LocalChanges[0].Type)
	require.Contains(t, result.LocalChanges[0].Path, "kit.json")
	require.Equal(t, 0, result.RemoteBehind)
}

func TestStatus_OutOfDate_NewLocalFile(t *testing.T) {
	// #given: an initialized repo with a new untracked file in the whitelist
	bare := helperBareRemote(t)
	configDir := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	r := New(configDir)
	kitDir := filepath.Join(configDir, "kit")
	require.NoError(t, os.MkdirAll(kitDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(kitDir, "kit.json"), []byte(`{}`), 0644))
	require.NoError(t, r.Sync(bare, ""))

	// Add a new file under kit/
	require.NoError(t, os.MkdirAll(filepath.Join(kitDir, "zsh"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(kitDir, "zsh", "zshrc"), []byte("# zshrc"), 0644))

	// #when: check status
	result, err := r.Status()

	// #then: out of date with added file
	require.NoError(t, err)
	require.Equal(t, StatusOutOfDate, result.State)
	require.Len(t, result.LocalChanges, 1)
	require.Equal(t, ChangeAdded, result.LocalChanges[0].Type)
}

func TestStatus_OutOfDate_RemoteChanges(t *testing.T) {
	// #given: an initialized repo with new remote commits
	bare := helperBareRemote(t)
	configDir := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	r := New(configDir)
	kitDir := filepath.Join(configDir, "kit")
	require.NoError(t, os.MkdirAll(kitDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(kitDir, "kit.json"), []byte(`{}`), 0644))
	require.NoError(t, r.Sync(bare, ""))

	// Push a commit from another "machine"
	helperPushInitialCommit(t, bare, "kit/kit.json", `{"from":"other"}`)

	// #when: check status
	result, err := r.Status()

	// #then: out of date with remote commits behind
	require.NoError(t, err)
	require.Equal(t, StatusOutOfDate, result.State)
	require.Empty(t, result.LocalChanges)
	require.Equal(t, 1, result.RemoteBehind)
}

func TestStatus_Conflict(t *testing.T) {
	// #given: an initialized repo with both local and remote changes
	bare := helperBareRemote(t)
	configDir := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	r := New(configDir)
	kitDir := filepath.Join(configDir, "kit")
	require.NoError(t, os.MkdirAll(kitDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(kitDir, "kit.json"), []byte(`{}`), 0644))
	require.NoError(t, r.Sync(bare, ""))

	// Push a remote change
	helperPushInitialCommit(t, bare, "kit/kit.json", `{"from":"remote"}`)

	// Make a local change
	require.NoError(t, os.WriteFile(filepath.Join(kitDir, "kit.json"), []byte(`{"from":"local"}`), 0644))

	// #when: check status
	result, err := r.Status()

	// #then: conflict state with both local and remote changes
	require.NoError(t, err)
	require.Equal(t, StatusConflict, result.State)
	require.NotEmpty(t, result.LocalChanges)
	require.Equal(t, 1, result.RemoteBehind)
}

func TestStatus_LastSyncedNever(t *testing.T) {
	// #given: a git repo initialized manually (no sync state file)
	bare := helperBareRemote(t)
	configDir := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	r := New(configDir)
	// Initialize repo manually without going through Sync
	r.run("init", "-b", "main")
	r.run("remote", "add", "origin", bare)
	require.NoError(t, r.writeGitignore())

	// #when: check status
	result, err := r.Status()

	// #then: up to date but last synced is nil (never)
	require.NoError(t, err)
	require.Nil(t, result.LastSyncedAt)
}

func TestStatus_ExcludedFilesNotListed(t *testing.T) {
	// #given: an initialized repo with excluded files added after sync
	bare := helperBareRemote(t)
	configDir := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	r := New(configDir)
	kitDir := filepath.Join(configDir, "kit")
	require.NoError(t, os.MkdirAll(kitDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(kitDir, "kit.json"), []byte(`{}`), 0644))
	require.NoError(t, r.Sync(bare, ""))

	// Add files that should be excluded by the gitignore whitelist
	require.NoError(t, os.MkdirAll(filepath.Join(configDir, "logs"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "logs", "app.log"), []byte("log"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "settings.json"), []byte("{}"), 0644))

	// #when: check status
	result, err := r.Status()

	// #then: excluded files do not appear in local changes
	require.NoError(t, err)
	require.Equal(t, StatusUpToDate, result.State)
	require.Empty(t, result.LocalChanges)
}

func TestStatus_DeletedFile(t *testing.T) {
	// #given: an initialized repo where a tracked file is deleted
	bare := helperBareRemote(t)
	configDir := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	r := New(configDir)
	kitDir := filepath.Join(configDir, "kit")
	require.NoError(t, os.MkdirAll(kitDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(kitDir, "kit.json"), []byte(`{}`), 0644))
	require.NoError(t, os.MkdirAll(filepath.Join(kitDir, "zsh"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(kitDir, "zsh", "zshrc"), []byte("# zshrc"), 0644))
	require.NoError(t, r.Sync(bare, ""))

	// Delete a tracked file
	require.NoError(t, os.Remove(filepath.Join(kitDir, "zsh", "zshrc")))

	// #when: check status
	result, err := r.Status()

	// #then: shows deleted file
	require.NoError(t, err)
	require.Equal(t, StatusOutOfDate, result.State)
	require.Len(t, result.LocalChanges, 1)
	require.Equal(t, ChangeDeleted, result.LocalChanges[0].Type)
	require.Contains(t, result.LocalChanges[0].Path, "zshrc")
}

func TestStatus_SyncStatePersistedAfterSync(t *testing.T) {
	// #given: a fresh config dir
	bare := helperBareRemote(t)
	configDir := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	r := New(configDir)
	kitDir := filepath.Join(configDir, "kit")
	require.NoError(t, os.MkdirAll(kitDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(kitDir, "kit.json"), []byte(`{}`), 0644))

	// #when: sync completes
	require.NoError(t, r.Sync(bare, ""))

	// #then: .sync-state.json exists with a recent timestamp
	state, err := r.readState()
	require.NoError(t, err)
	require.NotNil(t, state)
	require.WithinDuration(t, time.Now(), state.LastSyncedAt, 5*time.Second)
}

func TestStatus_SyncStateNotTrackedByGit(t *testing.T) {
	// #given: a synced repo
	bare := helperBareRemote(t)
	configDir := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	r := New(configDir)
	kitDir := filepath.Join(configDir, "kit")
	require.NoError(t, os.MkdirAll(kitDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(kitDir, "kit.json"), []byte(`{}`), 0644))
	require.NoError(t, r.Sync(bare, ""))

	// #when: check if .sync-state.json is tracked
	out, err := r.run("ls-files")
	require.NoError(t, err)

	// #then: .sync-state.json is not in the tracked files
	require.NotContains(t, out, stateFile)
}
