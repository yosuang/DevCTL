package sync

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// helperBareRemote creates a bare git repo and returns its path.
func helperBareRemote(t *testing.T) string {
	t.Helper()
	bare := filepath.Join(t.TempDir(), "remote.git")
	cmd := exec.Command("git", "init", "--bare", "-b", "main", bare)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))
	return bare
}

// helperPushInitialCommit creates a temp clone, makes a commit, and pushes.
func helperPushInitialCommit(t *testing.T, bareRemote, filename, content string) {
	t.Helper()
	clone := filepath.Join(t.TempDir(), "seed")
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", clone}, args...)...)
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
	}

	cmd := exec.Command("git", "clone", bareRemote, clone)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, string(out))

	require.NoError(t, os.WriteFile(filepath.Join(clone, filename), []byte(content), 0644))
	run("add", "-A")
	run("commit", "-m", "seed commit")
	run("push", "origin", "main")
}

func TestFirstSync(t *testing.T) {
	// #given: an empty config dir and a bare remote
	bare := helperBareRemote(t)
	configDir := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	// Write a file to be committed
	require.NoError(t, os.MkdirAll(filepath.Join(configDir, "kit"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "kit", "kit.json"), []byte(`{}`), 0644))

	// #when: first sync with remote URL
	r := New(configDir)
	err := r.Sync(bare, "")

	// #then: succeeds, git repo is initialized, file is pushed to remote
	require.NoError(t, err)
	require.DirExists(t, filepath.Join(configDir, ".git"))
	require.FileExists(t, filepath.Join(configDir, ".gitignore"))

	// Verify remote has the commit
	out, _ := r.run("log", "--oneline", "origin/main")
	require.Contains(t, out, "sync:")
}

func TestFirstSync_NoRemoteURL(t *testing.T) {
	// #given: an empty config dir (not a git repo)
	configDir := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	// #when: sync without remote URL
	r := New(configDir)
	err := r.Sync("", "")

	// #then: returns ErrRemoteRequired
	require.ErrorIs(t, err, ErrRemoteRequired)
}

func TestSubsequentSync_NoChanges(t *testing.T) {
	// #given: an initialized repo with no new changes
	bare := helperBareRemote(t)
	configDir := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	r := New(configDir)
	require.NoError(t, os.MkdirAll(filepath.Join(configDir, "kit"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "kit", "kit.json"), []byte(`{}`), 0644))
	require.NoError(t, r.Sync(bare, ""))

	// #when: sync again with no changes
	err := r.Sync("", "")

	// #then: succeeds (already up to date)
	require.NoError(t, err)
}

func TestSubsequentSync_LocalChanges(t *testing.T) {
	// #given: an initialized repo
	bare := helperBareRemote(t)
	configDir := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	r := New(configDir)
	require.NoError(t, os.MkdirAll(filepath.Join(configDir, "kit"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "kit", "kit.json"), []byte(`{}`), 0644))
	require.NoError(t, r.Sync(bare, ""))

	// #when: add a new file and sync
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "kit", "kit.json"), []byte(`{"updated":true}`), 0644))
	err := r.Sync("", "")

	// #then: succeeds, new commit is pushed
	require.NoError(t, err)
	out, _ := r.run("log", "--oneline")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	require.Len(t, lines, 2) // initial sync + new sync
}

func TestSubsequentSync_RemoteChanges(t *testing.T) {
	// #given: an initialized repo with remote changes
	bare := helperBareRemote(t)
	configDir := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	r := New(configDir)
	require.NoError(t, os.MkdirAll(filepath.Join(configDir, "kit"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "kit", "kit.json"), []byte(`{}`), 0644))
	require.NoError(t, r.Sync(bare, ""))

	// Push a change from another "machine" (file must be in the whitelist)
	helperPushInitialCommit(t, bare, "kit/kit.json", `{"from":"another machine"}`)

	// #when: sync
	err := r.Sync("", "")

	// #then: succeeds, remote change is merged locally
	require.NoError(t, err)
	content, readErr := os.ReadFile(filepath.Join(configDir, "kit", "kit.json"))
	require.NoError(t, readErr)
	require.Contains(t, string(content), "another machine")
}

func TestSubsequentSync_MergeConflict(t *testing.T) {
	// #given: local and remote both modify the same file
	bare := helperBareRemote(t)
	configDir := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	r := New(configDir)
	kitDir := filepath.Join(configDir, "kit")
	require.NoError(t, os.MkdirAll(kitDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(kitDir, "kit.json"), []byte(`{"version":1}`), 0644))
	require.NoError(t, r.Sync(bare, ""))

	// Push a conflicting change from another "machine"
	helperPushInitialCommit(t, bare, "kit/kit.json", `{"version":999}`)

	// Make a local conflicting change
	require.NoError(t, os.WriteFile(filepath.Join(kitDir, "kit.json"), []byte(`{"version":2}`), 0644))
	r.run("add", "-A")
	r.run("commit", "-m", "local change")

	// #when: sync
	err := r.Sync("", "")

	// #then: returns ErrConflict
	require.ErrorIs(t, err, ErrConflict)
}

func TestGitNotInstalled(t *testing.T) {
	// #given: git is not in PATH
	t.Setenv("PATH", t.TempDir()) // empty dir — no git

	// #when: sync
	r := New(t.TempDir())
	err := r.Sync("https://example.com/repo.git", "")

	// #then: returns ErrGitNotInstalled
	require.ErrorIs(t, err, ErrGitNotInstalled)
}

func TestGitignoreContent(t *testing.T) {
	// #given: a new repo after first sync
	bare := helperBareRemote(t)
	configDir := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	r := New(configDir)
	require.NoError(t, os.MkdirAll(filepath.Join(configDir, "kit"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "kit", "kit.json"), []byte(`{}`), 0644))
	require.NoError(t, r.Sync(bare, ""))

	// #when: read .gitignore
	content, err := os.ReadFile(filepath.Join(configDir, ".gitignore"))
	require.NoError(t, err)

	// #then: uses whitelist approach with correct entries
	text := string(content)
	require.Contains(t, text, "*")
	require.Contains(t, text, "!.gitignore")
	require.Contains(t, text, "!vault/")
	require.Contains(t, text, "!vault/vault.age")
	require.Contains(t, text, "!kit/")
	require.Contains(t, text, "!kit/**")
}

func TestCommitMessageFormat(t *testing.T) {
	// #given: an initialized repo with changes
	bare := helperBareRemote(t)
	configDir := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	r := New(configDir)
	require.NoError(t, os.MkdirAll(filepath.Join(configDir, "kit"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "kit", "kit.json"), []byte(`{}`), 0644))
	require.NoError(t, r.Sync(bare, ""))

	// #when: check the commit message
	out, err := r.run("log", "-1", "--format=%s")
	require.NoError(t, err)

	// #then: message matches "sync: yyyy-MM-dd HH:mm:ss"
	msg := strings.TrimSpace(out)
	require.True(t, strings.HasPrefix(msg, "sync: "), "commit message should start with 'sync: ', got: %s", msg)
	// Verify the timestamp part is parseable
	ts := strings.TrimPrefix(msg, "sync: ")
	_, err = time.Parse("2006-01-02 15:04:05", ts)
	require.NoError(t, err, "timestamp should be parseable: %s", ts)
}

func TestCustomCommitMessage(t *testing.T) {
	// #given: an initialized repo with changes
	bare := helperBareRemote(t)
	configDir := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	r := New(configDir)
	require.NoError(t, os.MkdirAll(filepath.Join(configDir, "kit"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "kit", "kit.json"), []byte(`{}`), 0644))

	// #when: sync with custom commit message
	err := r.Sync(bare, "chore: initial setup")

	// #then: commit uses the custom message
	require.NoError(t, err)
	out, err := r.run("log", "-1", "--format=%s")
	require.NoError(t, err)
	require.Equal(t, "chore: initial setup", strings.TrimSpace(out))
}

func TestIsInitialized(t *testing.T) {
	// #given: a non-git directory
	r := New(t.TempDir())

	// #when/#then: not initialized
	require.False(t, r.IsInitialized())

	// #given: after first sync
	bare := helperBareRemote(t)
	configDir := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	r2 := New(configDir)
	require.NoError(t, os.MkdirAll(filepath.Join(configDir, "kit"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "kit", "kit.json"), []byte(`{}`), 0644))
	require.NoError(t, r2.Sync(bare, ""))

	// #when/#then: is initialized
	require.True(t, r2.IsInitialized())
}

func TestExcludedFilesNotTracked(t *testing.T) {
	// #given: config dir with excluded files
	bare := helperBareRemote(t)
	configDir := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.MkdirAll(configDir, 0755))

	// Create files that should be excluded
	require.NoError(t, os.MkdirAll(filepath.Join(configDir, "logs"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "logs", "app.log"), []byte("log"), 0644))
	require.NoError(t, os.MkdirAll(filepath.Join(configDir, "kit"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "kit", ".compile-state.json"), []byte("{}"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "settings.json"), []byte("{}"), 0644))
	require.NoError(t, os.MkdirAll(filepath.Join(configDir, "vault"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "vault", "identity"), []byte("secret"), 0644))

	// Create files that should be tracked
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "kit", "kit.json"), []byte(`{}`), 0644))
	require.NoError(t, os.MkdirAll(filepath.Join(configDir, "kit", "claude-code"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "kit", "claude-code", "settings.json"), []byte(`{}`), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(configDir, "vault", "vault.age"), []byte("encrypted"), 0644))

	// #when: sync
	r := New(configDir)
	require.NoError(t, r.Sync(bare, ""))

	// #then: excluded files are not in the repo
	out, err := r.run("ls-files")
	require.NoError(t, err)

	trackedFiles := strings.Split(strings.TrimSpace(out), "\n")
	trackedSet := make(map[string]bool, len(trackedFiles))
	for _, f := range trackedFiles {
		trackedSet[strings.TrimSpace(f)] = true
	}

	// Excluded files are not present
	require.False(t, trackedSet["logs/app.log"], "logs/app.log should be excluded")
	require.False(t, trackedSet["kit/.compile-state.json"], "kit/.compile-state.json should be excluded")
	require.False(t, trackedSet["settings.json"], "settings.json should be excluded")
	require.False(t, trackedSet["vault/identity"], "vault/identity should be excluded")

	// Tracked files are present
	require.True(t, trackedSet["kit/kit.json"], "kit/kit.json should be tracked")
	require.True(t, trackedSet["kit/claude-code/settings.json"], "kit/claude-code/settings.json should be tracked")
	require.True(t, trackedSet["vault/vault.age"], "vault/vault.age should be tracked")
}
