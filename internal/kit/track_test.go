package kit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTrack_SingleFile(t *testing.T) {
	// #given: an existing file to track
	dir := t.TempDir()
	kitDir := filepath.Join(dir, "kit")
	targetFile := filepath.Join(dir, "source", ".claude", "settings.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(targetFile), 0755))
	require.NoError(t, os.WriteFile(targetFile, []byte(`{"key":"val"}`), 0644))

	k := New(kitDir)

	// #when: tracking the file with a name
	err := k.Track(targetFile, "claude-code", "")

	// #then: file is copied to kit/<name>/ and manifest is updated
	require.NoError(t, err)

	m, err := k.Load()
	require.NoError(t, err)
	require.Contains(t, m.Configs, "claude-code")
	require.Equal(t, DefaultConfigMode, m.Configs["claude-code"].Mode)

	// Verify the source file was copied into kit/claude-code/
	copied, err := os.ReadFile(filepath.Join(kitDir, "claude-code", "settings.json"))
	require.NoError(t, err)
	require.Equal(t, `{"key":"val"}`, string(copied))
}

func TestTrack_Directory(t *testing.T) {
	// #given: an existing directory to track
	dir := t.TempDir()
	kitDir := filepath.Join(dir, "kit")
	targetDir := filepath.Join(dir, "source", "opencode")
	require.NoError(t, os.MkdirAll(targetDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(targetDir, "opencode.jsonc"), []byte("// config"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(targetDir, "tui.json"), []byte(`{"theme":"dark"}`), 0644))

	k := New(kitDir)

	// #when: tracking the directory with a name
	err := k.Track(targetDir, "opencode", "")

	// #then: directory contents are copied to kit/<name>/ and manifest is updated
	require.NoError(t, err)

	m, err := k.Load()
	require.NoError(t, err)
	require.Contains(t, m.Configs, "opencode")
	require.Equal(t, DefaultConfigMode, m.Configs["opencode"].Mode)

	// Verify files were copied
	content, err := os.ReadFile(filepath.Join(kitDir, "opencode", "opencode.jsonc"))
	require.NoError(t, err)
	require.Equal(t, "// config", string(content))

	content, err = os.ReadFile(filepath.Join(kitDir, "opencode", "tui.json"))
	require.NoError(t, err)
	require.Equal(t, `{"theme":"dark"}`, string(content))
}

func TestTrack_OverwriteExisting(t *testing.T) {
	// #given: a file that is already tracked
	dir := t.TempDir()
	kitDir := filepath.Join(dir, "kit")
	targetFile := filepath.Join(dir, "source", ".claude", "settings.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(targetFile), 0755))
	require.NoError(t, os.WriteFile(targetFile, []byte("old"), 0644))

	k := New(kitDir)
	require.NoError(t, k.Track(targetFile, "claude-code", ""))

	// #when: updating the file and tracking again with the same name
	require.NoError(t, os.WriteFile(targetFile, []byte("new"), 0644))
	err := k.Track(targetFile, "claude-code", "")

	// #then: succeeds and file is updated
	require.NoError(t, err)
	copied, err := os.ReadFile(filepath.Join(kitDir, "claude-code", "settings.json"))
	require.NoError(t, err)
	require.Equal(t, "new", string(copied))
}

func TestTrack_ExpandsEnvVar(t *testing.T) {
	// #given: a file referenced via an environment variable in the path
	dir := t.TempDir()
	kitDir := filepath.Join(dir, "kit")
	homeDir := filepath.Join(dir, "fakehome")
	targetFile := filepath.Join(homeDir, ".claude", "settings.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(targetFile), 0755))
	require.NoError(t, os.WriteFile(targetFile, []byte(`{"key":"val"}`), 0644))

	t.Setenv("TEST_DEVCTL_HOME", homeDir)

	k := New(kitDir)

	// #when: tracking using $ENV_VAR in the path
	err := k.Track("$TEST_DEVCTL_HOME/.claude/settings.json", "claude-code", "")

	// #then: the env var is expanded and file is tracked successfully
	require.NoError(t, err)

	m, err := k.Load()
	require.NoError(t, err)
	require.Contains(t, m.Configs, "claude-code")

	copied, err := os.ReadFile(filepath.Join(kitDir, "claude-code", "settings.json"))
	require.NoError(t, err)
	require.Equal(t, `{"key":"val"}`, string(copied))
}

func TestUntrack(t *testing.T) {
	// #given: a tracked config
	dir := t.TempDir()
	kitDir := filepath.Join(dir, "kit")
	targetFile := filepath.Join(dir, "source", ".claude", "settings.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(targetFile), 0755))
	require.NoError(t, os.WriteFile(targetFile, []byte("content"), 0644))

	k := New(kitDir)
	require.NoError(t, k.Track(targetFile, "claude-code", ""))

	// #when: untracking the config
	err := k.Untrack("claude-code")

	// #then: config is removed from manifest
	require.NoError(t, err)
	m, err := k.Load()
	require.NoError(t, err)
	require.NotContains(t, m.Configs, "claude-code")

	// #then: source files are NOT deleted
	require.FileExists(t, filepath.Join(kitDir, "claude-code", "settings.json"))
}

func TestUntrack_NotTracked(t *testing.T) {
	// #given: a kit with no tracked configs
	k := New(filepath.Join(t.TempDir(), "kit"))
	require.NoError(t, k.SetVar("X", "y")) // create manifest

	// #when: untracking a non-existent config
	err := k.Untrack("missing")

	// #then: returns ErrNotTracked
	require.ErrorIs(t, err, ErrNotTracked)
}
