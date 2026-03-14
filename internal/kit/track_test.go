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
	targetFile := filepath.Join(dir, "source", ".gitconfig")
	require.NoError(t, os.MkdirAll(filepath.Dir(targetFile), 0755))
	require.NoError(t, os.WriteFile(targetFile, []byte("[user]\n    name = Yu"), 0644))

	k := New(kitDir)

	// #when: tracking the file
	err := k.Track(targetFile)

	// #then: file is copied to configs and manifest is updated
	require.NoError(t, err)

	m, err := k.Load()
	require.NoError(t, err)
	require.Contains(t, m.Configs, ".gitconfig")
	require.Equal(t, filepath.Join("configs", ".gitconfig"), m.Configs[".gitconfig"].Source)

	// Verify the source file was copied
	copied, err := os.ReadFile(filepath.Join(kitDir, "configs", ".gitconfig"))
	require.NoError(t, err)
	require.Equal(t, "[user]\n    name = Yu", string(copied))
}

func TestTrack_Directory(t *testing.T) {
	// #given: an existing directory to track
	dir := t.TempDir()
	kitDir := filepath.Join(dir, "kit")
	targetDir := filepath.Join(dir, "source", "nvim")
	require.NoError(t, os.MkdirAll(filepath.Join(targetDir, "lua"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(targetDir, "init.lua"), []byte("-- init"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(targetDir, "lua", "plugins.lua"), []byte("-- plugins"), 0644))

	k := New(kitDir)

	// #when: tracking the directory
	err := k.Track(targetDir)

	// #then: directory is copied recursively and manifest is updated
	require.NoError(t, err)

	m, err := k.Load()
	require.NoError(t, err)
	require.Contains(t, m.Configs, "nvim")
	require.Equal(t, filepath.Join("configs", "nvim"), m.Configs["nvim"].Source)

	// Verify files were copied
	content, err := os.ReadFile(filepath.Join(kitDir, "configs", "nvim", "init.lua"))
	require.NoError(t, err)
	require.Equal(t, "-- init", string(content))

	content, err = os.ReadFile(filepath.Join(kitDir, "configs", "nvim", "lua", "plugins.lua"))
	require.NoError(t, err)
	require.Equal(t, "-- plugins", string(content))
}

func TestTrack_AlreadyTracked(t *testing.T) {
	// #given: a file that is already tracked
	dir := t.TempDir()
	kitDir := filepath.Join(dir, "kit")
	targetFile := filepath.Join(dir, "source", ".gitconfig")
	require.NoError(t, os.MkdirAll(filepath.Dir(targetFile), 0755))
	require.NoError(t, os.WriteFile(targetFile, []byte("content"), 0644))

	k := New(kitDir)
	require.NoError(t, k.Track(targetFile))

	// #when: tracking the same file again
	err := k.Track(targetFile)

	// #then: returns ErrAlreadyTracked
	require.ErrorIs(t, err, ErrAlreadyTracked)
}

func TestTrack_BasenamCollision(t *testing.T) {
	// #given: a file with a basename that already exists as a tracked key
	dir := t.TempDir()
	kitDir := filepath.Join(dir, "kit")

	// Track first .gitconfig
	firstDir := filepath.Join(dir, "first")
	require.NoError(t, os.MkdirAll(firstDir, 0755))
	firstFile := filepath.Join(firstDir, ".gitconfig")
	require.NoError(t, os.WriteFile(firstFile, []byte("first"), 0644))

	k := New(kitDir)
	require.NoError(t, k.Track(firstFile))

	// Track second .gitconfig from a different directory
	secondDir := filepath.Join(dir, "second")
	require.NoError(t, os.MkdirAll(secondDir, 0755))
	secondFile := filepath.Join(secondDir, ".gitconfig")
	require.NoError(t, os.WriteFile(secondFile, []byte("second"), 0644))

	// #when: tracking the second file with the same basename
	err := k.Track(secondFile)

	// #then: the key is disambiguated using parent directory
	require.NoError(t, err)

	m, err := k.Load()
	require.NoError(t, err)
	require.Contains(t, m.Configs, ".gitconfig")
	require.Contains(t, m.Configs, "second-.gitconfig")
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

	// #when: tracking using $ENV_VAR in the path (simulating unexpanded shell variable)
	err := k.Track("$TEST_DEVCTL_HOME/.claude/settings.json")

	// #then: the env var is expanded and file is tracked successfully
	require.NoError(t, err)

	m, err := k.Load()
	require.NoError(t, err)
	require.Contains(t, m.Configs, "settings.json")

	copied, err := os.ReadFile(filepath.Join(kitDir, "configs", "settings.json"))
	require.NoError(t, err)
	require.Equal(t, `{"key":"val"}`, string(copied))
}

func TestUntrack(t *testing.T) {
	// #given: a tracked config
	dir := t.TempDir()
	kitDir := filepath.Join(dir, "kit")
	targetFile := filepath.Join(dir, "source", ".gitconfig")
	require.NoError(t, os.MkdirAll(filepath.Dir(targetFile), 0755))
	require.NoError(t, os.WriteFile(targetFile, []byte("content"), 0644))

	k := New(kitDir)
	require.NoError(t, k.Track(targetFile))

	// #when: untracking the config
	err := k.Untrack(".gitconfig")

	// #then: config is removed from manifest
	require.NoError(t, err)
	m, err := k.Load()
	require.NoError(t, err)
	require.NotContains(t, m.Configs, ".gitconfig")

	// #then: source file is NOT deleted
	require.FileExists(t, filepath.Join(kitDir, "configs", ".gitconfig"))
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
