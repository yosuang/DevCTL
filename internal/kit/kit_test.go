package kit

import (
	"path/filepath"
	"testing"

	"devctl/pkg/pkgmgr"

	"github.com/stretchr/testify/require"
)

func TestSetVar(t *testing.T) {
	// #given: an empty kit directory
	k := New(filepath.Join(t.TempDir(), "kit"))

	// #when: setting a variable
	err := k.SetVar("GIT_USER_NAME", "Yu")

	// #then: succeeds and value is persisted
	require.NoError(t, err)
	m, err := k.Load()
	require.NoError(t, err)
	require.Equal(t, "Yu", m.Vars["GIT_USER_NAME"])
}

func TestSetVar_InvalidKey(t *testing.T) {
	// #given: a kit instance
	k := New(filepath.Join(t.TempDir(), "kit"))

	// #when: setting a variable with an invalid key
	err := k.SetVar("invalid_key", "value")

	// #then: returns ErrInvalidKeyName
	require.ErrorIs(t, err, ErrInvalidKeyName)
}

func TestSetVar_Overwrite(t *testing.T) {
	// #given: a kit with an existing variable
	k := New(filepath.Join(t.TempDir(), "kit"))
	require.NoError(t, k.SetVar("MY_VAR", "old"))

	// #when: overwriting the variable
	err := k.SetVar("MY_VAR", "new")

	// #then: the new value is stored
	require.NoError(t, err)
	m, err := k.Load()
	require.NoError(t, err)
	require.Equal(t, "new", m.Vars["MY_VAR"])
}

func TestUnsetVar(t *testing.T) {
	// #given: a kit with a variable
	k := New(filepath.Join(t.TempDir(), "kit"))
	require.NoError(t, k.SetVar("MY_VAR", "val"))

	// #when: unsetting the variable
	err := k.UnsetVar("MY_VAR")

	// #then: the variable is removed
	require.NoError(t, err)
	m, err := k.Load()
	require.NoError(t, err)
	require.NotContains(t, m.Vars, "MY_VAR")
}

func TestUnsetVar_NotFound(t *testing.T) {
	// #given: a kit with no variables
	k := New(filepath.Join(t.TempDir(), "kit"))
	require.NoError(t, k.SetVar("OTHER", "val"))

	// #when: unsetting a non-existent variable
	err := k.UnsetVar("MISSING")

	// #then: returns an error
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

func TestAddPackage(t *testing.T) {
	// #given: an empty kit
	k := New(filepath.Join(t.TempDir(), "kit"))

	// #when: adding a package without group
	err := k.AddPackage("git", "1.28", "", "")

	// #then: added to "base" group
	require.NoError(t, err)
	m, err := k.Load()
	require.NoError(t, err)
	require.Len(t, m.Packages["base"], 1)
	require.Equal(t, "git", m.Packages["base"][0].Name)
	require.Equal(t, "1.28", m.Packages["base"][0].Version)
}

func TestAddPackage_WithGroup(t *testing.T) {
	// #given: an empty kit
	k := New(filepath.Join(t.TempDir(), "kit"))

	// #when: adding a package to a specific group
	err := k.AddPackage("kubectl", "", "work", "")

	// #then: added to the specified group
	require.NoError(t, err)
	m, err := k.Load()
	require.NoError(t, err)
	require.Len(t, m.Packages["work"], 1)
	require.Equal(t, "kubectl", m.Packages["work"][0].Name)
	require.Empty(t, m.Packages["work"][0].Version)
}

func TestAddPackage_Duplicate(t *testing.T) {
	// #given: a kit with an existing package
	k := New(filepath.Join(t.TempDir(), "kit"))
	require.NoError(t, k.AddPackage("git", "", "", ""))

	// #when: adding the same package again
	err := k.AddPackage("git", "2.0", "", "")

	// #then: returns ErrPackageExists
	require.ErrorIs(t, err, ErrPackageExists)
}

func TestRemovePackage(t *testing.T) {
	// #given: a kit with packages
	k := New(filepath.Join(t.TempDir(), "kit"))
	require.NoError(t, k.AddPackage("git", "", "", ""))
	require.NoError(t, k.AddPackage("jq", "", "", ""))

	// #when: removing one package
	err := k.RemovePackage("git", "")

	// #then: only the removed package is gone
	require.NoError(t, err)
	m, err := k.Load()
	require.NoError(t, err)
	require.Len(t, m.Packages["base"], 1)
	require.Equal(t, "jq", m.Packages["base"][0].Name)
}

func TestRemovePackage_LastInGroup(t *testing.T) {
	// #given: a kit with one package in a group
	k := New(filepath.Join(t.TempDir(), "kit"))
	require.NoError(t, k.AddPackage("git", "", "", ""))

	// #when: removing the last package in the group
	err := k.RemovePackage("git", "")

	// #then: the group is removed entirely
	require.NoError(t, err)
	m, err := k.Load()
	require.NoError(t, err)
	require.NotContains(t, m.Packages, "base")
}

func TestRemovePackage_NotFound(t *testing.T) {
	// #given: a kit with packages
	k := New(filepath.Join(t.TempDir(), "kit"))
	require.NoError(t, k.AddPackage("git", "", "", ""))

	// #when: removing a non-existent package
	err := k.RemovePackage("vim", "")

	// #then: returns ErrPackageNotFound
	require.ErrorIs(t, err, ErrPackageNotFound)
}

func TestListVars(t *testing.T) {
	// #given: a kit with multiple variables
	k := New(filepath.Join(t.TempDir(), "kit"))
	require.NoError(t, k.SetVar("CHARLIE", "c"))
	require.NoError(t, k.SetVar("ALPHA", "a"))
	require.NoError(t, k.SetVar("BRAVO", "b"))

	// #when: listing variables
	keys, vals, err := k.ListVars()

	// #then: returned sorted alphabetically
	require.NoError(t, err)
	require.Equal(t, []string{"ALPHA", "BRAVO", "CHARLIE"}, keys)
	require.Equal(t, []string{"a", "b", "c"}, vals)
}

func TestCheckPackageStatuses(t *testing.T) {
	// #given: desired packages and installed packages
	desired := []PackageEntry{
		{Name: "git", Version: "1.28"},
		{Name: "jq"},
		{Name: "vim"},
	}
	installed := []pkgmgr.Package{
		{Name: "git", Version: "1.28.0"},
		{Name: "vim", Version: "9.0"},
	}

	// #when: checking statuses
	statuses := CheckPackageStatuses(desired, installed)

	// #then: correctly identifies installed and missing packages
	require.Len(t, statuses, 3)
	require.True(t, statuses[0].Installed)
	require.Equal(t, "1.28.0", statuses[0].InstalledVersion)
	require.False(t, statuses[1].Installed)
	require.True(t, statuses[2].Installed)
}

func TestLoad_NotFound(t *testing.T) {
	// #given: a non-existent kit directory
	k := New(filepath.Join(t.TempDir(), "nonexistent"))

	// #when: loading the manifest
	_, err := k.Load()

	// #then: returns ErrManifestNotFound
	require.ErrorIs(t, err, ErrManifestNotFound)
}

func TestAddPackage_WithManager(t *testing.T) {
	// #given: an empty kit
	k := New(filepath.Join(t.TempDir(), "kit"))

	// #when: adding a package with a specific manager
	err := k.AddPackage("git", "2.40", "", "scoop")

	// #then: manager is persisted in manifest
	require.NoError(t, err)
	m, err := k.Load()
	require.NoError(t, err)
	require.Len(t, m.Packages["base"], 1)
	require.Equal(t, "git", m.Packages["base"][0].Name)
	require.Equal(t, "2.40", m.Packages["base"][0].Version)
	require.Equal(t, "scoop", m.Packages["base"][0].Manager)
}

func TestLoad_BackwardCompat_NoManager(t *testing.T) {
	// #given: a manifest saved without the manager field (old format)
	k := New(filepath.Join(t.TempDir(), "kit"))
	m := &Manifest{
		Vars:     map[string]string{},
		Packages: map[string][]PackageEntry{"base": {{Name: "git", Version: "2.40"}}},
		Configs:  map[string]ConfigEntry{},
	}
	require.NoError(t, k.Save(m))

	// #when: loading the manifest
	loaded, err := k.Load()

	// #then: manager defaults to empty string
	require.NoError(t, err)
	require.Equal(t, "", loaded.Packages["base"][0].Manager)
}

func TestSaveAndLoad(t *testing.T) {
	// #given: a manifest with all fields
	k := New(filepath.Join(t.TempDir(), "kit"))
	m := &Manifest{
		Vars:     map[string]string{"KEY": "val"},
		Packages: map[string][]PackageEntry{"base": {{Name: "git"}}},
		Configs:  map[string]ConfigEntry{"claude-code": {TargetDir: "~/.claude/", Mode: DefaultConfigMode}},
	}

	// #when: saving and loading
	require.NoError(t, k.Save(m))
	loaded, err := k.Load()

	// #then: all fields are preserved
	require.NoError(t, err)
	require.Equal(t, m.Vars, loaded.Vars)
	require.Equal(t, m.Packages, loaded.Packages)
	require.Equal(t, m.Configs, loaded.Configs)
}
