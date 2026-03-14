package kit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCompileTemplate_VarReplacement(t *testing.T) {
	// #given: a template with var placeholders
	template := "name = {{var.GIT_USER_NAME}}\nemail = {{var.GIT_EMAIL}}"
	vars := map[string]string{
		"GIT_USER_NAME": "Yu",
		"GIT_EMAIL":     "yu@example.com",
	}

	// #when: compiling the template
	result, err := CompileTemplate(context.Background(), template, vars, nil)

	// #then: placeholders are replaced with values
	require.NoError(t, err)
	require.Equal(t, "name = Yu\nemail = yu@example.com", result)
}

func TestCompileTemplate_VaultReplacement(t *testing.T) {
	// #given: a template with vault placeholder and a secret getter
	template := "token = {{vault.GITHUB_TOKEN}}"
	getter := func(_ context.Context, key string) (string, error) {
		if key == "GITHUB_TOKEN" {
			return "ghp_abc123", nil
		}
		return "", fmt.Errorf("not found")
	}

	// #when: compiling the template
	result, err := CompileTemplate(context.Background(), template, nil, getter)

	// #then: vault placeholder is resolved
	require.NoError(t, err)
	require.Equal(t, "token = ghp_abc123", result)
}

func TestCompileTemplate_EnvReplacement(t *testing.T) {
	// #given: a template with env placeholder and an environment variable set
	t.Setenv("DEVCTL_TEST_EDITOR", "vim")
	template := "editor = {{env.DEVCTL_TEST_EDITOR}}"

	// #when: compiling the template
	result, err := CompileTemplate(context.Background(), template, nil, nil)

	// #then: env placeholder is resolved
	require.NoError(t, err)
	require.Equal(t, "editor = vim", result)
}

func TestCompileTemplate_MixedSources(t *testing.T) {
	// #given: a template using all three sources
	t.Setenv("DEVCTL_TEST_HOME", "/home/yu")
	template := "user={{var.NAME}} token={{vault.TOKEN}} home={{env.DEVCTL_TEST_HOME}}"
	vars := map[string]string{"NAME": "Yu"}
	getter := func(_ context.Context, key string) (string, error) {
		if key == "TOKEN" {
			return "secret", nil
		}
		return "", fmt.Errorf("not found")
	}

	// #when: compiling the template
	result, err := CompileTemplate(context.Background(), template, vars, getter)

	// #then: all placeholders are resolved
	require.NoError(t, err)
	require.Equal(t, "user=Yu token=secret home=/home/yu", result)
}

func TestCompileTemplate_EscapedBraces(t *testing.T) {
	// #given: a template with escaped braces
	template := `literal: \{{not.A_PLACEHOLDER}} and {{var.NAME}}`
	vars := map[string]string{"NAME": "Yu"}

	// #when: compiling the template
	result, err := CompileTemplate(context.Background(), template, vars, nil)

	// #then: escaped braces are preserved as literal {{
	require.NoError(t, err)
	require.Equal(t, "literal: {{not.A_PLACEHOLDER}} and Yu", result)
}

func TestCompileTemplate_MissingVar(t *testing.T) {
	// #given: a template referencing a non-existent variable
	template := "name = {{var.MISSING_VAR}}"
	vars := map[string]string{}

	// #when: compiling the template
	_, err := CompileTemplate(context.Background(), template, vars, nil)

	// #then: returns ErrMissingVariables
	require.ErrorIs(t, err, ErrMissingVariables)
	require.Contains(t, err.Error(), "var.MISSING_VAR")
}

func TestCompileTemplate_MissingMultiple(t *testing.T) {
	// #given: a template with multiple missing variables from different sources
	template := "{{var.A}} {{vault.B}} {{env.DEVCTL_TEST_NONEXISTENT_XYZ}}"

	// #when: compiling the template
	_, err := CompileTemplate(context.Background(), template, nil, nil)

	// #then: all missing variables are listed
	require.ErrorIs(t, err, ErrMissingVariables)
	require.Contains(t, err.Error(), "var.A")
	require.Contains(t, err.Error(), "vault.B")
	require.Contains(t, err.Error(), "env.DEVCTL_TEST_NONEXISTENT_XYZ")
}

func TestCompileTemplate_InvalidPlaceholder(t *testing.T) {
	// #given: a template with an invalid placeholder (no prefix)
	template := "value = {{FOO}}"

	// #when: compiling the template
	_, err := CompileTemplate(context.Background(), template, nil, nil)

	// #then: returns ErrInvalidPlaceholder
	require.ErrorIs(t, err, ErrInvalidPlaceholder)
	require.Contains(t, err.Error(), "{{FOO}}")
}

func TestCompileTemplate_NoPlaceholders(t *testing.T) {
	// #given: a template without any placeholders
	template := "plain text content\nno variables here"

	// #when: compiling the template
	result, err := CompileTemplate(context.Background(), template, nil, nil)

	// #then: content is returned unchanged
	require.NoError(t, err)
	require.Equal(t, template, result)
}

func TestCompileTemplate_EmptyTemplate(t *testing.T) {
	// #given: an empty template
	template := ""

	// #when: compiling the template
	result, err := CompileTemplate(context.Background(), template, nil, nil)

	// #then: returns empty string
	require.NoError(t, err)
	require.Equal(t, "", result)
}

func TestCompile_SingleFile(t *testing.T) {
	// #given: a kit with a tracked config template
	dir := t.TempDir()
	kitDir := filepath.Join(dir, "kit")
	targetDir := filepath.Join(dir, "target")
	require.NoError(t, os.MkdirAll(targetDir, 0755))

	k := New(kitDir)
	require.NoError(t, k.SetVar("NAME", "Yu"))

	// Create template source
	sourceDir := filepath.Join(kitDir, "configs")
	require.NoError(t, os.MkdirAll(sourceDir, 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(sourceDir, ".gitconfig"),
		[]byte("[user]\n    name = {{var.NAME}}"),
		0644,
	))

	// Register config in manifest
	m, _ := k.Load()
	targetFile := filepath.Join(targetDir, ".gitconfig")
	m.Configs[".gitconfig"] = ConfigEntry{
		Source: "configs/.gitconfig",
		Target: targetFile,
	}
	require.NoError(t, k.Save(m))

	// #when: compiling the config
	err := k.Compile(context.Background(), ".gitconfig", nil)

	// #then: target file is written with resolved values
	require.NoError(t, err)
	content, err := os.ReadFile(targetFile)
	require.NoError(t, err)
	require.Equal(t, "[user]\n    name = Yu", string(content))

	// #then: compile state is updated
	state, err := k.loadCompileState()
	require.NoError(t, err)
	require.Contains(t, state, ".gitconfig")
	require.Contains(t, state[".gitconfig"].Hash, "sha256:")
}

func TestCompile_Directory(t *testing.T) {
	// #given: a kit with a tracked directory config
	dir := t.TempDir()
	kitDir := filepath.Join(dir, "kit")
	targetDir := filepath.Join(dir, "target", "nvim")

	k := New(kitDir)
	require.NoError(t, k.SetVar("THEME", "dark"))

	// Create template directory
	sourceDir := filepath.Join(kitDir, "configs", "nvim")
	require.NoError(t, os.MkdirAll(filepath.Join(sourceDir, "lua"), 0755))
	require.NoError(t, os.WriteFile(
		filepath.Join(sourceDir, "init.lua"),
		[]byte("vim.g.theme = '{{var.THEME}}'"),
		0644,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(sourceDir, "lua", "plugins.lua"),
		[]byte("-- plugins"),
		0644,
	))

	// Register config
	m, _ := k.loadOrInit()
	m.Configs["nvim"] = ConfigEntry{
		Source: "configs/nvim",
		Target: targetDir,
	}
	require.NoError(t, k.Save(m))

	// #when: compiling the directory config
	err := k.Compile(context.Background(), "nvim", nil)

	// #then: all files are compiled to target
	require.NoError(t, err)

	content, err := os.ReadFile(filepath.Join(targetDir, "init.lua"))
	require.NoError(t, err)
	require.Equal(t, "vim.g.theme = 'dark'", string(content))

	content, err = os.ReadFile(filepath.Join(targetDir, "lua", "plugins.lua"))
	require.NoError(t, err)
	require.Equal(t, "-- plugins", string(content))
}

func TestCompile_NotTracked(t *testing.T) {
	// #given: a kit with no tracked configs
	k := New(filepath.Join(t.TempDir(), "kit"))
	require.NoError(t, k.SetVar("X", "y")) // create manifest

	// #when: compiling a non-existent config
	err := k.Compile(context.Background(), "missing", nil)

	// #then: returns ErrNotTracked
	require.ErrorIs(t, err, ErrNotTracked)
}

func TestCompileAll(t *testing.T) {
	// #given: a kit with multiple tracked configs (one valid, one with missing var)
	dir := t.TempDir()
	kitDir := filepath.Join(dir, "kit")
	targetDir := filepath.Join(dir, "target")
	require.NoError(t, os.MkdirAll(targetDir, 0755))

	k := New(kitDir)
	require.NoError(t, k.SetVar("NAME", "Yu"))

	sourceDir := filepath.Join(kitDir, "configs")
	require.NoError(t, os.MkdirAll(sourceDir, 0755))

	// Good template
	require.NoError(t, os.WriteFile(
		filepath.Join(sourceDir, "good.conf"),
		[]byte("name={{var.NAME}}"),
		0644,
	))
	// Bad template (missing variable)
	require.NoError(t, os.WriteFile(
		filepath.Join(sourceDir, "bad.conf"),
		[]byte("val={{var.MISSING}}"),
		0644,
	))

	m, _ := k.Load()
	m.Configs["good"] = ConfigEntry{Source: "configs/good.conf", Target: filepath.Join(targetDir, "good.conf")}
	m.Configs["bad"] = ConfigEntry{Source: "configs/bad.conf", Target: filepath.Join(targetDir, "bad.conf")}
	require.NoError(t, k.Save(m))

	// #when: compiling all
	successes, failures := k.CompileAll(context.Background(), nil)

	// #then: good config succeeds, bad config fails independently
	require.Equal(t, []string{"good"}, successes)
	require.Contains(t, failures, "bad")
}

func TestConfigStatuses(t *testing.T) {
	// #given: a kit with compiled, outdated, and uncompiled configs
	dir := t.TempDir()
	kitDir := filepath.Join(dir, "kit")
	targetDir := filepath.Join(dir, "target")
	require.NoError(t, os.MkdirAll(targetDir, 0755))

	k := New(kitDir)
	require.NoError(t, k.SetVar("V", "1"))

	sourceDir := filepath.Join(kitDir, "configs")
	require.NoError(t, os.MkdirAll(sourceDir, 0755))

	// Compiled config
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "compiled.conf"), []byte("v={{var.V}}"), 0644))
	// Uncompiled config
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "uncompiled.conf"), []byte("x=1"), 0644))

	m, _ := k.Load()
	m.Configs["compiled"] = ConfigEntry{Source: "configs/compiled.conf", Target: filepath.Join(targetDir, "compiled.conf")}
	m.Configs["uncompiled"] = ConfigEntry{Source: "configs/uncompiled.conf", Target: filepath.Join(targetDir, "uncompiled.conf")}
	require.NoError(t, k.Save(m))

	// Compile the first one
	require.NoError(t, k.Compile(context.Background(), "compiled", nil))

	// #when: getting config statuses
	statuses, err := k.ConfigStatuses()

	// #then: correctly identifies compiled and uncompiled
	require.NoError(t, err)
	require.Len(t, statuses, 2)

	statusMap := make(map[string]ConfigState)
	for _, s := range statuses {
		statusMap[s.Name] = s.State
	}
	require.Equal(t, ConfigStateCompiled, statusMap["compiled"])
	require.Equal(t, ConfigStateUncompiled, statusMap["uncompiled"])
}
