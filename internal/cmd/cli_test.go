package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"devctl/internal/build"
)

func TestRootHelpVersionAndRemovedCommands(t *testing.T) {
	// #given: a config directory that is not the user home
	home := t.TempDir()
	configDir := t.TempDir()

	cases := []struct {
		name     string
		args     []string
		code     int
		outHas   string
		outLacks []string
	}{
		{
			name:     "no args",
			code:     0,
			outHas:   "Development CLI",
			outLacks: []string{"kit", "vault", "config", "sync", "Core Commands"},
		},
		{
			name:     "help",
			args:     []string{"--help"},
			code:     0,
			outHas:   "Development CLI",
			outLacks: []string{"kit", "vault", "config", "sync", "Core Commands"},
		},
		{
			name:   "version",
			args:   []string{"--version"},
			code:   0,
			outHas: build.FormatVersion() + "\n",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			// #when: the root command runs
			code, stdout, stderr := runCLI(t, home, configDir, tt.args...)
			combined := stdout + stderr

			// #then: the exit code and output match the retained root
			if code != tt.code {
				t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
			}
			if !strings.Contains(combined, tt.outHas) {
				t.Fatalf("output %q does not contain %q", combined, tt.outHas)
			}
			for _, word := range tt.outLacks {
				if strings.Contains(combined, word) {
					t.Fatalf("output %q still contains %q", combined, word)
				}
			}
		})
	}
}

func TestRemovedCommandsAreUnknown(t *testing.T) {
	home := t.TempDir()
	configDir := t.TempDir()
	for _, name := range []string{"kit", "vault", "config", "sync"} {
		t.Run(name, func(t *testing.T) {
			// #given: a removed command name
			// #when: it is invoked
			code, stdout, stderr := runCLI(t, home, configDir, name)

			// #then: the command is rejected
			if code == 0 {
				t.Fatalf("exit 0, stdout %q, stderr %q", stdout, stderr)
			}
			if !strings.Contains(stdout+stderr, "unknown command") {
				t.Fatalf("stdout %q stderr %q", stdout, stderr)
			}
		})
	}
}

func TestBaseCommandsDoNotCreateBusinessData(t *testing.T) {
	commands := [][]string{nil, {"--help"}, {"--version"}, {"kit"}, {"vault"}, {"config"}, {"sync"}}
	for _, args := range commands {
		name := "no-args"
		if len(args) > 0 {
			name = strings.Join(args, " ")
		}
		t.Run(name, func(t *testing.T) {
			// #given: empty home and config directories
			home := t.TempDir()
			configDir := t.TempDir()

			// #when: a root invocation finishes
			_, _, _ = runCLI(t, home, configDir, args...)

			// #then: historical business files are absent from both directories
			for _, root := range []string{home, configDir} {
				assertNoBusinessData(t, root)
			}
		})
	}
}

func assertNoBusinessData(t *testing.T, root string) {
	t.Helper()
	forbidden := map[string]bool{
		"kit":              true,
		"vault":            true,
		"settings.json":    true,
		".git":             true,
		".sync-state.json": true,
		"vault.age":        true,
		"kit.json":         true,
	}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		if forbidden[d.Name()] {
			return fmt.Errorf("created %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(homeDevctl(root))); err == nil {
		t.Fatalf("created %s", homeDevctl(root))
	}
}

func homeDevctl(root string) string {
	return filepath.Join(root, ".devctl")
}

func runCLI(t *testing.T, home, configDir string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestDevctlHelper$")
	cmd.Env = cliEnv(home, configDir, args)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return 0, stdout.String(), stderr.String()
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), stdout.String(), stderr.String()
	}
	t.Fatalf("run cli: %v", err)
	return 0, "", ""
}

func cliEnv(home, configDir string, args []string) []string {
	overrides := map[string]bool{
		"HOME": true, "USERPROFILE": true, "DEVCTL_CONFIG_DIR": true,
		"DEVCTL_DEBUG": true, "DEVCTL_SECRET_KEY": true,
		"DEVCTL_HELPER": true, "DEVCTL_HELPER_ARGS": true,
	}
	env := []string{
		"HOME=" + home,
		"USERPROFILE=" + home,
		"DEVCTL_CONFIG_DIR=" + configDir,
		"DEVCTL_HELPER=1",
		"DEVCTL_HELPER_ARGS=" + strings.Join(args, "\x1f"),
	}
	for _, kv := range os.Environ() {
		key, _, _ := strings.Cut(kv, "=")
		if overrides[key] {
			continue
		}
		env = append(env, kv)
	}
	return env
}

func TestDevctlHelper(t *testing.T) {
	if os.Getenv("DEVCTL_HELPER") != "1" {
		return
	}
	var args []string
	if raw := os.Getenv("DEVCTL_HELPER_ARGS"); raw != "" {
		args = strings.Split(raw, "\x1f")
	}
	os.Args = append([]string{"devctl"}, args...)
	command, err := NewCmdRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := command.Execute(); err != nil {
		var cerr *CommandError
		if errors.As(err, &cerr) {
			os.Exit(cerr.ExitCode)
		}
		os.Exit(1)
	}
	os.Exit(0)
}
