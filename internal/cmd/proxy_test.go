package cmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProxyCommandsLeaveRootLoggingHook(t *testing.T) {
	// #given the root command
	// #when proxy, start, and stop are inspected
	// #then they leave the root logging hook in place
	root, err := NewCmdRoot()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"proxy", "start", "stop"} {
		cmd := commandByName(root, name)
		if cmd == nil {
			t.Fatalf("missing %s", name)
		}
		if cmd.PersistentPreRun != nil || cmd.PersistentPreRunE != nil {
			t.Fatalf("%s replaced the root hook", name)
		}
	}
	if root.PersistentPreRunE == nil {
		t.Fatal("root hook")
	}
	start := commandByName(root, "start")
	if start.Flags().Lookup("core") == nil || start.Flags().Lookup("ticket") == nil {
		t.Fatal("flags")
	}
	if commandByName(root, "stop").Flags().Lookup("ticket") == nil {
		t.Fatal("stop ticket")
	}
}

func TestProxyHelpAndFlags(t *testing.T) {
	// #given the pairing command group
	// #when help and rejected flags are requested
	// #then proxy follows pair and does not take a coordinator
	root, err := NewCmdRoot()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	pairAt := strings.Index(text, "Pair two computers")
	proxyAt := strings.Index(text, "Run the local proxy")
	if !strings.Contains(text, "Pairing:") || pairAt < 0 || proxyAt < 0 || pairAt > proxyAt {
		t.Fatal("help order")
	}

	out.Reset()
	root.SetArgs([]string{"proxy", "start", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	help := out.String()
	if !strings.Contains(help, "--core") || !strings.Contains(help, "--ticket") || strings.Contains(help, "--coordinator") {
		t.Fatal("start help")
	}

	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	for _, args := range [][]string{
		{"proxy", "start"},
		{"proxy", "stop", "now"},
		{"proxy", "start", "--coordinator", "http://127.0.0.1:9", "--core", "/no/such/core"},
	} {
		next, err := NewCmdRoot()
		if err != nil {
			t.Fatal(err)
		}
		next.SetOut(io.Discard)
		next.SetErr(io.Discard)
		next.SetArgs(args)
		err = next.Execute()
		switch args[len(args)-1] {
		case "start":
			if err == nil || !strings.Contains(err.Error(), "core") {
				t.Fatalf("required %v", err)
			}
		case "now":
			if err == nil {
				t.Fatal("args")
			}
		default:
			if err == nil || !strings.Contains(err.Error(), "coordinator") {
				t.Fatalf("coordinator %v", err)
			}
		}
	}
}

func TestProxyRunUsesRootHook(t *testing.T) {
	// #given a config directory that holds a copy
	// #when start is missing its executable and stop sees a dead runtime
	// #then the root log is created and the runtime directory is removed
	root, err := NewCmdRoot()
	if err != nil {
		t.Fatal(err)
	}
	prevDir := cfg.ConfigDir
	prevDebug := cfg.Debug
	dir := t.TempDir()
	cfg.ConfigDir = dir
	cfg.Debug = false
	t.Cleanup(func() {
		cfg.ConfigDir = prevDir
		cfg.Debug = prevDebug
	})
	copyDir := filepath.Join(dir, "pair", "ticket-"+strings.Repeat("ab", 32))
	if err := os.MkdirAll(copyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(copyDir, "copy"), []byte("hysteria2://example-auth-not-a-secret@192.0.2.1:443/"), 0o600); err != nil {
		t.Fatal(err)
	}
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"proxy", "start", "--core", filepath.Join(dir, "missing-core")})
	err = root.Execute()
	if err == nil || !strings.Contains(err.Error(), "core_missing") {
		t.Fatalf("start %v", err)
	}
	logBody, err := os.ReadFile(filepath.Join(dir, "logs", "devctl.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logBody), "example-auth-not-a-secret") {
		t.Fatal("log")
	}

	runtimeDir := filepath.Join(dir, "proxy", "ticket-"+strings.Repeat("cd", 32))
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtimeDir, "pid"), []byte("0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runtimeDir, "config.yaml"), []byte("password: example-auth-not-a-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root.SetArgs([]string{"proxy", "stop"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	if _, statErr := os.Stat(runtimeDir); !os.IsNotExist(statErr) {
		t.Fatal("runtime remains")
	}
	if _, statErr := os.Stat(filepath.Join(copyDir, "copy")); statErr != nil {
		t.Fatal("copy")
	}
	logBody, err = os.ReadFile(filepath.Join(dir, "logs", "devctl.log"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logBody), "example-auth-not-a-secret") {
		t.Fatal("log")
	}
}
