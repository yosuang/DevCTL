package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// exampleURI is a fixture, not a credential.
const exampleURI = "hysteria2://example-auth-not-a-secret@192.0.2.1:443/?sni=example.invalid"

const exampleAuth = "example-auth-not-a-secret"

var (
	corePath  string
	listenRE  = regexp.MustCompile(`^listening 127\.0\.0\.1:[1-9][0-9]*\n$`)
	localCall = regexp.MustCompile(`local\("([a-z0-9_]+)"`)
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "devctl-proxy-core")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o700); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte("module core\n\ngo 1.26.3\n"), 0o600); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte(coreProgram), 0o600); err != nil {
		panic(err)
	}
	corePath = filepath.Join(dir, "core")
	cmd := exec.Command("go", "build", "-o", corePath, ".")
	cmd.Dir = src
	cmd.Env = append(withoutGOFLAGS(os.Environ()), "CGO_ENABLED=0", "GO111MODULE=on")
	out, err := cmd.CombinedOutput()
	if err != nil {
		panic(string(out) + err.Error())
	}
	os.Exit(m.Run())
}

func TestSchemesMatchVocabulary(t *testing.T) {
	// #given the scheme list in v1.json
	// #when the writer maps a URI scheme
	// #then the map keys are that list and every value is hysteria2
	var vocab struct {
		Schemes []string `json:"uri_schemes"`
	}
	if err := json.Unmarshal(readVocabulary(t), &vocab); err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(outboundType))
	for scheme, kind := range outboundType {
		got = append(got, scheme)
		if kind != "hysteria2" {
			t.Fatalf("kind %s", scheme)
		}
	}
	slices.Sort(got)
	slices.Sort(vocab.Schemes)
	if !slices.Equal(got, vocab.Schemes) {
		t.Fatalf("schemes %v", got)
	}
}

func TestLocalCodesMatchVocabulary(t *testing.T) {
	// #given the local error names in v1.json
	// #when this package reports a coded error
	// #then the code is one of those names
	var vocab struct {
		Errors struct {
			Local []string `json:"local"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(readVocabulary(t), &vocab); err != nil {
		t.Fatal(err)
	}
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	entries, err := os.ReadDir(filepath.Dir(file))
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(filepath.Dir(file), name))
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range localCall.FindAllSubmatch(body, -1) {
			code := string(match[1])
			found[code] = true
			if !slices.Contains(vocab.Errors.Local, code) {
				t.Fatalf("%s uses %s", name, code)
			}
		}
	}
	for _, code := range []string{"core_missing", "uri_invalid", "uri_unsupported", "copy_incomplete", "ticket_ambiguous"} {
		if !found[code] {
			t.Fatalf("missing %s", code)
		}
	}
}

func TestRenderURI(t *testing.T) {
	// #given a taken-over URI
	// #when the runtime config is rendered
	// #then only the checked loopback fields are written
	pin := strings.Repeat("ab", 32)
	colon := colonPin(pin)
	hyphen := strings.ReplaceAll(colon, ":", "-")
	cases := []struct {
		name  string
		uri   string
		code  string
		check func(*testing.T, []byte)
	}{
		{
			name: "example",
			uri:  exampleURI,
			check: func(t *testing.T, body []byte) {
				doc := assertSafeConfig(t, body, 1080)
				item := proxyItem(t, doc)
				if item["server"] != "192.0.2.1" || item["port"] != 443 || item["password"] != exampleAuth {
					t.Fatal("server fields")
				}
				if item["sni"] != "example.invalid" || item["type"] != "hysteria2" {
					t.Fatal("sni")
				}
				if _, ok := item["up"]; ok {
					t.Fatal("up")
				}
				if _, ok := item["down"]; ok {
					t.Fatal("down")
				}
			},
		},
		{
			name: "hy2 and default port",
			uri:  "hy2://example-auth-not-a-secret@192.0.2.1/",
			check: func(t *testing.T, body []byte) {
				item := proxyItem(t, assertSafeConfig(t, body, 1080))
				if item["type"] != "hysteria2" || item["port"] != 443 {
					t.Fatal("hy2")
				}
			},
		},
		{
			name: "user password",
			uri:  "hysteria2://user:pass@192.0.2.1:443/",
			check: func(t *testing.T, body []byte) {
				item := proxyItem(t, assertSafeConfig(t, body, 1080))
				if item["password"] != "user:pass" {
					t.Fatal("user password")
				}
			},
		},
		{
			name: "percent encoding",
			uri:  "hysteria2://user%3Aname:p%40ss@192.0.2.1/",
			check: func(t *testing.T, body []byte) {
				item := proxyItem(t, assertSafeConfig(t, body, 1080))
				if item["password"] != "user:name:p@ss" {
					t.Fatal("percent")
				}
			},
		},
		{
			name: "password true stays a string",
			uri:  "hysteria2://true@192.0.2.1:443/",
			check: func(t *testing.T, body []byte) {
				item := proxyItem(t, assertSafeConfig(t, body, 1080))
				if item["password"] != "true" {
					t.Fatalf("password %T", item["password"])
				}
			},
		},
		{
			name: "fragment is not configuration",
			uri:  exampleURI + "#display-name-only",
			check: func(t *testing.T, body []byte) {
				if strings.Contains(string(body), "display-name-only") {
					t.Fatal("fragment")
				}
			},
		},
		{
			name: "insecure one",
			uri:  "hysteria2://example-auth-not-a-secret@192.0.2.1/?insecure=1",
			check: func(t *testing.T, body []byte) {
				item := proxyItem(t, assertSafeConfig(t, body, 1080))
				if item["skip-cert-verify"] != true {
					t.Fatal("insecure")
				}
			},
		},
		{
			name: "insecure zero is explicit",
			uri:  "hysteria2://example-auth-not-a-secret@192.0.2.1/?insecure=0",
			check: func(t *testing.T, body []byte) {
				item := proxyItem(t, assertSafeConfig(t, body, 1080))
				if item["skip-cert-verify"] != false {
					t.Fatal("insecure zero")
				}
			},
		},
		{
			name: "insecure absent",
			uri:  "hysteria2://example-auth-not-a-secret@192.0.2.1/",
			check: func(t *testing.T, body []byte) {
				item := proxyItem(t, assertSafeConfig(t, body, 1080))
				if _, ok := item["skip-cert-verify"]; ok {
					t.Fatal("skip present")
				}
			},
		},
		{
			name: "salamander",
			uri:  "hysteria2://example-auth-not-a-secret@192.0.2.1/?obfs=salamander&obfs-password=pw",
			check: func(t *testing.T, body []byte) {
				item := proxyItem(t, assertSafeConfig(t, body, 1080))
				if item["obfs"] != "salamander" || item["obfs-password"] != "pw" {
					t.Fatal("obfs")
				}
			},
		},
		{
			name: "hyphenated host",
			uri:  "hysteria2://example-auth-not-a-secret@my-host.example:443/",
			check: func(t *testing.T, body []byte) {
				item := proxyItem(t, assertSafeConfig(t, body, 1080))
				if item["server"] != "my-host.example" || item["port"] != 443 {
					t.Fatal("host")
				}
			},
		},
		{
			name: "ipv6",
			uri:  "hysteria2://example-auth-not-a-secret@[2001:db8::1]/?sni=example.invalid",
			check: func(t *testing.T, body []byte) {
				item := proxyItem(t, assertSafeConfig(t, body, 1080))
				if item["server"] != "2001:db8::1" || item["port"] != 443 {
					t.Fatal("ipv6")
				}
			},
		},
		{
			name: "pin separators",
			uri:  "hysteria2://example-auth-not-a-secret@192.0.2.1/?pinSHA256=" + colon,
			check: func(t *testing.T, body []byte) {
				item := proxyItem(t, assertSafeConfig(t, body, 1080))
				if item["fingerprint"] != pin {
					t.Fatal("fingerprint")
				}
				if strings.Contains(string(body), ":") && strings.Contains(string(body), colon) {
					t.Fatal("colon pin copied")
				}
			},
		},
		{
			name: "pin hyphens",
			uri:  "hysteria2://example-auth-not-a-secret@192.0.2.1/?pinSHA256=" + hyphen,
			check: func(t *testing.T, body []byte) {
				item := proxyItem(t, assertSafeConfig(t, body, 1080))
				if item["fingerprint"] != pin || strings.Contains(item["fingerprint"].(string), "-") {
					t.Fatal("hyphen pin")
				}
			},
		},
		{name: "ech", uri: "hysteria2://example-auth-not-a-secret@192.0.2.1/?ech=example-ech-payload", code: "uri_unsupported"},
		{name: "alpn", uri: "hysteria2://example-auth-not-a-secret@192.0.2.1/?alpn=h3", code: "uri_invalid"},
		{name: "duplicate sni", uri: "hysteria2://example-auth-not-a-secret@192.0.2.1/?sni=a&sni=b", code: "uri_invalid"},
		{name: "insecure true", uri: "hysteria2://example-auth-not-a-secret@192.0.2.1/?insecure=true", code: "uri_invalid"},
		{name: "gecko without password", uri: "hysteria2://example-auth-not-a-secret@192.0.2.1/?obfs=gecko", code: "uri_invalid"},
		{name: "mystery obfs", uri: "hysteria2://example-auth-not-a-secret@192.0.2.1/?obfs=mystery&obfs-password=pw", code: "uri_invalid"},
		{name: "empty sni", uri: "hysteria2://example-auth-not-a-secret@192.0.2.1/?sni=", code: "uri_invalid"},
		{name: "multi-port", uri: "hysteria2://example-auth-not-a-secret@192.0.2.1:443,5000-6000/", code: "uri_unsupported"},
		{name: "ipv6 hop", uri: "hysteria2://example-auth-not-a-secret@[2001:db8::1]:443-444/", code: "uri_unsupported"},
		{name: "realm", uri: "hysteria2+realm://example-auth-not-a-secret@192.0.2.1:443/", code: "uri_unsupported"},
		{name: "path", uri: "hysteria2://example-auth-not-a-secret@192.0.2.1/extra", code: "uri_invalid"},
		{name: "openssl prefix", uri: "hysteria2://example-auth-not-a-secret@192.0.2.1/?pinSHA256=SHA256%20Fingerprint%3D" + colon, code: "uri_invalid"},
		{name: "short pin", uri: "hysteria2://example-auth-not-a-secret@192.0.2.1/?pinSHA256=abcd", code: "uri_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := renderURI(tc.uri)
			if tc.code == "" {
				if err != nil {
					t.Fatal(err)
				}
				tc.check(t, body)
				assertClean(t, errText(err))
				return
			}
			if codeOf(err) != tc.code {
				t.Fatalf("code %s", codeOf(err))
			}
			assertClean(t, err.Error())
		})
	}
}

func TestStartRequiresExecutable(t *testing.T) {
	// #given no separate core installation
	// #when the path is a bare name, a directory, or not executable
	// #then start fails closed and does not run a core
	dir := t.TempDir()
	plantCopy(t, dir, 0x11, "copy_complete", "", exampleURI)
	useCore(t, "listen")
	t.Setenv("PATH", filepath.Dir(corePath))
	if _, err := callStart(t, dir, "", "core"); codeOf(err) != "core_missing" || readRuns(t) != 0 {
		t.Fatalf("bare %v runs %d", err, readRuns(t))
	}
	if _, err := callStart(t, dir, "", t.TempDir()); codeOf(err) != "core_missing" || readRuns(t) != 0 {
		t.Fatal("directory")
	}
	missing := filepath.Join(t.TempDir(), "missing-core")
	if _, err := callStart(t, dir, "", missing); codeOf(err) != "core_missing" || readRuns(t) != 0 {
		t.Fatal("missing")
	}
	if runtime.GOOS != "windows" {
		file := filepath.Join(t.TempDir(), "core")
		if err := os.WriteFile(file, []byte("no"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := callStart(t, dir, "", file); codeOf(err) != "core_missing" || readRuns(t) != 0 {
			t.Fatal("mode")
		}
	}
}

func TestCancelledContextDoesNotSpawn(t *testing.T) {
	// #given a cancelled context
	// #when start is called
	// #then it returns before running a core
	dir := t.TempDir()
	plantCopy(t, dir, 0x11, "copy_complete", "", exampleURI)
	useCore(t, "listen")
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	buf := captureOut(t)
	err := Start(ctx, dir, "", corePath)
	if !errors.Is(err, context.Canceled) || readRuns(t) != 0 {
		t.Fatalf("err %v runs %d", err, readRuns(t))
	}
	if buf.Len() != 0 {
		t.Fatal("output")
	}
}

func TestExitCoreIsNotListening(t *testing.T) {
	// #given a core that exits before accepting
	// #when start waits for loopback
	// #then it reports the port, removes the runtime, and keeps the copy
	dir := t.TempDir()
	keep(t, dir)
	useCore(t, "exit")
	copyDir := plantCopy(t, dir, 0x11, "copy_complete", "", exampleURI)
	journal := readFile(t, filepath.Join(copyDir, "journal"))
	out, err := callStart(t, dir, "", corePath)
	if !errors.Is(err, errNotListening) {
		t.Fatalf("err %v", err)
	}
	if strings.Contains(out, "listening") || strings.Contains(out, "ready") {
		t.Fatal("output")
	}
	assertClean(t, out)
	matches, err := filepath.Glob(filepath.Join(dir, "proxy", "ticket-*"))
	if err != nil || len(matches) != 0 {
		t.Fatal("runtime remains")
	}
	if !bytes.Equal(readFile(t, filepath.Join(copyDir, "copy")), []byte(exampleURI)) {
		t.Fatal("copy")
	}
	if !bytes.Equal(readFile(t, filepath.Join(copyDir, "journal")), journal) {
		t.Fatal("journal")
	}
	report := readReport(t)
	assertChildContract(t, report, 0)
	if readRuns(t) != 1 {
		t.Fatalf("runs %d", readRuns(t))
	}
}

func TestStartListensAndStopKeepsCopy(t *testing.T) {
	// #given one complete copy and a core that accepts loopback
	// #when start runs and then stop runs
	// #then the port accepted a connection, the copy remains, and the core is gone
	dir := t.TempDir()
	keep(t, dir)
	useCore(t, "listen")
	t.Setenv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER", "0.0.0.0:9090")
	t.Setenv("CLASH_OVERRIDE_SECRET", "controller-secret")
	copyDir := plantCopy(t, dir, 0x11, "copy_complete", "", exampleURI)
	save := plantSave(t, dir, 0x11)
	journal := readFile(t, filepath.Join(copyDir, "journal"))
	logs := captureLog(t)
	out, err := callStart(t, dir, "", corePath)
	if err != nil {
		t.Fatal(err)
	}
	port := listenPort(t, out)
	if strings.Contains(out, "ready") {
		t.Fatal("ready")
	}
	assertClean(t, out)
	assertClean(t, logs.String())
	dialLoopback(t, port)
	report := readReport(t)
	assertChildContract(t, report, port)
	assertRuntimeMode(t, dir, 0x11)
	if runtime.GOOS == "linux" {
		assertLinuxListeners(t, readRuntimePID(t, dir), port)
	}
	if !bytes.Equal(readFile(t, filepath.Join(copyDir, "journal")), journal) {
		t.Fatal("journal")
	}
	pid := readRuntimePID(t, dir)
	second, err := callStart(t, dir, "", corePath)
	if err != nil || listenPort(t, second) != port || readRuns(t) != 1 {
		t.Fatalf("second %v runs %d", err, readRuns(t))
	}
	stopOut, err := callStop(t, dir, "")
	if err != nil || stopOut != "stopped\n"+credentialNotice {
		t.Fatal("stop text")
	}
	assertClean(t, stopOut)
	if strings.Contains(stopOut, "ready") {
		t.Fatal("ready")
	}
	if _, statErr := os.Stat(runtimeDir(dir, 0x11)); !os.IsNotExist(statErr) {
		t.Fatal("runtime remains")
	}
	if !bytes.Equal(readFile(t, filepath.Join(copyDir, "copy")), []byte(exampleURI)) {
		t.Fatal("copy")
	}
	if !bytes.Equal(readFile(t, save), []byte(exampleURI)) {
		t.Fatal("save")
	}
	if processAlive(pid) {
		t.Fatal("process")
	}
}

func TestForeignProcessIsNotKilled(t *testing.T) {
	// #given a live process that is not the recorded core
	// #when start and stop see that pid
	// #then they leave it running
	dir := t.TempDir()
	useCore(t, "listen")
	plantCopy(t, dir, 0xab, "copy_complete", "", exampleURI)
	rt := runtimeDir(dir, 0xab)
	if err := os.MkdirAll(rt, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rt, "pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rt, "exe"), []byte("/bin/sleep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rt, "addr"), []byte("127.0.0.1:1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := callStart(t, dir, "", corePath); !errors.Is(err, errProcessMatch) || readRuns(t) != 0 {
		t.Fatalf("start %v", err)
	}
	if _, err := callStop(t, dir, ""); !errors.Is(err, errProcessMatch) {
		t.Fatalf("stop %v", err)
	}
	if !processAlive(os.Getpid()) {
		t.Fatal("self")
	}
	if _, err := os.Stat(rt); err != nil {
		t.Fatal("runtime")
	}
}

func TestAmbiguousTickets(t *testing.T) {
	// #given two complete copies and two runtime directories
	// #when start or stop is asked for all of them
	// #then neither picks one, and stop kills nothing
	dir := t.TempDir()
	useCore(t, "listen")
	plantCopy(t, dir, 0x11, "copy_complete", "", exampleURI)
	plantCopy(t, dir, 0x22, "copy_complete", "", exampleURI)
	if _, err := callStart(t, dir, "", corePath); codeOf(err) != "ticket_ambiguous" || readRuns(t) != 0 {
		t.Fatalf("start %v runs %d", err, readRuns(t))
	}
	for _, fill := range []byte{0x11, 0x22} {
		rt := runtimeDir(dir, fill)
		if err := os.MkdirAll(rt, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(rt, "pid"), []byte("0\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out, err := callStop(t, dir, "")
	if codeOf(err) != "ticket_ambiguous" || out != "" {
		t.Fatalf("stop %v", err)
	}
	for _, fill := range []byte{0x11, 0x22} {
		if _, statErr := os.Stat(runtimeDir(dir, fill)); statErr != nil {
			t.Fatal("removed")
		}
	}
	out, err = callStop(t, dir, "11")
	if err != nil || out != "stopped\n"+credentialNotice {
		t.Fatal("prefix stop")
	}
	if _, statErr := os.Stat(runtimeDir(dir, 0x11)); !os.IsNotExist(statErr) {
		t.Fatal("prefix target")
	}
	if _, statErr := os.Stat(runtimeDir(dir, 0x22)); statErr != nil {
		t.Fatal("other ticket")
	}
}

func TestPhasesAndExpiredCopy(t *testing.T) {
	// #given a copy_complete, delivered, or expired copy
	// #when start runs
	// #then each copy can listen and the journal is unchanged
	cases := []struct {
		phase    string
		observed string
	}{
		{phase: "copy_complete"},
		{phase: "delivered"},
		{phase: "copy_complete", observed: "expired"},
	}
	for _, tc := range cases {
		t.Run(tc.phase+tc.observed, func(t *testing.T) {
			dir := t.TempDir()
			keep(t, dir)
			useCore(t, "listen")
			copyDir := plantCopy(t, dir, 0x33, tc.phase, tc.observed, exampleURI)
			journal := readFile(t, filepath.Join(copyDir, "journal"))
			out, err := callStart(t, dir, "", corePath)
			if err != nil {
				t.Fatal(err)
			}
			listenPort(t, out)
			if !bytes.Equal(readFile(t, filepath.Join(copyDir, "journal")), journal) {
				t.Fatal("journal")
			}
		})
	}
}

func TestUnsupportedURIDoesNotSpawn(t *testing.T) {
	// #given a stored URI whose ech parameter is not mapped
	// #when start parses it
	// #then it returns uri_unsupported and does not run the core
	dir := t.TempDir()
	useCore(t, "listen")
	uri := "hysteria2://example-auth-not-a-secret@192.0.2.1:443/?ech=example-ech-payload"
	plantCopy(t, dir, 0x44, "copy_complete", "", uri)
	out, err := callStart(t, dir, "", corePath)
	if codeOf(err) != "uri_unsupported" || readRuns(t) != 0 || out != "" {
		t.Fatalf("err %v runs %d", err, readRuns(t))
	}
	assertClean(t, err.Error())
}

func TestEmptyConfigDir(t *testing.T) {
	// #given an empty config directory
	// #when stop is called
	// #then it does not scan the current directory
	if _, err := callStop(t, "", ""); codeOf(err) != "copy_incomplete" {
		t.Fatal(err)
	}
}

func TestZombieIsNotAlive(t *testing.T) {
	// #given a core that has exited and has not been reaped
	// #when the runtime is inspected
	// #then the zombie is not treated as a running core
	if runtime.GOOS != "linux" {
		t.Skip("zombie state is read from /proc")
	}
	useCore(t, "exit")
	cmd := exec.Command(corePath)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Wait() })
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		alive, _ := inspect(cmd.Process.Pid)
		if !alive {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("zombie looked alive")
}

func TestRealCoreObservationIsNotReady(t *testing.T) {
	// #given no Mihomo binary is part of this module
	// #when DEVCTL_PROXY_CORE is unset
	// #then ready is untested
	path := os.Getenv("DEVCTL_PROXY_CORE")
	if path == "" {
		t.Skip("real Mihomo binary was not observed")
	}
	dir := t.TempDir()
	keep(t, dir)
	plantCopy(t, dir, 0x11, "copy_complete", "", exampleURI)
	out, err := callStart(t, dir, "", path)
	if err != nil {
		t.Fatal(err)
	}
	port := listenPort(t, out)
	if strings.Contains(out, "ready") {
		t.Fatal("ready")
	}
	dialLoopback(t, port)
	if runtime.GOOS == "linux" {
		assertLinuxListeners(t, readRuntimePID(t, dir), port)
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(loopbackHost, strconv.Itoa(port)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
	buf := make([]byte, 2)
	_, _ = conn.Read(buf)
	target, err := net.DialTimeout("tcp", "192.0.2.1:80", 500*time.Millisecond)
	if err == nil {
		_ = target.Close()
		t.Fatal("direct path is not a proxied download")
	}
}

func renderURI(uri string) ([]byte, error) {
	parsed, err := parseURI([]byte(uri))
	if err != nil {
		return nil, err
	}
	return renderConfig(parsed, 1080)
}

func assertSafeConfig(t *testing.T, body []byte, port int) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["allow-lan"] != false || doc["bind-address"] != loopbackHost {
		t.Fatal("bind")
	}
	if doc["mode"] != "rule" || doc["find-process-mode"] != "off" || doc["log-level"] != "warning" {
		t.Fatal("general")
	}
	if doc["ipv6"] != false || doc["geo-auto-update"] != false {
		t.Fatal("updates")
	}
	if _, ok := doc["port"]; ok {
		t.Fatal("top-level port")
	}
	rules, _ := doc["rules"].([]any)
	if len(rules) != 1 || rules[0] != "MATCH,devctl" {
		t.Fatal("rules")
	}
	text := string(body)
	for _, token := range []string{"0.0.0.0", "tproxy-port", "iptables", "external-controller", "external-ui", "mixed-port", "redir-port", "tun:"} {
		if strings.Contains(text, token) {
			t.Fatalf("token %s", token)
		}
	}
	var keys []string
	walkKeys(doc, func(key string) { keys = append(keys, key) })
	for _, key := range keys {
		switch key {
		case "tun", "iptables", "tproxy-port", "redir-port", "mixed-port", "socks-port",
			"external-controller", "external-ui", "secret", "external-doh-server", "up", "down":
			t.Fatalf("key %s", key)
		}
	}
	listeners, _ := doc["listeners"].([]any)
	if len(listeners) != 1 {
		t.Fatal("listeners")
	}
	ln, _ := listeners[0].(map[string]any)
	if ln["type"] != "socks" || ln["listen"] != loopbackHost || ln["udp"] != true || ln["name"] != "loopback" {
		t.Fatal("socks")
	}
	if port > 0 && ln["port"] != port {
		t.Fatal("port")
	}
	return doc
}

func proxyItem(t *testing.T, doc map[string]any) map[string]any {
	t.Helper()
	items, _ := doc["proxies"].([]any)
	if len(items) != 1 {
		t.Fatal("proxies")
	}
	item, _ := items[0].(map[string]any)
	if item["name"] != "devctl" {
		t.Fatal("name")
	}
	return item
}

func walkKeys(v any, fn func(string)) {
	switch node := v.(type) {
	case map[string]any:
		for key, child := range node {
			fn(key)
			walkKeys(child, fn)
		}
	case []any:
		for _, child := range node {
			walkKeys(child, fn)
		}
	}
}

func assertChildContract(t *testing.T, report coreReport, port int) {
	t.Helper()
	if len(report.Args) != 5 || report.Args[0] != corePath || report.Args[1] != "-d" || report.Args[3] != "-f" {
		t.Fatalf("args %d", len(report.Args))
	}
	if !strings.HasSuffix(report.Args[4], "config.yaml") || !strings.Contains(report.Args[2], string(filepath.Separator)+"proxy"+string(filepath.Separator)) {
		t.Fatal("argv paths")
	}
	for _, arg := range report.Args {
		if strings.Contains(arg, "ext-ctl") || strings.Contains(arg, "secret") || arg == "-m" {
			t.Fatal("arg")
		}
		assertClean(t, arg)
	}
	for _, item := range report.Env {
		if strings.HasPrefix(item, "CLASH_") || strings.Contains(item, "0.0.0.0:9090") || strings.Contains(item, "HOME=") {
			t.Fatal("env")
		}
		assertClean(t, item)
	}
	item := proxyItem(t, assertSafeConfig(t, []byte(report.Config), port))
	if item["password"] != exampleAuth {
		t.Fatal("password field")
	}
}

func assertRuntimeMode(t *testing.T, configDir string, fill byte) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return
	}
	rt := runtimeDir(configDir, fill)
	info, err := os.Stat(rt)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatal("dir mode")
	}
	parent, err := os.Stat(filepath.Dir(rt))
	if err != nil || parent.Mode().Perm() != 0o700 {
		t.Fatal("proxy mode")
	}
	for _, name := range []string{"config.yaml", "addr", "exe", "pid", "core.log"} {
		file, err := os.Stat(filepath.Join(rt, name))
		if err != nil || file.Mode().Perm() != 0o600 {
			t.Fatalf("mode %s", name)
		}
	}
}

func assertLinuxListeners(t *testing.T, pid, port int) {
	t.Helper()
	inodes := socketInodes(t, pid)
	if len(inodes) == 0 {
		t.Fatal("no sockets")
	}
	found := false
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		body, err := os.ReadFile(table)
		if err != nil {
			continue
		}
		lines := strings.Split(string(body), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 || fields[3] != "0A" {
				continue
			}
			if _, ok := inodes[fields[9]]; !ok {
				continue
			}
			host, gotPort, ok := parseProcAddr(fields[1])
			if !ok || host != loopbackHost || gotPort != port {
				t.Fatalf("listener %s", fields[1])
			}
			found = true
		}
	}
	if !found {
		t.Fatal("listen socket")
	}
}

func socketInodes(t *testing.T, pid int) map[string]struct{} {
	t.Helper()
	entries, err := os.ReadDir("/proc/" + strconv.Itoa(pid) + "/fd")
	if err != nil {
		t.Fatal(err)
	}
	inodes := map[string]struct{}{}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", entry.Name()))
		if err != nil || !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
			continue
		}
		inodes[target[len("socket:["):len(target)-1]] = struct{}{}
	}
	return inodes
}

func parseProcAddr(field string) (string, int, bool) {
	host, portHex, ok := strings.Cut(field, ":")
	if !ok {
		return "", 0, false
	}
	port64, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return "", 0, false
	}
	raw, err := hex.DecodeString(host)
	if err != nil {
		return "", 0, false
	}
	if len(raw) == 4 {
		ip := net.IPv4(raw[3], raw[2], raw[1], raw[0])
		return ip.String(), int(port64), true
	}
	if len(raw) == 16 {
		ip := make(net.IP, 16)
		for i := 0; i < 16; i += 4 {
			ip[i] = raw[i+3]
			ip[i+1] = raw[i+2]
			ip[i+2] = raw[i+1]
			ip[i+3] = raw[i]
		}
		return ip.String(), int(port64), true
	}
	return "", 0, false
}

func dialLoopback(t *testing.T, port int) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(loopbackHost, strconv.Itoa(port)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
}

func listenPort(t *testing.T, out string) int {
	t.Helper()
	if !listenRE.MatchString(out) {
		t.Fatalf("listening=%v ready=%v", strings.Contains(out, "listening"), strings.Contains(out, "ready"))
	}
	_, portText, err := net.SplitHostPort(strings.TrimSpace(strings.TrimPrefix(out, "listening ")))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 {
		t.Fatal("port")
	}
	return port
}

func callStart(t *testing.T, dir, prefix, core string) (string, error) {
	t.Helper()
	buf := captureOut(t)
	err := Start(t.Context(), dir, prefix, core)
	return buf.String(), err
}

func callStop(t *testing.T, dir, prefix string) (string, error) {
	t.Helper()
	buf := captureOut(t)
	err := Stop(context.WithoutCancel(t.Context()), dir, prefix)
	return buf.String(), err
}

func captureOut(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := userOut
	userOut = buf
	t.Cleanup(func() { userOut = prev })
	return buf
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return buf
}

func keep(t *testing.T, dir string) {
	t.Helper()
	ctx := context.WithoutCancel(t.Context())
	t.Cleanup(func() {
		prev := userOut
		userOut = io.Discard
		_ = Stop(ctx, dir, "")
		userOut = prev
	})
}

func useCore(t *testing.T, behavior string) {
	t.Helper()
	dir := filepath.Dir(corePath)
	if err := os.WriteFile(filepath.Join(dir, "behavior"), []byte(behavior), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "runs"), []byte("0"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(dir, "report.json"))
}

func readRuns(t *testing.T) int {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(filepath.Dir(corePath), "runs"))
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

type coreReport struct {
	Args   []string `json:"args"`
	Env    []string `json:"env"`
	Config string   `json:"config"`
}

func readReport(t *testing.T) coreReport {
	t.Helper()
	body := readFile(t, filepath.Join(filepath.Dir(corePath), "report.json"))
	var report coreReport
	if err := json.Unmarshal(body, &report); err != nil {
		t.Fatal(err)
	}
	return report
}

func plantCopy(t *testing.T, configDir string, fill byte, phase, observed, uri string) string {
	t.Helper()
	hash := hashHex(fill)
	dir := filepath.Join(configDir, "pair", "ticket-"+hash)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "copy"), []byte(uri), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(uri))
	env := sha256.Sum256([]byte("envelope-" + hash))
	record := plantedJournal{
		Phase:        phase,
		TicketHash:   hash,
		EnvelopeHash: hex.EncodeToString(env[:]),
		CopyHash:     hex.EncodeToString(sum[:]),
		Observed:     observed,
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "journal"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func plantSave(t *testing.T, configDir string, fill byte) string {
	t.Helper()
	path := filepath.Join(configDir, "saved", "ticket-"+hashHex(fill))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(exampleURI), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type plantedJournal struct {
	Phase        string `json:"phase"`
	TicketHash   string `json:"ticket_hash"`
	EnvelopeHash string `json:"envelope_hash"`
	CopyHash     string `json:"copy_hash"`
	Observed     string `json:"observed,omitempty"`
}

func hashHex(fill byte) string {
	return hex.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func runtimeDir(configDir string, fill byte) string {
	return filepath.Join(configDir, "proxy", "ticket-"+hashHex(fill))
}

func readRuntimePID(t *testing.T, configDir string) int {
	t.Helper()
	text := strings.TrimSpace(string(readFile(t, filepath.Join(runtimeDir(configDir, 0x11), "pid"))))
	pid, err := strconv.Atoi(text)
	if err != nil || pid <= 1 {
		t.Fatal("pid")
	}
	return pid
}

func processAlive(pid int) bool {
	if pid <= 1 {
		return false
	}
	alive, _ := inspect(pid)
	return alive
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func readVocabulary(t *testing.T) []byte {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	body, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "pair", "protocol", "v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func codeOf(err error) string {
	if err == nil {
		return ""
	}
	code, _, _ := strings.Cut(err.Error(), ":")
	return code
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func assertClean(t *testing.T, text string) {
	t.Helper()
	if strings.Contains(text, exampleAuth) || strings.Contains(text, "example-ech-payload") {
		t.Fatal("secret in output")
	}
}

func colonPin(pin string) string {
	var b strings.Builder
	for i := 0; i < len(pin); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(pin[i : i+2])
	}
	return b.String()
}

func withoutGOFLAGS(env []string) []string {
	out := make([]string, 0, len(env))
	for _, item := range env {
		if strings.HasPrefix(item, "GOFLAGS=") {
			continue
		}
		out = append(out, item)
	}
	return out
}

func TestStopWithNoRuntimePrintsNotice(t *testing.T) {
	// #given no runtime directory
	// #when stop runs
	// #then it still says the server credential is unchanged
	dir := t.TempDir()
	out, err := callStop(t, dir, "")
	if err != nil || out != credentialNotice {
		t.Fatal("notice")
	}
}

const coreProgram = `package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func main() {
	exe, err := os.Executable()
	if err != nil {
		os.Exit(2)
	}
	dir := filepath.Dir(exe)
	bump(filepath.Join(dir, "runs"))
	configPath := flagValue("-f")
	config, _ := os.ReadFile(configPath)
	report := map[string]any{"args": os.Args, "env": os.Environ(), "config": string(config)}
	raw, _ := json.Marshal(report)
	_ = os.WriteFile(filepath.Join(dir, "report.json"), raw, 0o600)
	behavior, err := os.ReadFile(filepath.Join(dir, "behavior"))
	if err != nil {
		os.Exit(2)
	}
	switch strings.TrimSpace(string(behavior)) {
	case "exit":
		os.Exit(0)
	case "delay":
		time.Sleep(2 * time.Second)
		listen(config)
	case "listen":
		listen(config)
	default:
		os.Exit(2)
	}
}

func listen(config []byte) {
	host, port, ok := socks(string(config))
	if !ok {
		os.Exit(3)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		os.Exit(4)
	}
	defer ln.Close()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}
}

func socks(body string) (string, int, bool) {
	in := false
	var kind, host string
	var port int
	for _, line := range strings.Split(body, "\n") {
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "listeners:") {
			in = true
			continue
		}
		if in && line != "" && line[0] != ' ' && line[0] != '-' {
			break
		}
		if !in {
			continue
		}
		if strings.HasPrefix(trim, "type:") {
			kind = unquote(strings.TrimSpace(strings.TrimPrefix(trim, "type:")))
		}
		if strings.HasPrefix(trim, "listen:") {
			host = unquote(strings.TrimSpace(strings.TrimPrefix(trim, "listen:")))
		}
		if strings.HasPrefix(trim, "port:") {
			port, _ = strconv.Atoi(unquote(strings.TrimSpace(strings.TrimPrefix(trim, "port:"))))
		}
	}
	if kind != "socks" || host == "" || port < 1 {
		return "", 0, false
	}
	return host, port, true
}

func unquote(value string) string {
	return strings.Trim(value, "\"'")
}

func flagValue(name string) string {
	for i := 0; i < len(os.Args)-1; i++ {
		if os.Args[i] == name {
			return os.Args[i+1]
		}
	}
	return ""
}

func bump(path string) {
	n := 0
	if body, err := os.ReadFile(path); err == nil {
		n, _ = strconv.Atoi(strings.TrimSpace(string(body)))
	}
	_ = os.WriteFile(path, []byte(strconv.Itoa(n+1)), 0o600)
}
`
