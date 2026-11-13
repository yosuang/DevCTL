//go:build linux

package pair

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"devctl/internal/logging"

	"golang.org/x/sys/unix"
)

// scriptPrompt is a test double. The devctl binary has no prompt replacement.
type scriptPrompt struct {
	uri     string
	phrases []string
}

func (p *scriptPrompt) URI() (string, error) {
	if p.uri == "" {
		return "", localCode("uri_invalid", "uri is not usable")
	}
	return p.uri, nil
}

func (p *scriptPrompt) Passphrase(bool) (string, error) {
	if len(p.phrases) == 0 {
		return "", localCode("passphrase_rejected", "passphrase is too short")
	}
	got := p.phrases[0]
	p.phrases = p.phrases[1:]
	return got, nil
}

func TestIntegration(t *testing.T) {
	root := moduleRoot(t)
	bin := buildDevctl(t, root)
	assertBinaryExit(t, bin)
	origin := startWrangler(t, root)
	t.Run("reject", func(t *testing.T) {
		testRejectReconnect(t, origin)
	})
	t.Run("deliver", func(t *testing.T) {
		testDeliverCLI(t, origin, bin)
	})
}

func testRejectReconnect(t *testing.T, origin string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	issuerDir := t.TempDir()
	receiverDir := t.TempDir()
	logPath := filepath.Join(receiverDir, "logs", "library.log")
	installDebugLog(t, logPath)

	var shown lockedBuffer
	prev := userOut
	userOut = &shown
	t.Cleanup(func() { userOut = prev })

	issuePrompt := &scriptPrompt{uri: exampleURI, phrases: []string{examplePassphrase}}
	if err := Issue(ctx, origin, issuePrompt, issuerDir); err != nil {
		t.Fatalf("issue: %s", err.Error())
	}
	if len(issuePrompt.phrases) != 0 {
		t.Fatal("issue did not read the passphrase")
	}
	ticket, issuerCap := readIssuer(t, issuerDir)
	ticketHash := sha256.Sum256(ticket)

	errCh := make(chan error, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		prompt := &scriptPrompt{phrases: []string{wrongPassphrase()}}
		errCh <- Receive(ctx, origin, prompt, receiverDir, "")
	}()
	defer func() {
		cancel()
		wg.Wait()
	}()
	sessionCap := waitSessionCapability(ctx, t, &shown)
	rec, err := loadReceiver(receiverDir)
	if err != nil || rec == nil {
		t.Fatalf("session: %v", err)
	}
	client, err := dialCoordinator(origin)
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	confirmed, err := client.confirm(ctx, ticket, sessionCap, rec.pub, rec.hash, ticketHash[:])
	if err != nil || confirmed.State != "bound" {
		t.Fatalf("confirm: %v state %s", err, confirmed.State)
	}
	recvErr := <-errCh
	if codeOf(recvErr) != "passphrase_rejected" {
		t.Fatalf("receive: %v", recvErr)
	}
	if treeContains(t, receiverDir, []byte(exampleURI)) || fileNamed(t, receiverDir, copyFileName) {
		t.Fatal("wrong passphrase wrote a copy")
	}
	if state := ticketStatus(ctx, t, origin, ticket, issuerCap); state != "bound" {
		t.Fatalf("state %s", state)
	}

	again, err := dialCoordinator(origin)
	if err != nil {
		t.Fatal(err)
	}
	defer again.close()
	rec, err = loadReceiver(receiverDir)
	if err != nil || rec == nil {
		t.Fatal(err)
	}
	envelope, state, err := again.readEnvelope(ctx, rec, ticketHash[:], "")
	if err != nil || state != "bound" {
		t.Fatalf("reread: %v state %s", err, state)
	}
	plain, err := openEnvelope(examplePassphrase, ticketHash[:], envelope)
	if err != nil || string(plain) != exampleURI {
		t.Fatalf("opened %v", err)
	}
	if fileNamed(t, receiverDir, copyFileName) {
		t.Fatal("reread wrote a copy")
	}

	_, otherKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, ok := otherKey.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("public key")
	}
	nonce, err := again.opNonce(ctx, ticketHash[:])
	if err != nil {
		t.Fatal(err)
	}
	_, err = again.signedTicket(ctx, "read", wireSpec.Routes.TicketRead, &receiver{key: otherKey, pub: otherPub}, ticketHash[:], nonce, 0, nil)
	if codeOf(err) != "forbidden" && codeOf(err) != "ticket_bound" {
		t.Fatalf("second receiver: %v", err)
	}

	secondDir := t.TempDir()
	second, err := createReceiver(secondDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := again.hello(ctx, second); err != nil {
		t.Fatal(err)
	}
	_, err = again.confirm(ctx, ticket, second.cap, second.pub, second.hash, ticketHash[:])
	if codeOf(err) != "ticket_bound" && codeOf(err) != "forbidden" {
		t.Fatalf("second confirm: %v", err)
	}
	if state := ticketStatus(ctx, t, origin, ticket, issuerCap); state != "bound" {
		t.Fatalf("state after reject %s", state)
	}
	assertLogClean(t, logPath, ticket)
}

func testDeliverCLI(t *testing.T, origin, bin string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	issuerDir := t.TempDir()
	receiverDir := t.TempDir()
	receive := startDevctl(ctx, t, bin, receiverDir, "--debug", "pair", "receive", "--coordinator", origin)
	defer receive.stop()
	page := receive.stdout.waitLine(ctx, t, "#sc=")
	sessionCap, err := decodeFragment(page)
	if err != nil {
		t.Fatal(err)
	}

	issue := startDevctl(ctx, t, bin, issuerDir, "--debug", "pair", "issue", "--coordinator", origin)
	defer issue.stop()
	issue.stderr.waitContains(ctx, t, "Hysteria2 URI:")
	issue.write(exampleURI)
	issue.stderr.waitContains(ctx, t, "Transfer passphrase (not this computer's login password):")
	issue.write(examplePassphrase)
	issue.stderr.waitContains(ctx, t, "Transfer passphrase again:")
	issue.write(examplePassphrase)
	ticketLine := issue.stdout.waitLine(ctx, t, "dct1.")
	if issue.wait() != 0 {
		t.Fatalf("issue exit, stderr %s", issue.stderr.String())
	}
	// #given the issuer capability from this upload is on disk
	// #when pair issue runs again
	// #then the same dct1. line is reprinted and no second envelope is uploaded
	var reprinted bytes.Buffer
	prevOut := userOut
	userOut = &reprinted
	t.Cleanup(func() { userOut = prevOut })
	if err := Issue(ctx, origin, failPrompt{}, issuerDir); err != nil {
		t.Fatalf("reissue: %v", err)
	}
	if reprinted.String() != ticketLine+"\n" {
		t.Fatal("reissue did not reprint the stored ticket")
	}
	ticket, err := b64url.DecodeString(strings.TrimPrefix(ticketLine, "dct1."))
	if err != nil || len(ticket) != 32 {
		t.Fatal("ticket text")
	}
	assertCommandClean(t, issue.cmd, ticket)
	assertCommandClean(t, receive.cmd, ticket)

	rec, err := loadReceiver(receiverDir)
	if err != nil || rec == nil {
		t.Fatal(err)
	}
	client, err := dialCoordinator(origin)
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	sum := sha256.Sum256(ticket)
	confirmed, err := client.confirm(ctx, ticket, sessionCap, rec.pub, rec.hash, sum[:])
	if err != nil || confirmed.State != "bound" {
		t.Fatalf("confirm: %v %s", err, confirmed.State)
	}
	receive.stderr.waitContains(ctx, t, "Transfer passphrase (not this computer's login password):")
	receive.write(examplePassphrase)
	if receive.wait() != 0 {
		t.Fatalf("receive exit, stderr %s", receive.stderr.String())
	}
	got, _, err := LoadTakenOver(receiverDir, "")
	if err != nil || got != exampleURI {
		t.Fatalf("copy %q err %v", got, err)
	}
	_, issuerCap := readIssuer(t, issuerDir)
	if state := ticketStatus(ctx, t, origin, ticket, issuerCap); state != "consumed" {
		t.Fatalf("state %s", state)
	}
	for _, dir := range []string{issuerDir, receiverDir} {
		logPath := filepath.Join(dir, "logs", "devctl.log")
		body, err := os.ReadFile(logPath)
		if err != nil || !bytes.Contains(body, []byte("level=DEBUG")) || !bytes.Contains(body, []byte("msg=pair")) {
			t.Fatalf("debug log %s: %v", logPath, err)
		}
		assertLogClean(t, logPath, ticket)
		errBody, err := os.ReadFile(filepath.Join(dir, "stderr.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if containsMaterial(errBody, ticket) {
			t.Fatal("stderr contains pairing material")
		}
	}
	if treeContains(t, issuerDir, []byte(exampleURI)) || treeContains(t, issuerDir, []byte(examplePassphrase)) {
		t.Fatal("issuer stored the uri or passphrase")
	}
}

func wrongPassphrase() string {
	return "wrong-passphrase-not-a-secret"
}

func assertBinaryExit(t *testing.T, bin string) {
	t.Helper()
	cmd := exec.Command(bin, "pair", "receive", "--coordinator", "http://example.com")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Env = cleanEnv(t.TempDir())
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("exit %v", err)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("bad_request:")) || bytes.Contains(stderr.Bytes(), []byte("example.com")) {
		t.Fatalf("stderr %s", stderr.String())
	}
}

func startWrangler(t *testing.T, root string) string {
	t.Helper()
	bin := filepath.Join(root, "coordinator", "node_modules", ".bin", "wrangler")
	if _, err := os.Stat(bin); err != nil {
		install := exec.Command("npm", "ci")
		install.Dir = filepath.Join(root, "coordinator")
		out, runErr := install.CombinedOutput()
		if runErr != nil {
			t.Fatalf("npm ci: %v\n%s", runErr, out)
		}
	}
	port := freePort(t)
	inspector := freePort(t)
	persist := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "wrangler.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cmd := exec.CommandContext(ctx, bin, "dev",
		"--config", "wrangler.jsonc",
		"--ip", "127.0.0.1",
		"--port", strconv.Itoa(port),
		"--inspector-ip", "127.0.0.1",
		"--inspector-port", strconv.Itoa(inspector),
		"--local",
		"--local-protocol", "http",
		"--infer-origin-from-routes=false",
		"--persist-to", persist,
		"--log-level", "error",
		"--show-interactive-dev-session=false",
	)
	cmd.Dir = filepath.Join(root, "coordinator")
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"TMPDIR=" + os.TempDir(),
		"WRANGLER_SEND_METRICS=false",
		"FORCE_COLOR=0",
		"CI=true",
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &unix.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = syscallKillGroup(cmd)
		_ = cmd.Wait()
		_ = logFile.Close()
	})
	origin := "http://127.0.0.1:" + strconv.Itoa(port)
	waitReady(t, origin, logPath)
	assertLoopback(t, port)
	assertLoopback(t, inspector)
	return origin
}

func waitReady(t *testing.T, origin, logPath string) {
	t.Helper()
	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) { return nil, nil },
		},
	}
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(origin + "/v1/tickets")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusMethodNotAllowed {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	body, _ := os.ReadFile(logPath)
	t.Fatalf("wrangler did not listen\n%s", tail(body))
}

func assertLoopback(t *testing.T, port int) {
	t.Helper()
	raw, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		t.Fatal(err)
	}
	upper := bytes.ToUpper(raw)
	local := []byte(fmt.Sprintf("0100007F:%04X", port))
	wild := []byte(fmt.Sprintf("00000000:%04X", port))
	if !bytes.Contains(upper, local) {
		t.Fatalf("port %d is not bound to 127.0.0.1", port)
	}
	if bytes.Contains(upper, wild) {
		t.Fatalf("port %d is bound to 0.0.0.0", port)
	}
}

func buildDevctl(t *testing.T, root string) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "devctl")
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/devctl")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod")
		}
		dir = parent
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

type devctlProc struct {
	cmd    *exec.Cmd
	master *os.File
	stdout *lockedBuffer
	stderr *lockedBuffer
	done   chan error
}

func startDevctl(ctx context.Context, t *testing.T, bin, configDir string, args ...string) *devctlProc {
	t.Helper()
	return runDevctlCmd(ctx, t, exec.Command(bin, args...), configDir)
}

func runDevctlCmd(ctx context.Context, t *testing.T, cmd *exec.Cmd, configDir string) *devctlProc {
	t.Helper()
	master, slave, err := openPTY()
	if err != nil {
		t.Fatal(err)
	}
	stdout := &lockedBuffer{}
	stderr := &lockedBuffer{}
	cmd.Dir = configDir
	if cmd.Env == nil {
		cmd.Env = cleanEnv(configDir)
	}
	cmd.Stdin = slave
	cmd.Stdout = stdout
	cmd.Stderr = io.MultiWriter(stderr, mustFile(t, filepath.Join(configDir, "stderr.txt")))
	cmd.SysProcAttr = &unix.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		master.Close()
		slave.Close()
		t.Fatal(err)
	}
	slave.Close()
	go func() { _, _ = io.Copy(io.Discard, master) }()
	proc := &devctlProc{cmd: cmd, master: master, stdout: stdout, stderr: stderr, done: make(chan error, 1)}
	go func() { proc.done <- cmd.Wait() }()
	go func() {
		<-ctx.Done()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	}()
	return proc
}

func (p *devctlProc) write(line string) {
	_, _ = p.master.Write([]byte(line + "\n"))
}

func (p *devctlProc) wait() int {
	err := <-p.done
	_ = p.master.Close()
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	return 1
}

func (p *devctlProc) stop() {
	if p.cmd.Process != nil {
		_ = p.cmd.Process.Kill()
	}
}

func openPTY() (*os.File, *os.File, error) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}
	// TIOCSPTLCK clears the kernel lock. The slave name comes from TIOCGPTN.
	if err := unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		master.Close()
		return nil, nil, err
	}
	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	return master, slave, nil
}

func cleanEnv(configDir string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"TMPDIR=" + os.TempDir(),
		"DEVCTL_CONFIG_DIR=" + configDir,
		"LANG=C",
	}
}

func assertCommandClean(t *testing.T, cmd *exec.Cmd, ticket []byte) {
	t.Helper()
	text := strings.Join(append(append([]string{}, cmd.Args...), cmd.Env...), "\n")
	if containsMaterial([]byte(text), ticket) {
		t.Fatal("command arguments or environment contain pairing material")
	}
}

func installDebugLog(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o666)
	if err != nil {
		t.Fatal(err)
	}
	prev := slog.Default()
	slog.SetDefault(logging.NewLogger(file, func() bool { return true }))
	t.Cleanup(func() {
		slog.SetDefault(prev)
		_ = file.Close()
	})
}

func assertLogClean(t *testing.T, path string, ticket []byte) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if containsMaterial(body, ticket) {
		t.Fatalf("%s contains pairing material", path)
	}
}

func containsMaterial(body, ticket []byte) bool {
	encoded := b64url.EncodeToString(ticket)
	needles := [][]byte{
		[]byte(exampleURI),
		[]byte(examplePassphrase),
		[]byte(wrongPassphrase()),
		ticket,
		[]byte(encoded),
		[]byte("dct1." + encoded),
	}
	for _, needle := range needles {
		if len(needle) > 0 && bytes.Contains(body, needle) {
			return true
		}
	}
	return false
}

func ticketStatus(ctx context.Context, t *testing.T, origin string, ticket, issuer []byte) string {
	t.Helper()
	client, err := dialCoordinator(origin)
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	state, err := client.status(ctx, ticket, issuer)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func readIssuer(t *testing.T, configDir string) ([]byte, []byte) {
	t.Helper()
	root := filepath.Join(configDir, pairFolderName)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var dir string
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "issuer-") {
			if dir != "" {
				t.Fatal("two issuer directories")
			}
			dir = filepath.Join(root, entry.Name())
		}
	}
	if dir == "" {
		t.Fatal("issuer directory")
	}
	ticket, err := os.ReadFile(filepath.Join(dir, "ticket"))
	if err != nil {
		t.Fatal(err)
	}
	capability, err := os.ReadFile(filepath.Join(dir, "capability"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(ticket)
	if !strings.HasSuffix(dir, hex.EncodeToString(sum[:])) {
		t.Fatal("issuer directory hash")
	}
	return ticket, capability
}

func waitSessionCapability(ctx context.Context, t *testing.T, shown *lockedBuffer) []byte {
	t.Helper()
	line := shown.waitLine(ctx, t, "#sc=")
	raw, err := decodeFragment(line)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func decodeFragment(line string) ([]byte, error) {
	const marker = "#sc="
	i := strings.Index(line, marker)
	if i < 0 {
		return nil, errors.New("fragment")
	}
	encoded := strings.TrimSpace(line[i+len(marker):])
	raw, err := b64url.DecodeString(encoded)
	if err != nil || len(raw) != 32 {
		return nil, err
	}
	return raw, nil
}

func treeContains(t *testing.T, root string, needle []byte) bool {
	t.Helper()
	found := false
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || !info.Mode().IsRegular() || found {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr == nil && bytes.Contains(body, needle) {
			found = true
		}
		return nil
	})
	return found
}

func fileNamed(t *testing.T, root, name string) bool {
	t.Helper()
	found := false
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info != nil && info.Name() == name {
			found = true
		}
		return nil
	})
	return found
}

func mustFile(t *testing.T, path string) *os.File {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func syscallKillGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
}

func tail(body []byte) string {
	if len(body) > 4000 {
		body = body[len(body)-4000:]
	}
	return string(body)
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *lockedBuffer) waitContains(ctx context.Context, t *testing.T, needle string) {
	t.Helper()
	if err := b.wait(ctx, func(text string) bool { return strings.Contains(text, needle) }); err != nil {
		t.Fatalf("timed out waiting for %q", needle)
	}
}

func (b *lockedBuffer) waitLine(ctx context.Context, t *testing.T, prefix string) string {
	t.Helper()
	var line string
	err := b.wait(ctx, func(text string) bool {
		for _, item := range strings.Split(text, "\n") {
			if strings.Contains(item, prefix) {
				line = strings.TrimSpace(item)
				return true
			}
		}
		return false
	})
	if err != nil {
		t.Fatalf("timed out waiting for %q", prefix)
	}
	return line
}

func (b *lockedBuffer) wait(ctx context.Context, ready func(string) bool) error {
	for {
		if ready(b.String()) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}
