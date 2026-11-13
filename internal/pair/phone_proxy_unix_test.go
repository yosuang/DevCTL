//go:build linux

package pair

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// listenLine is the only start text this lifecycle accepts.
// A matching line is not a ready result.
var listenLine = regexp.MustCompile(`^listening 127\.0\.0\.1:[1-9][0-9]*\n$`)

const proxyStopped = "stopped\nStopping does not revoke the proxy credentials. The Hysteria2 authentication material stays valid on the proxy server until you change it there.\n"

func TestPhoneConfirmProxyLifecycle(t *testing.T) {
	// #given a loopback coordinator and the phone confirm page
	// #when issue, the page confirm HTTP path, receive, and proxy start/stop run
	// #then default stop deletes the ticket copy, and an explicit save or a post-takeover expired journal keeps it
	// The confirm path is the page's preview, challenge, and confirm requests. This test does not open a camera.
	// proxy start may print listening. That line is not ready, and this test does not probe through the proxy.
	root := moduleRoot(t)
	bin := buildDevctl(t, root)
	origin := startWrangler(t, root)
	core := lifecycleCore(t, root)
	t.Run("default", func(t *testing.T) {
		// #given a takeover with no save directory
		// #when proxy stop runs after start prints listening
		// #then pair/ticket-<hash>/copy is deleted
		dir := takeover(t, origin, bin, "")
		hash := oneTicketHash(t, dir)
		copyPath := ticketCopyPath(dir, hash)
		if _, err := os.Stat(copyPath); err != nil {
			t.Fatal(err)
		}
		startOut, stopOut := runProxy(t, bin, dir, core)
		if _, err := os.Stat(copyPath); !os.IsNotExist(err) {
			t.Fatal("temporary plaintext remains")
		}
		if _, err := os.Stat(filepath.Join(dir, "proxy", "ticket-"+hash)); !os.IsNotExist(err) {
			t.Fatal("runtime remains")
		}
		assertListeningOnly(t, startOut, stopOut)
	})
	t.Run("save-dir", func(t *testing.T) {
		// #given receive was passed --save-dir
		// #when proxy stop runs
		// #then pair/ticket-<hash>/copy stays
		save := t.TempDir()
		dir := takeover(t, origin, bin, save)
		hash := oneTicketHash(t, dir)
		copyPath := ticketCopyPath(dir, hash)
		saved := readFile(t, filepath.Join(save, "ticket-"+hash))
		if string(saved) != exampleURI {
			t.Fatal("save file")
		}
		if same, err := samePath(copyPath, filepath.Join(save, "ticket-"+hash)); err != nil || same {
			t.Fatal("save file is not separate")
		}
		journal := readFile(t, filepath.Join(filepath.Dir(copyPath), journalFileName))
		if !bytes.Contains(journal, []byte(`"saved":true`)) {
			t.Fatal("saved flag")
		}
		startOut, stopOut := runProxy(t, bin, dir, core)
		if string(readFile(t, copyPath)) != exampleURI {
			t.Fatal("saved copy was deleted")
		}
		if !bytes.Equal(readFile(t, filepath.Join(filepath.Dir(copyPath), journalFileName)), journal) {
			t.Fatal("journal")
		}
		assertListeningOnly(t, startOut, stopOut)
	})
	t.Run("expired", func(t *testing.T) {
		// #given a journal that records expiry after takeover
		// #when issue, the phone confirm HTTP path, receive, proxy start, and proxy stop run
		// #then pair/ticket-<hash>/copy stays and is not marked saved
		keepObservedCopy(t, origin, bin, core, "expired")
	})
}

func TestPhoneConfirmCancelledKeepsCopy(t *testing.T) {
	// #given a loopback coordinator and a local copy that is already complete
	// #when the coordinator cancels that ticket before the consumed acknowledgment
	// #then proxy stop keeps pair/ticket-<hash>/copy from the server outcome
	// Receive must not exit 0 and this test must not write the journal afterward.
	// This coordinator admits three tickets, so cancellation uses its own loopback instance.
	root := moduleRoot(t)
	bin := buildDevctl(t, root)
	origin := startWrangler(t, root)
	core := lifecycleCore(t, root)
	dir, cancelBody := cancelDuringReceive(t, origin, bin)
	hash := oneTicketHash(t, dir)
	copyPath := ticketCopyPath(dir, hash)
	journalPath := filepath.Join(filepath.Dir(copyPath), journalFileName)
	journal := readFile(t, journalPath)
	record := decodeJournal(t, journal)
	if record.Phase != phaseCopyComplete || record.Observed != "cancelled" || record.Saved {
		t.Fatalf("journal %s", journal)
	}
	if bytes.Contains(journal, []byte(`"phase":"delivered"`)) || bytes.Contains(journal, []byte(`"saved"`)) {
		t.Fatalf("journal %s", journal)
	}
	if string(readFile(t, copyPath)) != exampleURI {
		t.Fatal("copy")
	}
	t.Logf("coordinator cancel response %s", bytes.TrimSpace(cancelBody))
	startOut, stopOut := runProxy(t, bin, dir, core)
	if string(readFile(t, copyPath)) != exampleURI {
		t.Fatal("copy was deleted")
	}
	if !bytes.Equal(readFile(t, journalPath), journal) {
		t.Fatal("journal")
	}
	assertListeningOnly(t, startOut, stopOut)
}

func keepObservedCopy(t *testing.T, origin, bin, core, observed string) {
	t.Helper()
	dir := takeover(t, origin, bin, "")
	hash := oneTicketHash(t, dir)
	copyPath := ticketCopyPath(dir, hash)
	markPostTakeover(t, filepath.Dir(copyPath), observed)
	journal := readFile(t, filepath.Join(filepath.Dir(copyPath), journalFileName))
	if bytes.Contains(journal, []byte(`"saved"`)) || bytes.Contains(journal, []byte(`"phase":"delivered"`)) {
		t.Fatal("treated as saved")
	}
	if !bytes.Contains(journal, []byte(`"observed":"`+observed+`"`)) {
		t.Fatal("observed")
	}
	startOut, stopOut := runProxy(t, bin, dir, core)
	if string(readFile(t, copyPath)) != exampleURI {
		t.Fatal("copy was deleted")
	}
	if !bytes.Equal(readFile(t, filepath.Join(filepath.Dir(copyPath), journalFileName)), journal) {
		t.Fatal("journal")
	}
	assertListeningOnly(t, startOut, stopOut)
}

func takeover(t *testing.T, origin, bin, saveDir string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	issuerDir := t.TempDir()
	receiverDir := t.TempDir()
	t.Cleanup(func() { stopProxy(bin, receiverDir) })
	args := []string{"--debug", "pair", "receive", "--coordinator", origin}
	if saveDir != "" {
		args = append(args, "--save-dir", saveDir)
	}
	receive := startDevctl(t, ctx, bin, receiverDir, args...)
	defer receive.stop()
	page := receive.stdout.waitLine(t, ctx, "#sc=")
	sessionCap, err := decodeFragment(page)
	if err != nil {
		t.Fatal(err)
	}
	issue := startDevctl(t, ctx, bin, issuerDir, "--debug", "pair", "issue", "--coordinator", origin)
	defer issue.stop()
	issue.stderr.waitContains(t, ctx, "Hysteria2 URI:")
	issue.write(exampleURI)
	issue.stderr.waitContains(t, ctx, "Transfer passphrase (not this computer's login password):")
	issue.write(examplePassphrase)
	issue.stderr.waitContains(t, ctx, "Transfer passphrase again:")
	issue.write(examplePassphrase)
	ticketLine := issue.stdout.waitLine(t, ctx, "dct1.")
	if issue.wait() != 0 {
		t.Fatalf("issue exit, stderr %s", issue.stderr.String())
	}
	ticket, err := b64url.DecodeString(strings.TrimPrefix(ticketLine, "dct1."))
	if err != nil || len(ticket) != 32 {
		t.Fatal("ticket text")
	}
	_, issuer := readIssuer(t, issuerDir)
	confirmFromPhonePage(t, ctx, origin, sessionCap, ticket, issuer)
	receive.stderr.waitContains(t, ctx, "Transfer passphrase (not this computer's login password):")
	receive.write(examplePassphrase)
	if receive.wait() != 0 {
		t.Fatalf("receive exit, stderr %s", receive.stderr.String())
	}
	return receiverDir
}

func cancelDuringReceive(t *testing.T, origin, bin string) (string, []byte) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	issuerDir := t.TempDir()
	receiverDir := t.TempDir()
	t.Cleanup(func() { stopProxy(bin, receiverDir) })
	hold, receive := startHeldDevctl(t, ctx, bin, receiverDir, "--debug", "pair", "receive", "--coordinator", origin)
	defer receive.stop()
	page := receive.stdout.waitLine(t, ctx, "#sc=")
	sessionCap, err := decodeFragment(page)
	if err != nil {
		t.Fatal(err)
	}
	issue := startDevctl(t, ctx, bin, issuerDir, "--debug", "pair", "issue", "--coordinator", origin)
	defer issue.stop()
	issue.stderr.waitContains(t, ctx, "Hysteria2 URI:")
	issue.write(exampleURI)
	issue.stderr.waitContains(t, ctx, "Transfer passphrase (not this computer's login password):")
	issue.write(examplePassphrase)
	issue.stderr.waitContains(t, ctx, "Transfer passphrase again:")
	issue.write(examplePassphrase)
	ticketLine := issue.stdout.waitLine(t, ctx, "dct1.")
	if issue.wait() != 0 {
		t.Fatalf("issue exit, stderr %s", issue.stderr.String())
	}
	ticket, err := b64url.DecodeString(strings.TrimPrefix(ticketLine, "dct1."))
	if err != nil || len(ticket) != 32 {
		t.Fatal("ticket text")
	}
	_, issuer := readIssuer(t, issuerDir)
	confirmFromPhonePage(t, ctx, origin, sessionCap, ticket, issuer)
	receive.stderr.waitContains(t, ctx, "Transfer passphrase (not this computer's login password):")
	receive.write(examplePassphrase)
	hold.wait(t, receive)
	if hold.kind != "challenge" {
		t.Fatalf("held %s, want the op challenge before the acknowledgment", hold.kind)
	}
	hash := oneTicketHash(t, receiverDir)
	sum := sha256.Sum256(ticket)
	if hexEncode(sum[:]) != hash {
		t.Fatal("ticket hash")
	}
	copyPath := ticketCopyPath(receiverDir, hash)
	if string(readFile(t, copyPath)) != exampleURI {
		t.Fatal("copy was not complete")
	}
	record := decodeJournal(t, readFile(t, filepath.Join(filepath.Dir(copyPath), journalFileName)))
	if record.Phase != phaseCopyComplete || record.Observed != "" || record.Saved {
		t.Fatalf("journal before cancel %+v", record)
	}
	if state := ticketStatus(t, ctx, origin, ticket, issuer); state != "bound" {
		t.Fatalf("state before cancel %s", state)
	}
	cancelBody := cancelTicket(t, ctx, origin, ticket, issuer)
	if state := ticketStatus(t, ctx, origin, ticket, issuer); state != "cancelled" {
		t.Fatalf("state after cancel %s body %s", state, bytes.TrimSpace(cancelBody))
	}
	hold.release()
	if code := receive.wait(); code != 1 {
		t.Fatalf("receive exit %d, stderr %s", code, receive.stderr.String())
	}
	if !strings.Contains(receive.stderr.String(), "cancelled:") {
		t.Fatalf("stderr %s", receive.stderr.String())
	}
	if state := ticketStatus(t, ctx, origin, ticket, issuer); state != "cancelled" {
		t.Fatalf("state after receive %s", state)
	}
	return receiverDir, cancelBody
}

func cancelTicket(t *testing.T, ctx context.Context, origin string, ticket, issuer []byte) []byte {
	t.Helper()
	if err := loadWire(); err != nil {
		t.Fatal(err)
	}
	var routes struct {
		Routes struct {
			Challenge string `json:"ticket_challenge"`
			Cancel    string `json:"ticket_cancel"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(vocabularyJSON, &routes); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(ticket)
	status, chalBody := postRaw(t, ctx, origin, routes.Routes.Challenge, struct {
		V          int    `json:"v"`
		TicketHash string `json:"ticket_hash"`
		Purpose    string `json:"purpose"`
	}{V: protocolVersion, TicketHash: hexEncode(sum[:]), Purpose: "cancel"})
	var challenged resultBody
	if err := json.Unmarshal(chalBody, &challenged); err != nil || status != http.StatusOK || challenged.Error != "" || challenged.Nonce == "" {
		t.Fatalf("cancel challenge %d %s", status, chalBody)
	}
	nonce, err := decodeFixed(challenged.Nonce, wireSpec.NonceBytes)
	if err != nil {
		t.Fatal(err)
	}
	issuerHash := sha256.Sum256(issuer)
	digest, err := digestBytes("cancel", signParts{
		nonce:      nonce,
		ticketHash: sum[:],
		issuerHash: issuerHash[:],
	})
	if err != nil {
		t.Fatal(err)
	}
	status, body := postRaw(t, ctx, origin, routes.Routes.Cancel, struct {
		V      int    `json:"v"`
		Ticket string `json:"ticket"`
		Issuer string `json:"issuer_capability"`
		Nonce  string `json:"nonce"`
		Digest string `json:"digest"`
	}{
		V:      protocolVersion,
		Ticket: b64url.EncodeToString(ticket),
		Issuer: b64url.EncodeToString(issuer),
		Nonce:  challenged.Nonce,
		Digest: b64url.EncodeToString(digest),
	})
	var result resultBody
	if err := json.Unmarshal(body, &result); err != nil || status != http.StatusOK || result.Error != "" || result.State != "cancelled" {
		t.Fatalf("cancel %d %s", status, body)
	}
	return body
}

func postRaw(t *testing.T, ctx context.Context, origin, path string, payload any) (int, []byte) {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+path, &buf)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) { return nil, nil },
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := readLimited(resp)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, body
}

func decodeJournal(t *testing.T, body []byte) journal {
	t.Helper()
	var record journal
	if err := json.Unmarshal(body, &record); err != nil {
		t.Fatal(err)
	}
	return record
}

func confirmFromPhonePage(t *testing.T, ctx context.Context, origin string, sessionCap, ticket, issuer []byte) {
	t.Helper()
	var routes struct {
		Routes struct {
			Page            string `json:"page"`
			SessionPreview  string `json:"session_preview"`
			TicketPreview   string `json:"ticket_preview"`
			TicketChallenge string `json:"ticket_challenge"`
			TicketConfirm   string `json:"ticket_confirm"`
			TicketRead      string `json:"ticket_read"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(vocabularyJSON, &routes); err != nil {
		t.Fatal(err)
	}
	page := getBody(t, origin+routes.Routes.Page)
	if !bytes.Contains(page, []byte(">Confirm<")) || !bytes.Contains(page, []byte(`src="/page.js"`)) {
		t.Fatal("phone page")
	}
	script := getBody(t, origin+"/page.js")
	if !bytes.Contains(script, []byte("confirm: true")) || !bytes.Contains(script, []byte(routes.Routes.TicketConfirm)) {
		t.Fatal("phone confirm script")
	}
	if bytes.Contains(script, []byte(routes.Routes.TicketRead)) || bytes.Contains(script, []byte("decrypt")) {
		t.Fatal("phone script")
	}
	client, err := dialCoordinator(origin)
	if err != nil {
		t.Fatal(err)
	}
	defer client.close()
	sessionText := b64url.EncodeToString(sessionCap)
	ticketText := b64url.EncodeToString(ticket)
	session, err := client.post(ctx, routes.Routes.SessionPreview, struct {
		V       int    `json:"v"`
		Session string `json:"session_capability"`
	}{V: protocolVersion, Session: sessionText})
	if err != nil || session.Fingerprint == "" || session.Pubkey == "" {
		t.Fatalf("session preview %v", err)
	}
	preview, err := client.post(ctx, routes.Routes.TicketPreview, struct {
		V      int    `json:"v"`
		Ticket string `json:"ticket"`
	}{V: protocolVersion, Ticket: ticketText})
	if err != nil || preview.State != "open" || preview.Envelope != "" {
		t.Fatalf("ticket preview %v state %s", err, preview.State)
	}
	if state := ticketStatus(t, ctx, origin, ticket, issuer); state != "open" {
		t.Fatalf("preview bound the ticket: %s", state)
	}
	sum := sha256.Sum256(ticket)
	challenged, err := client.post(ctx, routes.Routes.TicketChallenge, struct {
		V          int    `json:"v"`
		TicketHash string `json:"ticket_hash"`
		Purpose    string `json:"purpose"`
	}{V: protocolVersion, TicketHash: hexEncode(sum[:]), Purpose: "confirm"})
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := decodeFixed(challenged.Nonce, wireSpec.NonceBytes)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := decodeFixed(session.Pubkey, wireSpec.PubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	sessionHash := sha256.Sum256(sessionCap)
	digest, err := digestBytes("confirm", signParts{
		nonce:       nonce,
		sessionHash: sessionHash[:],
		ticketHash:  sum[:],
		pub:         pub,
	})
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := client.post(ctx, routes.Routes.TicketConfirm, struct {
		V       int    `json:"v"`
		Ticket  string `json:"ticket"`
		Session string `json:"session_capability"`
		Confirm bool   `json:"confirm"`
		Nonce   string `json:"nonce"`
		Digest  string `json:"digest"`
	}{
		V:       protocolVersion,
		Ticket:  ticketText,
		Session: sessionText,
		Confirm: true,
		Nonce:   challenged.Nonce,
		Digest:  b64url.EncodeToString(digest),
	})
	if err != nil || confirmed.State != "bound" || confirmed.Fingerprint != session.Fingerprint || confirmed.Envelope != "" {
		t.Fatalf("confirm %v state %s", err, confirmed.State)
	}
	if state := ticketStatus(t, ctx, origin, ticket, issuer); state != "bound" {
		t.Fatalf("state %s", state)
	}
}

func runProxy(t *testing.T, bin, configDir, core string) (string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	startOut := runDevctl(t, ctx, bin, configDir, "proxy", "start", "--core", core)
	stopOut := runDevctl(t, ctx, bin, configDir, "proxy", "stop")
	assertListeningOnly(t, startOut, stopOut)
	return startOut, stopOut
}

func assertListeningOnly(t *testing.T, startOut, stopOut string) {
	t.Helper()
	if strings.Contains(startOut, "ready") || strings.Contains(stopOut, "ready") || strings.Contains(startOut, exampleURI) {
		t.Fatal("output")
	}
	if !listenLine.MatchString(startOut) || stopOut != proxyStopped {
		t.Fatalf("start %q stop %q", startOut, stopOut)
	}
}

func runDevctl(t *testing.T, ctx context.Context, bin, configDir string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = cleanEnv(configDir)
	cmd.Dir = configDir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s: %v\n%s%s", strings.Join(args, " "), err, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr %s", stderr.String())
	}
	return stdout.String()
}

func stopProxy(bin, configDir string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "proxy", "stop")
	cmd.Env = cleanEnv(configDir)
	cmd.Dir = configDir
	_ = cmd.Run()
}

func getBody(t *testing.T, rawURL string) []byte {
	t.Helper()
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) { return nil, nil },
		},
	}
	resp, err := client.Get(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := readLimited(resp)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s %d %v", rawURL, resp.StatusCode, err)
	}
	return body
}

func readLimited(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 1<<20 {
		return nil, bytes.ErrTooLarge
	}
	return body, nil
}

func oneTicketHash(t *testing.T, configDir string) string {
	t.Helper()
	root := filepath.Join(configDir, pairFolderName)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var hash string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() && strings.HasPrefix(name, "ticket-") {
			if hash != "" {
				t.Fatal("two tickets")
			}
			hash = strings.TrimPrefix(name, "ticket-")
		}
	}
	if len(hash) != sha256.Size*2 {
		t.Fatal("ticket hash")
	}
	return hash
}

func ticketCopyPath(configDir, hash string) string {
	return filepath.Join(configDir, pairFolderName, "ticket-"+hash, copyFileName)
}

func markPostTakeover(t *testing.T, dir, state string) {
	t.Helper()
	path := filepath.Join(dir, journalFileName)
	body := readFile(t, path)
	var record journal
	if err := json.Unmarshal(body, &record); err != nil {
		t.Fatal(err)
	}
	if record.Phase != phaseDelivered {
		t.Fatalf("phase %s", record.Phase)
	}
	record.Phase = phaseCopyComplete
	record.Observed = state
	record.Saved = false
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func lifecycleCore(t *testing.T, root string) string {
	t.Helper()
	path := os.Getenv("DEVCTL_PROXY_CORE")
	if path == "" {
		return buildListenCore(t)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		t.Fatal(err)
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		t.Fatal("core path is inside the module")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		t.Fatal("core is not executable")
	}
	return resolved
}

func buildListenCore(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(src, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "go.mod"), []byte("module core\n\ngo 1.26.3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "main.go"), []byte(listenCoreProgram), 0o600); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "core")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	cmd.Dir = src
	cmd.Env = append(withoutGoFlags(os.Environ()), "CGO_ENABLED=0", "GO111MODULE=on")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("core build: %v\n%s", err, out)
	}
	return bin
}

func withoutGoFlags(env []string) []string {
	out := make([]string, 0, len(env))
	for _, item := range env {
		if strings.HasPrefix(item, "GOFLAGS=") {
			continue
		}
		out = append(out, item)
	}
	return out
}

const listenCoreProgram = `package main

import (
	"net"
	"os"
	"strconv"
	"strings"
)

func main() {
	configPath := flagValue("-f")
	body, err := os.ReadFile(configPath)
	if err != nil {
		os.Exit(2)
	}
	host, port, ok := socks(string(body))
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
`
