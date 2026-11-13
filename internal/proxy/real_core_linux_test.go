//go:build linux

package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// loopbackAuth is a fixture password for the local upstream. It is not a credential.
const loopbackAuth = "test-auth-not-a-secret"

func TestRealCoreObservation(t *testing.T) {
	// #given an official core outside this module and a loopback upstream with test credentials
	// #when that URI is started, downloaded through, stopped, and started again
	// #then forwarding, loopback binding, no management endpoint, process stop, cleanup, and recovery are observed
	// A skip below is not a ready observation.
	core := realCorePath(t)
	work := t.TempDir()
	upstreamPort, upstreamPID, pin := startUpstream(t, core, work)
	origin := startOrigin(t, upstreamPID)
	uri := fmt.Sprintf(
		"hysteria2://%s@%s/?sni=example.invalid&pinSHA256=%s",
		loopbackAuth,
		net.JoinHostPort(loopbackHost, strconv.Itoa(upstreamPort)),
		pin,
	)

	dir := t.TempDir()
	keep(t, dir)
	copyDir := plantCopy(t, dir, 0x11, "copy_complete", "", uri)
	journal := readFile(t, filepath.Join(copyDir, "journal"))

	first := observeSession(t, dir, core, work, upstreamPort, pin, origin)
	assertSameBytes(t, filepath.Join(copyDir, "journal"), journal)
	stopOwned(t, dir, copyDir, uri, journal, first.pid, first.addr)

	copyDir = plantCopy(t, dir, 0x11, "copy_complete", "", uri)
	journal = readFile(t, filepath.Join(copyDir, "journal"))
	second := observeSession(t, dir, core, work, upstreamPort, pin, origin)
	if second.pid == first.pid || processAlive(first.pid) {
		t.Fatalf("recovery pid %d", second.pid)
	}
	stopOwned(t, dir, copyDir, uri, journal, second.pid, second.addr)
	t.Logf(
		"forwarded through %s then %s; pids %d and %d; upstream %d",
		first.addr, second.addr, first.pid, second.pid, upstreamPID,
	)
}

type sessionObs struct {
	pid  int
	addr string
	port int
}

func observeSession(t *testing.T, dir, core, work string, upstreamPort int, pin string, origin *loopbackOrigin) sessionObs {
	t.Helper()
	out, err := callStart(t, dir, "", core)
	if err != nil {
		t.Fatalf("start %v\nclient %s\nupstream %s", err, logTail(t, filepath.Join(runtimeDir(dir, 0x11), "core.log")), logTail(t, filepath.Join(work, "upstream.log")))
	}
	if strings.Contains(out, "ready") || strings.Contains(out, loopbackAuth) {
		t.Fatal("output")
	}
	port := listenPort(t, out)
	pid := readRuntimePID(t, dir)
	assertCoreImage(t, pid, core)
	assertOwnedLoopback(t, pid, port)
	assertNoManagement(t, dir, port, upstreamPort, pin)
	if err := origin.download(port); err != nil {
		t.Fatalf("forward %v\nclient %s\nupstream %s", err, logTail(t, filepath.Join(runtimeDir(dir, 0x11), "core.log")), logTail(t, filepath.Join(work, "upstream.log")))
	}
	return sessionObs{pid: pid, port: port, addr: net.JoinHostPort(loopbackHost, strconv.Itoa(port))}
}

func stopOwned(t *testing.T, dir, copyDir, uri string, journal []byte, pid int, addr string) {
	t.Helper()
	out, err := callStop(t, dir, "")
	if err != nil || out != "stopped\n"+credentialNotice {
		t.Fatalf("stop %v %q", err, redact(out))
	}
	if strings.Contains(out, "ready") || strings.Contains(out, loopbackAuth) {
		t.Fatal("stop output")
	}
	if processAlive(pid) {
		t.Fatal("process still alive")
	}
	conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Fatal("port still accepts")
	}
	if _, statErr := os.Stat(runtimeDir(dir, 0x11)); !os.IsNotExist(statErr) {
		t.Fatal("runtime remains")
	}
	if _, statErr := os.Stat(filepath.Join(copyDir, "copy")); !os.IsNotExist(statErr) {
		t.Fatal("temporary plaintext remains")
	}
	assertSameBytes(t, filepath.Join(copyDir, "journal"), journal)
}

func realCorePath(t *testing.T) string {
	t.Helper()
	path := os.Getenv("DEVCTL_PROXY_CORE")
	if path == "" {
		t.Skip("real Mihomo binary was not observed; ready is untested")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		t.Fatal(err)
	}
	root := moduleRoot(t)
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

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func startUpstream(t *testing.T, core, work string) (int, int, string) {
	t.Helper()
	conn, err := net.ListenPacket("udp", net.JoinHostPort(loopbackHost, "0"))
	if err != nil {
		t.Fatal(err)
	}
	udp, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || udp.Port < 1 {
		_ = conn.Close()
		t.Fatal("udp port")
	}
	port := udp.Port
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, pin, err := newUpstreamCert()
	if err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(work, "cert.pem")
	keyPath := filepath.Join(work, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(`allow-lan: false
bind-address: "127.0.0.1"
mode: rule
find-process-mode: off
log-level: info
ipv6: false
geo-auto-update: false
listeners:
  - name: "upstream"
    type: "hysteria2"
    listen: "127.0.0.1"
    port: %d
    users:
      test-user: %s
    certificate: %s
    private-key: %s
    ignore-client-bandwidth: true
rules:
  - MATCH,DIRECT
`, port, strconv.Quote(loopbackAuth), strconv.Quote(certPath), strconv.Quote(keyPath))
	if err := os.WriteFile(filepath.Join(work, "upstream.yaml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.OpenFile(filepath.Join(work, "upstream.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(core, "-d", work, "-f", filepath.Join(work, "upstream.yaml"))
	cmd.Dir = work
	cmd.Env = []string{"HOME=" + work, "TMPDIR=" + work, "LANG=C", "PATH=" + os.Getenv("PATH")}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		_ = logFile.Close()
		close(done)
	}()
	t.Cleanup(func() {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	})
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-done:
			t.Fatalf("upstream exited\n%s", logTail(t, filepath.Join(work, "upstream.log")))
		default:
		}
		if udpBound(pid, port) {
			return port, pid, pin
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("upstream did not listen\n%s", logTail(t, filepath.Join(work, "upstream.log")))
	return 0, 0, ""
}

type loopbackOrigin struct {
	port     int
	token    string
	upstream int
	mu       sync.Mutex
	hits     []originHit
}

type originHit struct {
	path string
	pid  int
	err  string
}

func startOrigin(t *testing.T, upstreamPID int) *loopbackOrigin {
	t.Helper()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	origin := &loopbackOrigin{
		token:    "devctl-loopback-" + hex.EncodeToString(raw),
		upstream: upstreamPID,
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(loopbackHost, "0"))
	if err != nil {
		t.Fatal(err)
	}
	tcp, ok := ln.Addr().(*net.TCPAddr)
	if !ok || tcp.Port < 1 {
		_ = ln.Close()
		t.Fatal("origin port")
	}
	origin.port = tcp.Port
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, text, splitErr := net.SplitHostPort(r.RemoteAddr)
			hit := originHit{path: r.URL.Path}
			if splitErr != nil || host != loopbackHost {
				hit.err = r.RemoteAddr
			} else {
				remotePort, convErr := strconv.Atoi(text)
				if convErr != nil {
					hit.err = r.RemoteAddr
				} else if pid, ownErr := establishedOwner(remotePort, origin.port); ownErr != nil {
					hit.err = ownErr.Error()
				} else {
					hit.pid = pid
				}
			}
			origin.mu.Lock()
			origin.hits = append(origin.hits, hit)
			origin.mu.Unlock()
			if r.URL.Path != "/token" {
				http.NotFound(w, r)
				return
			}
			_, _ = io.WriteString(w, origin.token)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return origin
}

func (o *loopbackOrigin) download(socksPort int) error {
	before := o.snapshot()
	body, err := socksGet(socksPort, o.port)
	if err != nil {
		return err
	}
	if !strings.Contains(body, o.token) {
		return errors.New("proxied body did not contain the origin token")
	}
	after := o.snapshot()
	hits := after[len(before):]
	if len(hits) != 1 || hits[0].path != "/token" || hits[0].err != "" || hits[0].pid != o.upstream {
		return fmt.Errorf("origin saw %+v", hits)
	}
	return nil
}

func (o *loopbackOrigin) snapshot() []originHit {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]originHit, len(o.hits))
	copy(out, o.hits)
	return out
}

func socksGet(proxyPort, destPort int) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(loopbackHost, strconv.Itoa(proxyPort)), 3*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		return "", err
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return "", err
	}
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", err
	}
	if head[0] != 0x05 || head[1] != 0x00 {
		return "", fmt.Errorf("socks greeting %d", head[1])
	}
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, net.ParseIP(loopbackHost).To4()...)
	req = append(req, byte(destPort>>8), byte(destPort))
	if _, err := conn.Write(req); err != nil {
		return "", err
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return "", err
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		return "", fmt.Errorf("socks connect %d", reply[1])
	}
	if err := discardSocksBind(conn, reply[3]); err != nil {
		return "", err
	}
	if _, err := io.WriteString(conn, "GET /token HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"); err != nil {
		return "", err
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func discardSocksBind(r io.Reader, atyp byte) error {
	switch atyp {
	case 0x01:
		_, err := io.ReadFull(r, make([]byte, 6))
		return err
	case 0x04:
		_, err := io.ReadFull(r, make([]byte, 18))
		return err
	case 0x03:
		n := make([]byte, 1)
		if _, err := io.ReadFull(r, n); err != nil {
			return err
		}
		_, err := io.ReadFull(r, make([]byte, int(n[0])+2))
		return err
	default:
		return fmt.Errorf("socks address %d", atyp)
	}
}

func assertNoManagement(t *testing.T, dir string, socksPort, upstreamPort int, pin string) {
	t.Helper()
	body := readFile(t, filepath.Join(runtimeDir(dir, 0x11), "config.yaml"))
	doc := assertSafeConfig(t, body, socksPort)
	item := proxyItem(t, doc)
	gotPort, ok := item["port"].(int)
	fp, _ := item["fingerprint"].(string)
	if item["server"] != loopbackHost || !ok || gotPort != upstreamPort {
		t.Fatal("upstream")
	}
	if _, skip := item["skip-cert-verify"]; skip || item["sni"] != "example.invalid" || fp != pin {
		t.Fatal("tls")
	}
	text := string(body)
	for _, token := range []string{"external-controller", "external-ui", "0.0.0.0", "tproxy-port"} {
		if strings.Contains(text, token) {
			t.Fatalf("config contains %s", token)
		}
	}
}

func assertOwnedLoopback(t *testing.T, pid, port int) {
	t.Helper()
	tcp := boundSockets(t, pid, []string{"/proc/net/tcp", "/proc/net/tcp6"}, "0A")
	if len(tcp) == 0 {
		t.Fatal("no tcp listener")
	}
	saw := false
	for _, addr := range tcp {
		host, got, ok := splitHostPort(addr)
		ip := net.ParseIP(host)
		if !ok || ip == nil || !ip.IsLoopback() || got != port {
			t.Fatalf("tcp listener %s", addr)
		}
		if host == loopbackHost {
			saw = true
		}
	}
	if !saw {
		t.Fatal("missing 127.0.0.1 listener")
	}
	for _, addr := range boundSockets(t, pid, []string{"/proc/net/udp", "/proc/net/udp6"}, "07") {
		host, got, ok := splitHostPort(addr)
		if !ok || got == 0 {
			continue
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() || got != port {
			t.Fatalf("udp listener %s", addr)
		}
	}
}

func assertCoreImage(t *testing.T, pid int, core string) {
	t.Helper()
	got, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		t.Fatal(err)
	}
	got = strings.TrimSuffix(got, " (deleted)")
	if !samePath(got, core) {
		t.Fatalf("image %s", got)
	}
}

func boundSockets(t *testing.T, pid int, tables []string, state string) []string {
	t.Helper()
	inodes := socketInodes(t, pid)
	var addrs []string
	for _, table := range tables {
		body, err := os.ReadFile(table)
		if err != nil {
			continue
		}
		lines := strings.Split(string(body), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 || fields[3] != state {
				continue
			}
			if _, ok := inodes[fields[9]]; !ok {
				continue
			}
			host, port, ok := parseProcAddr(fields[1])
			if !ok {
				t.Fatalf("addr %s", fields[1])
			}
			addrs = append(addrs, net.JoinHostPort(host, strconv.Itoa(port)))
		}
	}
	return addrs
}

func udpBound(pid, port int) bool {
	inodes := map[string]struct{}{}
	entries, err := os.ReadDir("/proc/" + strconv.Itoa(pid) + "/fd")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "fd", entry.Name()))
		if err != nil || !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
			continue
		}
		inodes[target[len("socket:["):len(target)-1]] = struct{}{}
	}
	for _, table := range []string{"/proc/net/udp", "/proc/net/udp6"} {
		body, err := os.ReadFile(table)
		if err != nil {
			continue
		}
		lines := strings.Split(string(body), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 || fields[3] != "07" {
				continue
			}
			if _, ok := inodes[fields[9]]; !ok {
				continue
			}
			host, got, ok := parseProcAddr(fields[1])
			if ok && host == loopbackHost && got == port {
				return true
			}
		}
	}
	return false
}

func establishedOwner(localPort, remotePort int) (int, error) {
	inodes := map[string]struct{}{}
	for _, table := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		body, err := os.ReadFile(table)
		if err != nil {
			continue
		}
		lines := strings.Split(string(body), "\n")
		for _, line := range lines[1:] {
			fields := strings.Fields(line)
			if len(fields) < 10 || fields[3] != "01" {
				continue
			}
			host, lport, ok := parseProcAddr(fields[1])
			if !ok || lport != localPort || host != loopbackHost {
				continue
			}
			remoteHost, rport, ok := parseProcAddr(fields[2])
			if !ok || rport != remotePort || remoteHost != loopbackHost {
				continue
			}
			inodes[fields[9]] = struct{}{}
		}
	}
	if len(inodes) == 0 {
		return 0, errors.New("origin peer socket was not found")
	}
	var owners []int
	seen := map[int]struct{}{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}
	for _, entry := range entries {
		pid, convErr := strconv.Atoi(entry.Name())
		if convErr != nil || pid <= 1 {
			continue
		}
		fds, readErr := os.ReadDir(filepath.Join("/proc", entry.Name(), "fd"))
		if readErr != nil {
			continue
		}
		for _, fd := range fds {
			target, linkErr := os.Readlink(filepath.Join("/proc", entry.Name(), "fd", fd.Name()))
			if linkErr != nil || !strings.HasPrefix(target, "socket:[") || !strings.HasSuffix(target, "]") {
				continue
			}
			inode := target[len("socket:[") : len(target)-1]
			if _, ok := inodes[inode]; !ok {
				continue
			}
			if _, dup := seen[pid]; !dup {
				seen[pid] = struct{}{}
				owners = append(owners, pid)
			}
			break
		}
	}
	if len(owners) != 1 {
		return 0, fmt.Errorf("peer owners %v", owners)
	}
	return owners[0], nil
}

func newUpstreamCert() (certPEM, keyPEM []byte, pin string, err error) {
	cert, key, err := makeCert()
	if err != nil {
		return nil, nil, "", err
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, key.Public(), key)
	if err != nil {
		return nil, nil, "", err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, "", err
	}
	sum := sha256.Sum256(parsed.Raw)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, "", err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, hex.EncodeToString(sum[:]), nil
}

func makeCert() (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "example.invalid"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.invalid"},
		IPAddresses:  []net.IP{net.ParseIP(loopbackHost)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	return tmpl, key, nil
}

func assertSameBytes(t *testing.T, path string, want []byte) {
	t.Helper()
	if string(readFile(t, path)) != string(want) {
		t.Fatal(path)
	}
}

func redact(text string) string {
	return strings.ReplaceAll(text, loopbackAuth, "[redacted]")
}

func logTail(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		return err.Error()
	}
	text := redact(string(body))
	if len(text) > 1200 {
		text = text[len(text)-1200:]
	}
	return text
}

func splitHostPort(addr string) (string, int, bool) {
	host, text, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, false
	}
	port, err := strconv.Atoi(text)
	if err != nil {
		return "", 0, false
	}
	return host, port, true
}
