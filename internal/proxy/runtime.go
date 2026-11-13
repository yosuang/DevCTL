package proxy

import (
	"context"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const listenTimeout = 20 * time.Second

func launch(ctx context.Context, dir, exe string, port int, body []byte) error {
	if err := prepareDir(dir); err != nil {
		return err
	}
	configPath := filepath.Join(dir, "config.yaml")
	if err := writePrivate(configPath, body); err != nil {
		return err
	}
	addr := net.JoinHostPort(loopbackHost, strconv.Itoa(port))
	if err := writePrivate(filepath.Join(dir, "addr"), []byte(addr+"\n")); err != nil {
		return err
	}
	if err := writePrivate(filepath.Join(dir, "exe"), []byte(exe+"\n")); err != nil {
		return err
	}
	logPath := filepath.Join(dir, "core.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return local("copy_incomplete", "file protection could not be applied")
	}
	if err := restrictFile(logPath); err != nil {
		_ = logFile.Close()
		return err
	}
	stdin, err := os.Open(os.DevNull)
	if err != nil {
		_ = logFile.Close()
		return local("core_missing", "executable cannot be run")
	}
	cmd := exec.Command(exe, "-d", dir, "-f", configPath)
	cmd.Path = exe
	cmd.Dir = dir
	cmd.Env = childEnv()
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Stdin = stdin
	prepareChild(cmd)
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = logFile.Close()
		return local("core_missing", "executable cannot be run")
	}
	_ = stdin.Close()
	pid := cmd.Process.Pid
	if err := writePrivate(filepath.Join(dir, "pid"), []byte(strconv.Itoa(pid)+"\n")); err != nil {
		_ = terminate(context.Background(), pid)
		_ = cmd.Wait()
		_ = logFile.Close()
		return err
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)
	if err := waitListen(ctx, cmd, addr, sig, logFile); err != nil {
		return err
	}
	return writeListening(port)
}

func waitListen(ctx context.Context, cmd *exec.Cmd, addr string, sig <-chan os.Signal, logFile *os.File) error {
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		_ = logFile.Close()
		close(exited)
	}()
	deadline := time.NewTimer(listenTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		dialCtx, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
		cancel()
		if err == nil {
			_ = conn.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			_ = terminate(context.Background(), cmd.Process.Pid)
			<-exited
			return ctx.Err()
		case <-sig:
			_ = terminate(context.Background(), cmd.Process.Pid)
			<-exited
			return errInterrupted
		case <-exited:
			return errNotListening
		case <-deadline.C:
			_ = terminate(context.Background(), cmd.Process.Pid)
			<-exited
			return errNotListening
		case <-ticker.C:
		}
	}
}

func adopt(dir, exe string) (bool, error) {
	if _, err := os.Stat(dir); err != nil {
		return false, nil
	}
	pid, ok := readPID(filepath.Join(dir, "pid"))
	if !ok {
		return false, removeIfRuntime(dir)
	}
	alive, image := inspect(pid)
	if !alive {
		return false, removeIfRuntime(dir)
	}
	want, err := readText(filepath.Join(dir, "exe"))
	if err != nil || !samePath(want, exe) || !imageMatch(image, exe) {
		return true, errProcessMatch
	}
	addr, port, ok := readLoopback(filepath.Join(dir, "addr"))
	if !ok || !portAccepts(addr) {
		return true, errNotListening
	}
	if err := writeListening(port); err != nil {
		return true, err
	}
	return true, nil
}

func removeIfRuntime(dir string) error {
	if _, ok := parseRuntimeName(filepath.Base(dir)); !ok {
		return errProcessMatch
	}
	if err := os.RemoveAll(dir); err != nil {
		return local("copy_incomplete", "file protection could not be applied")
	}
	return nil
}

func stopOne(ctx context.Context, configDir, dir string) error {
	if !insideRuntime(configDir, dir) {
		return errProcessMatch
	}
	pid, ok := readPID(filepath.Join(dir, "pid"))
	if ok {
		alive, image := inspect(pid)
		if alive {
			want, err := readText(filepath.Join(dir, "exe"))
			if err != nil || !imageMatch(image, want) {
				return errProcessMatch
			}
			if err := terminate(ctx, pid); err != nil {
				return err
			}
		}
	}
	return removeRuntime(configDir, dir)
}

func processAliveIn(dir string) bool {
	pid, ok := readPID(filepath.Join(dir, "pid"))
	if !ok {
		return false
	}
	alive, _ := inspect(pid)
	return alive
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(loopbackHost, "0"))
	if err != nil {
		return 0, errNotListening
	}
	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok || addr == nil || addr.Port < 1 {
		_ = ln.Close()
		return 0, errNotListening
	}
	port := addr.Port
	if err := ln.Close(); err != nil {
		return 0, err
	}
	return port, nil
}

func portAccepts(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func childEnv() []string {
	keys := []string{
		"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
		"TMPDIR", "TMP", "TEMP",
		"SystemRoot", "WINDIR", "SYSTEMROOT", "PATHEXT",
	}
	env := make([]string, 0, len(keys))
	for _, key := range keys {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	return env
}

func executable(path string) (string, error) {
	if path == "" || !strings.ContainsAny(path, `/\`) {
		return "", local("core_missing", "executable is missing")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", local("core_missing", "executable is missing")
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", local("core_missing", "executable is missing")
	}
	info, err := os.Stat(resolved)
	if err != nil || info.IsDir() || !info.Mode().IsRegular() {
		return "", local("core_missing", "executable is missing")
	}
	if !executableMode(info.Mode()) {
		return "", local("core_missing", "executable is missing")
	}
	return resolved, nil
}

func prepareDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return local("copy_incomplete", "file protection could not be applied")
	}
	parent := filepath.Dir(dir)
	if err := restrictDir(parent); err != nil {
		return err
	}
	return restrictDir(dir)
}

func writePrivate(path string, data []byte) error {
	partial := path + ".partial"
	f, err := os.OpenFile(partial, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return local("copy_incomplete", "file protection could not be applied")
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(partial)
		return local("copy_incomplete", "file protection could not be applied")
	}
	if err := restrictFile(partial); err != nil {
		_ = os.Remove(partial)
		return err
	}
	if err := syncFile(partial); err != nil {
		_ = os.Remove(partial)
		return err
	}
	if err := os.Rename(partial, path); err != nil {
		_ = os.Remove(path)
		if err2 := os.Rename(partial, path); err2 != nil {
			_ = os.Remove(partial)
			return local("copy_incomplete", "file protection could not be applied")
		}
	}
	if err := restrictFile(path); err != nil {
		_ = os.Remove(path)
		return err
	}
	return syncDir(filepath.Dir(path))
}

func ticketRuntime(configDir, hash string) string {
	return filepath.Join(configDir, "proxy", "ticket-"+hash)
}

func insideRuntime(configDir, dir string) bool {
	root, err := filepath.Abs(filepath.Join(configDir, "proxy"))
	if err != nil {
		return false
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return false
	}
	_, ok := parseRuntimeName(rel)
	return ok
}

func removeRuntime(configDir, dir string) error {
	if !insideRuntime(configDir, dir) {
		return errProcessMatch
	}
	if err := os.RemoveAll(dir); err != nil {
		return local("copy_incomplete", "file protection could not be applied")
	}
	return nil
}

func matchingRuntimes(configDir, prefix string) ([]string, error) {
	root := filepath.Join(configDir, "proxy")
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, local("copy_incomplete", "no complete copy is available")
	}
	var dirs []string
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		hash, ok := parseRuntimeName(entry.Name())
		if !ok {
			continue
		}
		if prefix != "" && !strings.HasPrefix(hash, prefix) {
			continue
		}
		dirs = append(dirs, filepath.Join(root, entry.Name()))
	}
	return dirs, nil
}

func parseRuntimeName(name string) (string, bool) {
	hash, ok := strings.CutPrefix(name, "ticket-")
	if !ok || !validHash(hash) {
		return "", false
	}
	return hash, true
}

func validHash(hash string) bool {
	return len(hash) == 64 && isHex(hash)
}

func normalizePrefix(prefix string) (string, error) {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	if prefix == "" {
		return "", nil
	}
	if strings.Contains(prefix, "..") || strings.ContainsAny(prefix, `/\`) || !isHex(prefix) {
		return "", local("copy_incomplete", "no complete copy is available")
	}
	return prefix, nil
}

func isHex(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		default:
			return false
		}
	}
	return true
}

func readPID(path string) (int, bool) {
	text, err := readText(path)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(text)
	if err != nil || pid <= 1 {
		return 0, false
	}
	return pid, true
}

func readText(path string) (string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(body)), nil
}

func readLoopback(path string) (string, int, bool) {
	text, err := readText(path)
	if err != nil {
		return "", 0, false
	}
	host, portText, err := net.SplitHostPort(text)
	if err != nil || host != loopbackHost {
		return "", 0, false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, false
	}
	return net.JoinHostPort(host, portText), port, true
}

func imageMatch(got, want string) bool {
	got = strings.TrimSpace(strings.TrimSuffix(got, " (deleted)"))
	want = strings.TrimSpace(want)
	if got == "" || want == "" {
		return false
	}
	if samePath(got, want) {
		return true
	}
	return strings.HasPrefix(got, want+" ")
}

func samePath(left, right string) bool {
	if caseFoldPaths() {
		return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
	}
	a, errA := filepath.EvalSymlinks(left)
	b, errB := filepath.EvalSymlinks(right)
	if errA != nil || errB != nil {
		return filepath.Clean(left) == filepath.Clean(right)
	}
	return a == b
}

func waitUntilDead(ctx context.Context, pid int, timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		alive, _ := inspect(pid)
		if !alive {
			return true
		}
		select {
		case <-ctx.Done():
			alive, _ = inspect(pid)
			return !alive
		case <-timer.C:
			alive, _ = inspect(pid)
			return !alive
		case <-ticker.C:
		}
	}
}
