// Package proxy starts and stops a local core for one taken-over proxy URI.
// The core is an external executable. This module does not vendor or download it.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"

	"devctl/internal/pair"
)

const (
	loopbackHost = "127.0.0.1"

	// credentialNotice is the stop text. Stopping does not revoke the server credential.
	credentialNotice = "Stopping does not revoke the proxy credentials. The Hysteria2 authentication material stays valid on the proxy server until you change it there.\n"
)

var (
	userOut io.Writer = os.Stdout

	errNotListening = errors.New("loopback port did not accept a connection")
	errInterrupted  = errors.New("interrupted")
	errProcessMatch = errors.New("core process did not match")
	errDidNotExit   = errors.New("core did not exit")
)

type codeError struct {
	code string
	text string
}

func (e *codeError) Error() string {
	return e.code + ": " + e.text
}

func local(code, text string) error {
	return &codeError{code: code, text: text}
}

// Start runs the local core for one taken-over URI.
// It prints listening after 127.0.0.1 accepts a connection.
// It does not print ready. A crashed core stays stopped until the next Start.
func Start(ctx context.Context, configDir, ticketPrefix, corePath string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	exe, err := executable(corePath)
	if err != nil {
		return err
	}
	uri, hash, err := pair.LoadTakenOver(configDir, ticketPrefix)
	if err != nil {
		return err
	}
	if !validHash(hash) {
		return local("copy_incomplete", "no complete copy is available")
	}
	raw := []byte(uri)
	defer func() {
		zero(raw)
		runtime.KeepAlive(raw)
	}()
	parsed, err := parseURI(raw)
	if err != nil {
		return err
	}
	dir := ticketRuntime(configDir, hash)
	if !insideRuntime(configDir, dir) {
		return local("copy_incomplete", "no complete copy is available")
	}
	done, err := adopt(dir, exe)
	if done || err != nil {
		return err
	}
	port, err := freePort()
	if err != nil {
		return err
	}
	body, err := renderConfig(parsed, port)
	if err != nil {
		return err
	}
	defer func() {
		zero(body)
		runtime.KeepAlive(body)
	}()
	if err := launch(ctx, dir, exe, port, body); err != nil {
		if !processAliveIn(dir) {
			_ = removeRuntime(configDir, dir)
		}
		return err
	}
	return nil
}

// Stop signals the core for one ticket and deletes that runtime directory.
// It leaves the taken-over copy in place. It does not revoke server credentials.
func Stop(ctx context.Context, configDir, ticketPrefix string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if configDir == "" {
		return local("copy_incomplete", "no complete copy is available")
	}
	prefix, err := normalizePrefix(ticketPrefix)
	if err != nil {
		return err
	}
	dirs, err := matchingRuntimes(configDir, prefix)
	if err != nil {
		return err
	}
	if len(dirs) > 1 {
		return local("ticket_ambiguous", "more than one ticket matches")
	}
	if len(dirs) == 1 {
		if err := stopOne(ctx, configDir, dirs[0]); err != nil {
			return err
		}
		if err := writeUser("stopped\n"); err != nil {
			return err
		}
	}
	return writeUser(credentialNotice)
}

func writeUser(text string) error {
	if _, err := io.WriteString(userOut, text); err != nil {
		return err
	}
	return nil
}

func writeListening(port int) error {
	return writeUser(fmt.Sprintf("listening %s\n", net.JoinHostPort(loopbackHost, strconv.Itoa(port))))
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
