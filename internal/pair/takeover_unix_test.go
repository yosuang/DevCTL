//go:build unix

package pair

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestTakeoverUnixModes(t *testing.T) {
	previous := unix.Umask(0)
	t.Cleanup(func() { unix.Umask(previous) })

	config := t.TempDir()
	hash := exampleTicketHash(0x44)
	ticket, err := ticketPath(config, hash)
	if err != nil {
		t.Fatal("path")
	}
	if err := commitCopy(ticket, hash, []byte("envelope-bytes"), []byte(exampleURI)); err != nil {
		t.Fatalf("copy: %s", codeOf(err))
	}
	assertPerm(t, filepath.Join(config, pairFolderName), 0o700)
	assertPerm(t, ticket, 0o700)
	assertPerm(t, filepath.Join(ticket, copyFileName), 0o600)
	assertPerm(t, filepath.Join(ticket, journalFileName), 0o600)

	sessionHash := bytes.Repeat([]byte{0x71}, 32)
	if err := storeSession(config, sessionHash, bytes.Repeat([]byte{0x72}, 32), bytes.Repeat([]byte{0x73}, 32)); err != nil {
		t.Fatal("session")
	}
	sessionDir := filepath.Join(config, pairFolderName, "session-"+hex.EncodeToString(sessionHash))
	assertPerm(t, sessionDir, 0o700)
	assertPerm(t, filepath.Join(sessionDir, sessionKeyName), 0o600)
	assertPerm(t, filepath.Join(sessionDir, sessionCapName), 0o600)
}

func assertPerm(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal("stat")
	}
	if info.Mode().Perm() != want {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
}
