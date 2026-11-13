package pair

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/term"
)

// Takeover fixtures reuse the envelope examples. They are not secrets.
// fastEnvelopeKey stands in for Argon2 so these tests stay on the file and ACK rules.
// Envelope tests cover argon2.IDKey.

type recordingPrompt struct {
	pass      string
	err       error
	uriCalls  int
	passCalls int
	confirm   bool
}

func (p *recordingPrompt) URI() (string, error) {
	p.uriCalls++
	return "", localCode("uri_invalid", "uri is not usable")
}

func (p *recordingPrompt) Passphrase(confirm bool) (string, error) {
	p.passCalls++
	p.confirm = confirm
	if p.err != nil {
		return "", p.err
	}
	return p.pass, nil
}

func TestTakeoverIncompleteFileIsNotCopyComplete(t *testing.T) {
	config := t.TempDir()
	hash := exampleTicketHash(0x15)
	ticket, err := ticketPath(config, hash)
	if err != nil {
		t.Fatal("path")
	}
	if err := makePrivateDir(ticket); err != nil {
		t.Fatal("dir")
	}
	partial := filepath.Join(ticket, partialFileName)
	if err := os.WriteFile(partial, []byte("partial"), 0o600); err != nil {
		t.Fatal("partial")
	}
	if err := finishCopy(ticket, hash, []byte("env"), []byte("partial"), []byte(exampleURI)); codeOf(err) != "copy_incomplete" {
		t.Fatalf("mismatch: %s", codeOf(err))
	}
	if _, err := os.Stat(filepath.Join(ticket, copyFileName)); !os.IsNotExist(err) {
		t.Fatal("partial file was promoted")
	}
	if _, err := os.Stat(filepath.Join(ticket, journalFileName)); !os.IsNotExist(err) {
		t.Fatal("partial file became copy_complete")
	}
	effective := phaseNone
	if record, ok := copyReady(ticket, hash); ok {
		effective = record.Phase
	}
	if effective != phaseNone {
		t.Fatal("incomplete file is copy_complete")
	}

	acks := 0
	prompt := &recordingPrompt{err: localCode("passphrase_rejected", "stopped")}
	for range 2 {
		err = receiveCopy(config, "", prompt, hash, []byte("env"), func([]byte) (string, error) {
			acks++
			return "consumed", nil
		})
		if codeOf(err) != "passphrase_rejected" || prompt.uriCalls != 0 || acks != 0 {
			t.Fatalf("acked an incomplete file: code %s calls %d acks %d", codeOf(err), prompt.passCalls, acks)
		}
	}
	if prompt.passCalls != 2 {
		t.Fatal("a later receive skipped the passphrase")
	}
	if _, err := os.Stat(filepath.Join(ticket, journalFileName)); !os.IsNotExist(err) {
		t.Fatal("journal was written")
	}
}

func TestTakeoverCopyCompleteSurvivesFailedAck(t *testing.T) {
	useFastKDF(t)
	config := t.TempDir()
	logs := startLogCapture(t)
	hash := exampleTicketHash(0x31)
	env := sealFast(t, hash)
	prompt := &recordingPrompt{pass: examplePassphrase}
	acks := 0
	ack := func(sum []byte) (string, error) {
		acks++
		if !bytes.Equal(sum, digest(env)) {
			t.Fatal("ack hash")
		}
		return "", errors.New("down")
	}
	err := receiveCopy(config, "", prompt, hash, env, ack)
	if codeOf(err) != "ack_pending" || prompt.passCalls != 1 || prompt.uriCalls != 0 || prompt.confirm || acks != 1 {
		t.Fatalf("first: code %s pass %d uri %d acks %d", codeOf(err), prompt.passCalls, prompt.uriCalls, acks)
	}
	assertNoMaterial(t, err)
	ticket, err := ticketPath(config, hash)
	if err != nil {
		t.Fatal("path")
	}
	record, ok := copyReady(ticket, hash)
	if !ok || record.Phase != phaseCopyComplete {
		t.Fatal("failed ack did not keep copy_complete")
	}
	if _, err := os.Stat(filepath.Join(ticket, copyFileName)); err != nil {
		t.Fatal("copy is missing")
	}
	if countContaining(t, config, []byte(exampleURI)) != 1 {
		t.Fatal("default save left another plaintext uri")
	}
	if countContaining(t, config, []byte(examplePassphrase)) != 0 {
		t.Fatal("passphrase was stored")
	}
	if logContainsMaterial(logs) {
		t.Fatal("log contains example material")
	}

	err = receiveCopy(config, "", prompt, hash, nil, ack)
	if codeOf(err) != "ack_pending" || prompt.passCalls != 1 || prompt.uriCalls != 0 || acks != 2 {
		t.Fatalf("retry: code %s pass %d acks %d", codeOf(err), prompt.passCalls, acks)
	}
	record, ok = copyReady(ticket, hash)
	if !ok || record.Phase != phaseCopyComplete {
		t.Fatal("retry dropped copy_complete")
	}
	assertNoMaterial(t, err)
}

func TestTakeoverDeliveredOnlyAfterConsumed(t *testing.T) {
	useFastKDF(t)
	config := t.TempDir()
	hash := exampleTicketHash(0x32)
	env := sealFast(t, hash)
	prompt := &recordingPrompt{pass: examplePassphrase}
	acks := 0
	err := receiveCopy(config, "", prompt, hash, env, func([]byte) (string, error) {
		acks++
		return "consumed", nil
	})
	if err != nil || prompt.passCalls != 1 || acks != 1 {
		t.Fatalf("consume: %s pass %d acks %d", codeOf(err), prompt.passCalls, acks)
	}
	ticket, err := ticketPath(config, hash)
	if err != nil {
		t.Fatal("path")
	}
	record, ok := copyReady(ticket, hash)
	if !ok || record.Phase != phaseDelivered || record.Saved {
		t.Fatal("consumed was not delivered")
	}
	if _, err := os.Stat(filepath.Join(ticket, copyFileName)); err != nil {
		t.Fatal("delivered copy was deleted")
	}
	if countContaining(t, config, []byte(exampleURI)) != 1 {
		t.Fatal("default save left another plaintext uri")
	}
	err = receiveCopy(config, "", prompt, hash, nil, func([]byte) (string, error) {
		acks++
		return "consumed", nil
	})
	if err != nil || prompt.passCalls != 1 || acks != 1 {
		t.Fatalf("second: %s pass %d acks %d", codeOf(err), prompt.passCalls, acks)
	}
}

func TestTakeoverExpiryKeepsFileAndIsNotDelivered(t *testing.T) {
	for _, state := range []string{"expired", "cancelled"} {
		t.Run(state, func(t *testing.T) {
			useFastKDF(t)
			config := t.TempDir()
			save := t.TempDir()
			hash := exampleTicketHash(0x41)
			env := sealFast(t, hash)
			prompt := &recordingPrompt{pass: examplePassphrase}
			acks := 0
			err := receiveCopy(config, save, prompt, hash, env, func([]byte) (string, error) {
				acks++
				return state, nil
			})
			if codeOf(err) != state || prompt.passCalls != 1 || prompt.uriCalls != 0 || acks != 1 {
				t.Fatalf("first: code %s pass %d acks %d", codeOf(err), prompt.passCalls, acks)
			}
			assertNoMaterial(t, err)
			ticket, err := ticketPath(config, hash)
			if err != nil {
				t.Fatal("path")
			}
			record, ok := copyReady(ticket, hash)
			if !ok || record.Phase != phaseCopyComplete || record.Observed != state || !record.Saved {
				t.Fatal("server outcome was stored as delivered")
			}
			raw, err := os.ReadFile(filepath.Join(ticket, journalFileName))
			if err != nil || bytes.Contains(raw, []byte(`"phase":"delivered"`)) {
				t.Fatal("journal phase is delivered")
			}
			if _, err := os.Stat(filepath.Join(ticket, copyFileName)); err != nil {
				t.Fatal("copy was deleted")
			}
			saveFile := filepath.Join(save, "ticket-"+hex.EncodeToString(hash))
			if _, err := os.Stat(saveFile); err != nil {
				t.Fatal("explicit save is missing")
			}
			same, err := samePath(filepath.Join(ticket, copyFileName), saveFile)
			if err != nil || same {
				t.Fatal("save shares the ticket file")
			}
			loaded, gotHash, err := LoadTakenOver(config, "")
			if err != nil || gotHash != hex.EncodeToString(hash) {
				t.Fatalf("load: %s", codeOf(err))
			}
			if subtle.ConstantTimeCompare([]byte(loaded), []byte(exampleURI)) != 1 {
				t.Fatal("loaded copy mismatch")
			}

			err = receiveCopy(config, save, prompt, hash, nil, func([]byte) (string, error) {
				acks++
				return state, nil
			})
			if codeOf(err) != state || prompt.passCalls != 1 || acks != 2 {
				t.Fatalf("retry: code %s pass %d acks %d", codeOf(err), prompt.passCalls, acks)
			}
			record, ok = copyReady(ticket, hash)
			if !ok || record.Phase != phaseCopyComplete || record.Observed != state || !record.Saved {
				t.Fatal("retry marked the copy delivered")
			}
			if _, err := os.Stat(filepath.Join(ticket, copyFileName)); err != nil || mustStat(t, saveFile) {
				t.Fatal("retry deleted a copy")
			}
		})
	}
}

func TestExplicitSaveSurvivesConsumed(t *testing.T) {
	// #given a save directory
	// #when the copy is stored and the server reports consumed
	// #then the ticket journal is marked saved and the extra file is separate
	useFastKDF(t)
	config := t.TempDir()
	save := t.TempDir()
	hash := exampleTicketHash(0x33)
	env := sealFast(t, hash)
	prompt := &recordingPrompt{pass: examplePassphrase}
	if err := receiveCopy(config, save, prompt, hash, env, func([]byte) (string, error) {
		return "consumed", nil
	}); err != nil {
		t.Fatal(err)
	}
	ticket, err := ticketPath(config, hash)
	if err != nil {
		t.Fatal(err)
	}
	record, ok := copyReady(ticket, hash)
	if !ok || record.Phase != phaseDelivered || !record.Saved {
		t.Fatal("explicit save was dropped")
	}
	saveFile := filepath.Join(save, "ticket-"+hex.EncodeToString(hash))
	if _, err := os.Stat(saveFile); err != nil {
		t.Fatal("explicit save is missing")
	}
	same, err := samePath(filepath.Join(ticket, copyFileName), saveFile)
	if err != nil || same {
		t.Fatal("save shares the ticket file")
	}
}

func TestFailedExpiryJournalIsNotServerOutcome(t *testing.T) {
	// #given a default takeover and a journal install that fails
	// #when the server expires or cancels
	// #then the error is not that server outcome and stop leaves the plaintext
	for _, state := range []string{"expired", "cancelled"} {
		t.Run(state, func(t *testing.T) {
			useFastKDF(t)
			config := t.TempDir()
			hash := exampleTicketHash(0x51)
			env := sealFast(t, hash)
			prompt := &recordingPrompt{pass: examplePassphrase}
			err := receiveCopy(config, "", prompt, hash, env, func([]byte) (string, error) {
				return "", errors.New("down")
			})
			if codeOf(err) != "ack_pending" || prompt.passCalls != 1 {
				t.Fatalf("setup: %s", codeOf(err))
			}
			ticket, err := ticketPath(config, hash)
			if err != nil {
				t.Fatal(err)
			}
			prev := installJournalFile
			installJournalFile = func(string, string) error { return errors.New("full") }
			t.Cleanup(func() { installJournalFile = prev })
			err = receiveCopy(config, "", prompt, hash, nil, func([]byte) (string, error) {
				return state, nil
			})
			if codeOf(err) == state || codeOf(err) != "copy_incomplete" {
				t.Fatalf("outcome %s", codeOf(err))
			}
			assertNoMaterial(t, err)
			if _, err := os.Stat(filepath.Join(ticket, copyFileName)); err != nil {
				t.Fatal("copy is missing")
			}
			record, ok := copyReady(ticket, hash)
			if !ok || record.Phase != phaseCopyComplete || record.Saved || record.Observed != "" {
				t.Fatal("failed install changed the stored journal")
			}
			if err := ReleaseTemporary(config, ""); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(ticket, copyFileName)); err != nil {
				t.Fatal("stop deleted the plaintext")
			}
			record, ok = copyReady(ticket, hash)
			if !ok || record.Saved {
				t.Fatal("stop marked the default copy saved")
			}
		})
	}
}

func TestExpiryReadBackRequiresObserved(t *testing.T) {
	// #given a default takeover whose installed journal omits the server outcome
	// #when the server expires
	// #then the result is not that server outcome and stop leaves the plaintext
	useFastKDF(t)
	config := t.TempDir()
	hash := exampleTicketHash(0x52)
	env := sealFast(t, hash)
	prompt := &recordingPrompt{pass: examplePassphrase}
	if err := receiveCopy(config, "", prompt, hash, env, func([]byte) (string, error) {
		return "", errors.New("down")
	}); codeOf(err) != "ack_pending" {
		t.Fatalf("setup: %s", codeOf(err))
	}
	ticket, err := ticketPath(config, hash)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(filepath.Join(ticket, journalFileName))
	if err != nil {
		t.Fatal(err)
	}
	prev := installJournalFile
	installJournalFile = func(_, final string) error {
		return os.WriteFile(final, original, 0o600)
	}
	t.Cleanup(func() { installJournalFile = prev })
	err = receiveCopy(config, "", prompt, hash, nil, func([]byte) (string, error) {
		return "expired", nil
	})
	if codeOf(err) == "expired" || codeOf(err) != "copy_incomplete" {
		t.Fatalf("outcome %s", codeOf(err))
	}
	assertNoMaterial(t, err)
	if err := ReleaseTemporary(config, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(ticket, copyFileName)); err != nil {
		t.Fatal("stop deleted the plaintext")
	}
	record, ok := copyReady(ticket, hash)
	if !ok || record.Saved || record.Observed != "" {
		t.Fatal("default copy was marked saved")
	}
}

func TestTakeoverTwoTicketsUseTwoDirectories(t *testing.T) {
	useFastKDF(t)
	config := t.TempDir()
	var tickets []string
	for _, fill := range []byte{0x11, 0x22} {
		hash := exampleTicketHash(fill)
		env := sealFast(t, hash)
		prompt := &recordingPrompt{pass: examplePassphrase}
		if err := receiveCopy(config, "", prompt, hash, env, func([]byte) (string, error) {
			return "consumed", nil
		}); err != nil {
			t.Fatalf("receive: %s", codeOf(err))
		}
		ticket, err := ticketPath(config, hash)
		if err != nil {
			t.Fatal("path")
		}
		tickets = append(tickets, ticket)
	}
	if tickets[0] == tickets[1] {
		t.Fatal("tickets share a directory")
	}
	for _, name := range []string{copyFileName, journalFileName} {
		same, err := samePath(filepath.Join(tickets[0], name), filepath.Join(tickets[1], name))
		if err != nil || same {
			t.Fatal("tickets share a file")
		}
	}
	sessionHash := bytes.Repeat([]byte{0x5a}, 32)
	if err := storeSession(config, sessionHash, bytes.Repeat([]byte{0x42}, 32), bytes.Repeat([]byte{0x43}, 32)); err != nil {
		t.Fatal("session")
	}
	sessionDir := filepath.Join(config, pairFolderName, "session-"+hex.EncodeToString(sessionHash))
	if sessionDir == tickets[0] || sessionDir == tickets[1] {
		t.Fatal("session uses a ticket directory")
	}
	keyPath := filepath.Join(sessionDir, sessionKeyName)
	for _, ticket := range tickets {
		same, err := samePath(keyPath, filepath.Join(ticket, copyFileName))
		if err != nil || same {
			t.Fatal("session key shares a ticket file")
		}
		rel, err := filepath.Rel(ticket, sessionDir)
		if err != nil || !isOutside(rel) {
			t.Fatal("session directory is inside a ticket directory")
		}
	}
	if countContaining(t, sessionDir, []byte(exampleURI)) != 0 {
		t.Fatal("session directory holds the uri")
	}
	if _, _, err := LoadTakenOver(config, ""); codeOf(err) != "ticket_ambiguous" {
		t.Fatalf("prefix: %s", codeOf(err))
	}
	loaded, gotHash, err := LoadTakenOver(config, "1111")
	if err != nil || gotHash != hex.EncodeToString(exampleTicketHash(0x11)) {
		t.Fatalf("prefixed load: %s", codeOf(err))
	}
	if subtle.ConstantTimeCompare([]byte(loaded), []byte(exampleURI)) != 1 {
		t.Fatal("loaded copy mismatch")
	}
}

func TestTakeoverShortPassphraseDoesNotWrite(t *testing.T) {
	called := guardKDF(t)
	config := t.TempDir()
	hash := exampleTicketHash(0x51)
	prompt := &recordingPrompt{pass: "short"}
	acks := 0
	err := receiveCopy(config, "", prompt, hash, []byte("env"), func([]byte) (string, error) {
		acks++
		return "consumed", nil
	})
	if *called || codeOf(err) != "passphrase_rejected" || acks != 0 || prompt.passCalls != 1 {
		t.Fatalf("short: code %s called %v acks %d", codeOf(err), *called, acks)
	}
	ticket, pathErr := ticketPath(config, hash)
	if pathErr != nil {
		t.Fatal("path")
	}
	if _, statErr := os.Stat(ticket); !os.IsNotExist(statErr) {
		t.Fatal("short passphrase created a ticket directory")
	}
	assertNoMaterial(t, err)
}

func TestTakeoverWrongPassphraseDoesNotAck(t *testing.T) {
	useFastKDF(t)
	config := t.TempDir()
	hash := exampleTicketHash(0x52)
	env := sealFast(t, hash)
	wrong := []byte(examplePassphrase)
	wrong[len(wrong)-1]++
	prompt := &recordingPrompt{pass: string(wrong)}
	acks := 0
	err := receiveCopy(config, "", prompt, hash, env, func([]byte) (string, error) {
		acks++
		return "consumed", nil
	})
	if codeOf(err) != "passphrase_rejected" || acks != 0 {
		t.Fatalf("wrong passphrase: %s acks %d", codeOf(err), acks)
	}
	ticket, pathErr := ticketPath(config, hash)
	if pathErr != nil {
		t.Fatal("path")
	}
	if _, statErr := os.Stat(filepath.Join(ticket, copyFileName)); !os.IsNotExist(statErr) {
		t.Fatal("wrong passphrase wrote a copy")
	}
	assertNoMaterial(t, err)
}

func TestTakeoverInvalidURIDoesNotAck(t *testing.T) {
	useFastKDF(t)
	config := t.TempDir()
	hash := exampleTicketHash(0x53)
	raw, err := sealEnvelope(examplePassphrase, hash, []byte("http://user@192.0.2.1/"))
	if err != nil {
		t.Fatal("seal")
	}
	prompt := &recordingPrompt{pass: examplePassphrase}
	acks := 0
	err = receiveCopy(config, "", prompt, hash, raw, func([]byte) (string, error) {
		acks++
		return "consumed", nil
	})
	if codeOf(err) != "uri_invalid" || acks != 0 {
		t.Fatalf("invalid uri: %s acks %d", codeOf(err), acks)
	}
	ticket, pathErr := ticketPath(config, hash)
	if pathErr != nil {
		t.Fatal("path")
	}
	if _, statErr := os.Stat(filepath.Join(ticket, copyFileName)); !os.IsNotExist(statErr) {
		t.Fatal("invalid uri wrote a copy")
	}
	assertNoMaterial(t, err)
}

func TestTerminalPrompterRejectsNonTTY(t *testing.T) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		t.Skip("stdin is a terminal")
	}
	prompt := TerminalPrompter()
	if _, err := prompt.URI(); codeOf(err) != "not_a_tty" {
		t.Fatalf("uri: %s", codeOf(err))
	}
	if _, err := prompt.Passphrase(true); codeOf(err) != "not_a_tty" {
		t.Fatalf("passphrase: %s", codeOf(err))
	}
}

func useFastKDF(t *testing.T) {
	t.Helper()
	swapKDF(t, fastEnvelopeKey)
}

func fastEnvelopeKey(password, salt []byte, _, _ uint32, _ uint8, keyLen uint32) []byte {
	mac := hmac.New(sha256.New, salt)
	_, _ = mac.Write(password)
	sum := mac.Sum(nil)
	out := make([]byte, keyLen)
	copy(out, sum)
	return out
}

func sealFast(t *testing.T, ticketHash []byte) []byte {
	t.Helper()
	raw, err := sealEnvelope(examplePassphrase, ticketHash, []byte(exampleURI))
	if err != nil {
		t.Fatalf("seal: %s", codeOf(err))
	}
	return raw
}

func digest(raw []byte) []byte {
	sum := sha256.Sum256(raw)
	return sum[:]
}

func samePath(left, right string) (bool, error) {
	a, err := os.Stat(left)
	if err != nil {
		return false, err
	}
	b, err := os.Stat(right)
	if err != nil {
		return false, err
	}
	return os.SameFile(a, b), nil
}

func isOutside(rel string) bool {
	return rel == ".." || len(rel) >= 3 && rel[:3] == "../"
}

func countContaining(t *testing.T, root string, needle []byte) int {
	t.Helper()
	n := 0
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || !info.Mode().IsRegular() {
			return nil
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if bytes.Contains(body, needle) {
			n++
		}
		return nil
	})
	return n
}

func mustStat(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	return err != nil
}

func startLogCapture(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() {
		slog.SetDefault(previous)
	})
	return &logs
}

func logContainsMaterial(logs *bytes.Buffer) bool {
	text := logs.String()
	for _, material := range []string{examplePassphrase, exampleURI, "example-auth-not-a-secret"} {
		if bytes.Contains([]byte(text), []byte(material)) {
			return true
		}
	}
	return false
}
