package pair

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// userOut receives the pairing text a person copies or scans.
// It is not the log file.
var userOut io.Writer = os.Stdout

// Issue reads a proxy URI and a transfer passphrase from prompt, seals them,
// and uploads the envelope. The URI and passphrase are not flags, environment
// variables, or log fields.
func Issue(ctx context.Context, coordinator string, prompt Prompter, configDir string) error {
	client, err := dialCoordinator(coordinator)
	if err != nil {
		return err
	}
	defer client.close()
	if prompt == nil {
		return localCode("not_a_tty", "stdin is not a terminal")
	}
	uri, err := prompt.URI()
	if err != nil {
		return err
	}
	pass, err := prompt.Passphrase(true)
	if err != nil {
		return err
	}
	passBuf := []byte(pass)
	defer zeroBytes(passBuf)
	ticket, err := randomBytes(wireSpec.CapabilityBytes)
	if err != nil {
		return err
	}
	defer zeroBytes(ticket)
	issuer, err := randomBytes(wireSpec.CapabilityBytes)
	if err != nil {
		return err
	}
	defer zeroBytes(issuer)
	sum := sha256.Sum256(ticket)
	sealed, err := sealEnvelope(string(passBuf), sum[:], []byte(uri))
	if err != nil {
		return err
	}
	defer zeroBytes(sealed)
	created, err := client.create(ctx, ticket, issuer, sealed)
	if err != nil {
		return err
	}
	if created.State != "open" {
		return serverCode("bad_request", "coordinator request failed")
	}
	if err := storeIssuer(configDir, sum[:], ticket, issuer); err != nil {
		return err
	}
	text, err := ticketText(ticket)
	if err != nil {
		return err
	}
	return writeUser("%s\n", text)
}

// Receive registers this computer, waits until a ticket is bound to its key,
// and stores the opened URI. A finished local copy is acknowledged without
// asking for the passphrase again.
func Receive(ctx context.Context, coordinator string, prompt Prompter, configDir, saveDir string) error {
	client, err := dialCoordinator(coordinator)
	if err != nil {
		return err
	}
	defer client.close()
	if resumed, err := resumeAck(ctx, client, configDir, saveDir, prompt); resumed {
		return err
	}
	if prompt == nil {
		return localCode("not_a_tty", "stdin is not a terminal")
	}
	rec, err := loadOrCreate(configDir)
	if err != nil {
		return err
	}
	remote, err := client.hello(ctx, rec)
	if err != nil {
		return err
	}
	local, err := formatFingerprint(rec.pub)
	if err != nil {
		return err
	}
	if local == "" || local != remote {
		return serverCode("bad_request", "coordinator request failed")
	}
	page, err := pageURL(client.origin, rec.cap)
	if err != nil {
		return err
	}
	if err := writeUser("%s\n%s\n", local, page); err != nil {
		return err
	}
	hint, err := client.pollHint(ctx, rec)
	if err != nil {
		return err
	}
	if hint.State == "expired" || hint.State == "cancelled" {
		return serverCode(hint.State, "the server copy is gone")
	}
	if hint.State != "bound" {
		return serverCode("bad_request", "coordinator request failed")
	}
	ticketHash := decodeHash(hint.TicketHash)
	if ticketHash == nil {
		return serverCode("bad_request", "coordinator request failed")
	}
	envelope, state, err := client.readEnvelope(ctx, rec, ticketHash, hint.SeedNonce)
	if err != nil {
		return err
	}
	if state != "" && state != "bound" {
		return serverCode(state, "the server copy is gone")
	}
	return receiveCopy(configDir, saveDir, prompt, ticketHash, envelope, func(envelopeHash []byte) (string, error) {
		return client.ack(ctx, rec, ticketHash, envelopeHash)
	})
}

func writeUser(format string, args ...any) error {
	if _, err := fmt.Fprintf(userOut, format, args...); err != nil {
		return serverCode("bad_request", "coordinator request failed")
	}
	return nil
}

func resumeAck(ctx context.Context, client *coordinator, configDir, saveDir string, prompt Prompter) (bool, error) {
	pending, err := copyCompleteOnly(configDir)
	if err != nil {
		return true, err
	}
	if len(pending) == 0 {
		return false, nil
	}
	if len(pending) > 1 {
		return true, localCode("ticket_ambiguous", "more than one ticket matches")
	}
	rec, err := loadReceiver(configDir)
	if err != nil || rec == nil {
		return true, localCode("ack_pending", "acknowledgment was not observed")
	}
	ticketHash := decodeHash(pending[0].hashHex)
	if ticketHash == nil {
		return true, localCode("ack_pending", "acknowledgment was not observed")
	}
	err = receiveCopy(configDir, saveDir, prompt, ticketHash, nil, func(envelopeHash []byte) (string, error) {
		return client.ack(ctx, rec, ticketHash, envelopeHash)
	})
	return true, err
}

func copyCompleteOnly(configDir string) ([]ticketMatch, error) {
	matches, err := matchingTickets(configDir, "")
	if err != nil {
		return nil, err
	}
	var pending []ticketMatch
	for _, match := range matches {
		record, err := readJournal(filepath.Join(match.dir, journalFileName))
		if err != nil || record.Phase != phaseCopyComplete {
			continue
		}
		pending = append(pending, match)
	}
	return pending, nil
}

func loadOrCreate(configDir string) (*receiver, error) {
	rec, err := loadReceiver(configDir)
	if err != nil || rec != nil {
		return rec, err
	}
	return createReceiver(configDir)
}

func createReceiver(configDir string) (*receiver, error) {
	if err := loadWire(); err != nil {
		return nil, err
	}
	capability, err := randomBytes(wireSpec.CapabilityBytes)
	if err != nil {
		return nil, err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil || len(pub) != wireSpec.PubkeyBytes || len(priv) != ed25519.PrivateKeySize {
		return nil, serverCode("bad_request", "entropy source failed")
	}
	sum := sha256.Sum256(capability)
	if err := storeSession(configDir, sum[:], priv, capability); err != nil {
		return nil, err
	}
	root, err := pairRoot(configDir)
	if err != nil {
		return nil, err
	}
	rec := &receiver{
		dir:  filepath.Join(root, "session-"+hex.EncodeToString(sum[:])),
		hash: append([]byte(nil), sum[:]...),
		cap:  capability,
		key:  priv,
		pub:  pub,
	}
	if err := saveCounter(rec); err != nil {
		return nil, err
	}
	return rec, nil
}

func loadReceiver(configDir string) (*receiver, error) {
	if err := loadWire(); err != nil {
		return nil, err
	}
	root := filepath.Join(configDir, pairFolderName)
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, localCode("copy_incomplete", "session material is incomplete")
	}
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() && strings.HasPrefix(name, "session-") && len(name) == len("session-")+sha256.Size*2 {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil, nil
	}
	if len(names) > 1 {
		return nil, localCode("ticket_ambiguous", "more than one ticket matches")
	}
	hash := decodeHash(strings.TrimPrefix(names[0], "session-"))
	if hash == nil {
		return nil, localCode("copy_incomplete", "session material is incomplete")
	}
	dir := filepath.Join(root, names[0])
	key, err := os.ReadFile(filepath.Join(dir, sessionKeyName))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return nil, localCode("copy_incomplete", "session material is incomplete")
	}
	capability, err := os.ReadFile(filepath.Join(dir, sessionCapName))
	if err != nil || len(capability) != wireSpec.CapabilityBytes {
		return nil, localCode("copy_incomplete", "session material is incomplete")
	}
	sum := sha256.Sum256(capability)
	if subtle.ConstantTimeCompare(sum[:], hash) != 1 {
		return nil, localCode("copy_incomplete", "session material is incomplete")
	}
	priv := ed25519.PrivateKey(key)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pub) != wireSpec.PubkeyBytes {
		return nil, localCode("copy_incomplete", "session material is incomplete")
	}
	counter, err := loadCounter(dir)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, localCode("copy_incomplete", "session material is incomplete")
		}
		counter = 0
	}
	return &receiver{
		dir:     dir,
		hash:    hash,
		cap:     capability,
		key:     priv,
		pub:     pub,
		counter: counter,
	}, nil
}

func storeIssuer(configDir string, ticketHash, ticket, capability []byte) error {
	root, err := pairRoot(configDir)
	if err != nil {
		return err
	}
	dir := filepath.Join(root, "issuer-"+hex.EncodeToString(ticketHash))
	if err := makePrivateDir(dir); err != nil {
		return err
	}
	if err := writeSecretFile(filepath.Join(dir, "ticket"), ticket); err != nil {
		return err
	}
	return writeSecretFile(filepath.Join(dir, "capability"), capability)
}
