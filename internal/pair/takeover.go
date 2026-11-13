package pair

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	phaseNone         = "none"
	phaseCopyComplete = "copy_complete"
	phaseDelivered    = "delivered"

	pairFolderName     = "pair"
	copyFileName       = "copy"
	partialFileName    = "copy.partial"
	journalFileName    = "journal"
	journalPartialName = "journal.partial"
	journalNextName    = "journal.next"
	sessionKeyName     = "key"
	sessionCapName     = "capability"
	sessionPhaseName   = "phase"
)

// journal is the per-ticket record. It stores hashes, not the URI.
type journal struct {
	Phase        string `json:"phase"`
	TicketHash   string `json:"ticket_hash"`
	EnvelopeHash string `json:"envelope_hash"`
	CopyHash     string `json:"copy_hash"`
	// Observed is set when a complete copy outlives an expired or cancelled server ticket.
	// The phase stays copy_complete. Delivered is reserved for an observed consumed ACK.
	Observed string `json:"observed,omitempty"`
	// Saved is set only when the user passes a save directory.
	// The default copy is temporary until proxy stop deletes it.
	Saved bool `json:"saved,omitempty"`
}

type ticketMatch struct {
	dir      string
	hashHex  string
	copyHash string
}

// LoadTakenOver returns the plaintext URI from one complete local copy.
// ticketPrefix is a lowercase or uppercase hex prefix of the ticket hash.
// An empty prefix selects the only complete copy.
func LoadTakenOver(configDir, ticketPrefix string) (string, string, error) {
	if vocabularyErr != nil {
		return "", "", vocabularyErr
	}
	matches, err := matchingTickets(configDir, ticketPrefix)
	if err != nil {
		return "", "", err
	}
	if len(matches) == 0 {
		return "", "", localCode("copy_incomplete", "no complete copy is available")
	}
	if len(matches) > 1 {
		return "", "", localCode("ticket_ambiguous", "more than one ticket matches")
	}
	match := matches[0]
	body, err := os.ReadFile(filepath.Join(match.dir, copyFileName))
	if err != nil {
		return "", "", localCode("copy_incomplete", "no complete copy is available")
	}
	sum := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(sum[:], decodeHash(match.copyHash)) != 1 {
		return "", "", localCode("copy_incomplete", "copy does not match")
	}
	if err := validatePairURI(body); err != nil {
		return "", "", err
	}
	return string(body), match.hashHex, nil
}

// receiveCopy stores a plaintext copy of envelope and then asks ack to observe the server.
// ack is called only after the copy is complete. It returns the server state.
// There is no network call in this function.
func receiveCopy(configDir, saveDir string, prompt Prompter, ticketHash, envelope []byte, ack func(envelopeHash []byte) (string, error)) error {
	if vocabularyErr != nil {
		return vocabularyErr
	}
	if len(ticketHash) != aad.ticketHashLen {
		return serverCode("bad_request", "ticket hash length is not the fixed size")
	}
	dir, err := ticketPath(configDir, ticketHash)
	if err != nil {
		return err
	}
	if record, ok := copyReady(dir, ticketHash); ok {
		if err := protectExisting(dir); err != nil {
			return err
		}
		if err := ensureSave(saveDir, dir, ticketHash); err != nil {
			return err
		}
		record, ok = copyReady(dir, ticketHash)
		if !ok {
			return localCode("copy_incomplete", "copy does not match")
		}
		if record.Phase == phaseDelivered {
			return nil
		}
		return observeAck(dir, record, ack)
	}
	if len(envelope) == 0 {
		return localCode("copy_incomplete", "copy does not match")
	}
	if prompt == nil {
		return localCode("not_a_tty", "stdin is not a terminal")
	}
	pass, err := prompt.Passphrase(false)
	if err != nil {
		return err
	}
	if utf8.RuneCountInString(pass) < vocabulary.PassphraseMinCodepoints {
		return localCode("passphrase_rejected", "passphrase is too short")
	}
	plain, err := openEnvelope(pass, ticketHash, envelope)
	if err != nil {
		return err
	}
	defer zeroBytes(plain)
	if err := validatePairURI(plain); err != nil {
		return err
	}
	if err := commitCopy(dir, ticketHash, envelope, plain); err != nil {
		return err
	}
	if err := ensureSave(saveDir, dir, ticketHash); err != nil {
		return err
	}
	record, ok := copyReady(dir, ticketHash)
	if !ok || record.Phase != phaseCopyComplete {
		return localCode("copy_incomplete", "copy does not match")
	}
	return observeAck(dir, record, ack)
}

func storeSession(configDir string, sessionHash, privateKey, capability []byte) error {
	if len(sessionHash) != sha256.Size || len(privateKey) == 0 || len(capability) == 0 {
		return localCode("copy_incomplete", "session material is incomplete")
	}
	root, err := pairRoot(configDir)
	if err != nil {
		return err
	}
	dir := filepath.Join(root, "session-"+hex.EncodeToString(sessionHash))
	if err := makePrivateDir(dir); err != nil {
		return err
	}
	if err := writeSecretFile(filepath.Join(dir, sessionKeyName), privateKey); err != nil {
		return err
	}
	if err := writeSecretFile(filepath.Join(dir, sessionCapName), capability); err != nil {
		return err
	}
	return writeSecretFile(filepath.Join(dir, sessionPhaseName), []byte("active"))
}

func observeAck(dir string, record journal, ack func([]byte) (string, error)) error {
	sum := decodeHash(record.EnvelopeHash)
	ticketHash := decodeHash(record.TicketHash)
	if sum == nil || ticketHash == nil {
		return localCode("copy_incomplete", "copy does not match")
	}
	if ack == nil {
		return localCode("ack_pending", "acknowledgment was not observed")
	}
	state, err := ack(sum)
	if err != nil || !terminalState(state) {
		return localCode("ack_pending", "acknowledgment was not observed")
	}
	if state == "consumed" {
		record.Phase = phaseDelivered
		record.Observed = ""
		if err := saveJournal(dir, record); err != nil {
			return err
		}
		got, ok := copyReady(dir, ticketHash)
		if !ok || got.Phase != phaseDelivered {
			return localCode("ack_pending", "acknowledgment was not observed")
		}
		return nil
	}
	if state != "expired" && state != "cancelled" {
		return localCode("ack_pending", "acknowledgment was not observed")
	}
	// The local file stays. This status is the server outcome only after the
	// journal records it. A failed write is not that outcome, and it is not delivered.
	record.Phase = phaseCopyComplete
	record.Observed = state
	if err := saveJournal(dir, record); err != nil {
		return err
	}
	got, ok := copyReady(dir, ticketHash)
	if !ok || got.Phase != phaseCopyComplete || got.Observed != state {
		return localCode("copy_incomplete", "copy does not match")
	}
	if _, err := os.Stat(filepath.Join(dir, copyFileName)); err != nil {
		return localCode("copy_incomplete", "copy does not match")
	}
	return serverCode(state, "the server copy is gone")
}

func commitCopy(dir string, ticketHash, envelope, plaintext []byte) error {
	if err := validatePairURI(plaintext); err != nil {
		return err
	}
	if err := makePrivateDir(dir); err != nil {
		return err
	}
	partial := filepath.Join(dir, partialFileName)
	if err := writeUnsynced(partial, plaintext); err != nil {
		return err
	}
	readBack, err := os.ReadFile(partial)
	if err != nil {
		return localCode("copy_incomplete", "copy does not match")
	}
	return finishCopy(dir, ticketHash, envelope, readBack, plaintext)
}

// finishCopy promotes partial only after the read-back hash matches.
// A mismatch leaves the partial file in place and does not write copy_complete.
func finishCopy(dir string, ticketHash, envelope, readBack, want []byte) error {
	if !hashEqual(readBack, want) {
		return localCode("copy_incomplete", "copy does not match")
	}
	partial := filepath.Join(dir, partialFileName)
	if err := syncPath(partial); err != nil {
		return err
	}
	synced, err := os.ReadFile(partial)
	if err != nil || !hashEqual(synced, want) {
		return localCode("copy_incomplete", "copy does not match")
	}
	final := filepath.Join(dir, copyFileName)
	if err := replaceFile(partial, final); err != nil {
		return localCode("copy_incomplete", "copy could not be saved")
	}
	if err := restrictFile(final); err != nil {
		_ = os.Remove(final)
		return err
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	copySum := sha256.Sum256(synced)
	envSum := sha256.Sum256(envelope)
	record := journal{
		Phase:        phaseCopyComplete,
		TicketHash:   hex.EncodeToString(ticketHash),
		EnvelopeHash: hex.EncodeToString(envSum[:]),
		CopyHash:     hex.EncodeToString(copySum[:]),
	}
	if err := saveJournal(dir, record); err != nil {
		return err
	}
	if _, ok := copyReady(dir, ticketHash); !ok {
		return localCode("copy_incomplete", "copy does not match")
	}
	return nil
}

func copyReady(dir string, ticketHash []byte) (journal, bool) {
	record, err := readJournal(filepath.Join(dir, journalFileName))
	if err != nil {
		return journal{}, false
	}
	if record.Phase != phaseCopyComplete && record.Phase != phaseDelivered {
		return journal{}, false
	}
	if record.TicketHash != hex.EncodeToString(ticketHash) {
		return journal{}, false
	}
	body, err := os.ReadFile(filepath.Join(dir, copyFileName))
	if err != nil {
		return journal{}, false
	}
	sum := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(sum[:], decodeHash(record.CopyHash)) != 1 {
		return journal{}, false
	}
	if decodeHash(record.EnvelopeHash) == nil {
		return journal{}, false
	}
	if err := validatePairURI(body); err != nil {
		return journal{}, false
	}
	return record, true
}

func ensureSave(saveDir, ticketDir string, ticketHash []byte) error {
	if saveDir == "" {
		return nil
	}
	if _, ok := copyReady(ticketDir, ticketHash); !ok {
		return localCode("copy_incomplete", "copy does not match")
	}
	body, err := os.ReadFile(filepath.Join(ticketDir, copyFileName))
	if err != nil {
		return localCode("copy_incomplete", "copy does not match")
	}
	if err := writeSecretFile(filepath.Join(saveDir, "ticket-"+hex.EncodeToString(ticketHash)), body); err != nil {
		return err
	}
	return markSaved(ticketDir, ticketHash)
}

// markSaved records the explicit persistence opt-in on the ticket journal.
func markSaved(ticketDir string, ticketHash []byte) error {
	record, ok := copyReady(ticketDir, ticketHash)
	if !ok {
		return localCode("copy_incomplete", "copy does not match")
	}
	if record.Saved {
		return nil
	}
	record.Saved = true
	return saveJournal(ticketDir, record)
}

// ReleaseTemporary deletes the takeover plaintext for the selected ticket.
// The file stays when the user explicitly saved it, or when the server
// expired or cancelled after the local copy was complete.
// prefix is a hex prefix of the ticket hash. A 64-character hash selects
// that ticket even when other tickets exist. A shorter prefix deletes the
// one temporary copy it matches. More than one temporary copy is
// ticket_ambiguous and nothing is deleted. A missing ticket is not an error.
func ReleaseTemporary(configDir, prefix string) error {
	if configDir == "" {
		return localCode("copy_incomplete", "no complete copy is available")
	}
	norm, err := normalizePrefix(prefix)
	if err != nil {
		return err
	}
	if len(norm) == sha256.Size*2 {
		return releaseByHash(configDir, norm)
	}
	hashes, err := ticketHashes(configDir, norm)
	if err != nil {
		return err
	}
	var temporary []string
	for _, hashHex := range hashes {
		kept, err := copyKept(configDir, hashHex)
		if err != nil {
			return err
		}
		if !kept {
			temporary = append(temporary, hashHex)
		}
	}
	if len(temporary) > 1 {
		return localCode("ticket_ambiguous", "more than one ticket matches")
	}
	if len(temporary) == 0 {
		return nil
	}
	return releaseByHash(configDir, temporary[0])
}

func copyKept(configDir, hashHex string) (bool, error) {
	dir := filepath.Join(configDir, pairFolderName, "ticket-"+hashHex)
	return plaintextKept(dir)
}

// plaintextKept reports whether stop must leave the takeover plaintext in place.
// A missing journal is not proof that the copy is temporary: installing an
// expiry record can remove the old journal before the new one is in place.
// A synced partial from that failed install still keeps the copy.
func plaintextKept(dir string) (bool, error) {
	record, err := readJournal(filepath.Join(dir, journalFileName))
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return false, localCode("copy_incomplete", "copy does not match")
		}
		return true, nil
	}
	if keepCopy(record) {
		return true, nil
	}
	return partialKeeps(dir)
}

func partialKeeps(dir string) (bool, error) {
	record, err := readJournal(filepath.Join(dir, journalPartialName))
	if err != nil || !keepCopy(record) {
		return false, nil
	}
	if record.TicketHash != strings.TrimPrefix(filepath.Base(dir), "ticket-") {
		return false, nil
	}
	body, err := os.ReadFile(filepath.Join(dir, copyFileName))
	if err != nil {
		return false, nil
	}
	sum := sha256.Sum256(body)
	if subtle.ConstantTimeCompare(sum[:], decodeHash(record.CopyHash)) != 1 {
		return false, nil
	}
	return true, nil
}

func releaseByHash(configDir, hashHex string) error {
	if len(hashHex) != sha256.Size*2 || !isHexString(hashHex) {
		return localCode("copy_incomplete", "no complete copy is available")
	}
	dir := filepath.Join(configDir, pairFolderName, "ticket-"+hashHex)
	info, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return localCode("copy_incomplete", "no complete copy is available")
	}
	if !info.IsDir() {
		return nil
	}
	kept, err := plaintextKept(dir)
	if err != nil {
		return err
	}
	if kept {
		return nil
	}
	return removePlaintext(dir)
}

func keepCopy(record journal) bool {
	if record.Saved {
		return true
	}
	return record.Observed == "expired" || record.Observed == "cancelled"
}

func hasPlaintext(dir string) bool {
	for _, name := range []string{copyFileName, partialFileName} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err == nil && info.Mode().IsRegular() {
			return true
		}
	}
	return false
}

func removePlaintext(dir string) error {
	removed := false
	for _, name := range []string{copyFileName, partialFileName} {
		err := os.Remove(filepath.Join(dir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return localCode("copy_incomplete", "temporary copy could not be removed")
		}
		removed = true
	}
	if !removed {
		return nil
	}
	return syncDir(dir)
}

func ticketHashes(configDir, prefix string) ([]string, error) {
	root := filepath.Join(configDir, pairFolderName)
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, localCode("copy_incomplete", "no complete copy is available")
	}
	var hashes []string
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || !strings.HasPrefix(name, "ticket-") {
			continue
		}
		hashHex := strings.TrimPrefix(name, "ticket-")
		if len(hashHex) != sha256.Size*2 || !isHexString(hashHex) {
			continue
		}
		if prefix != "" && !strings.HasPrefix(hashHex, prefix) {
			continue
		}
		if !hasPlaintext(filepath.Join(root, name)) {
			continue
		}
		hashes = append(hashes, hashHex)
	}
	return hashes, nil
}

func matchingTickets(configDir, ticketPrefix string) ([]ticketMatch, error) {
	if configDir == "" {
		return nil, localCode("copy_incomplete", "no complete copy is available")
	}
	prefix, err := normalizePrefix(ticketPrefix)
	if err != nil {
		return nil, err
	}
	root := filepath.Join(configDir, pairFolderName)
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, localCode("copy_incomplete", "no complete copy is available")
	}
	var matches []ticketMatch
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || !strings.HasPrefix(name, "ticket-") {
			continue
		}
		hashHex := strings.TrimPrefix(name, "ticket-")
		if len(hashHex) != sha256.Size*2 || !isHexString(hashHex) {
			continue
		}
		if prefix != "" && !strings.HasPrefix(hashHex, prefix) {
			continue
		}
		ticketHash := decodeHash(hashHex)
		if ticketHash == nil {
			continue
		}
		dir := filepath.Join(root, name)
		record, ok := copyReady(dir, ticketHash)
		if !ok {
			continue
		}
		matches = append(matches, ticketMatch{dir: dir, hashHex: hashHex, copyHash: record.CopyHash})
	}
	return matches, nil
}

func protectExisting(dir string) error {
	if err := restrictDir(filepath.Dir(dir)); err != nil {
		return err
	}
	if err := restrictDir(dir); err != nil {
		return err
	}
	if err := restrictFile(filepath.Join(dir, copyFileName)); err != nil {
		return err
	}
	return restrictFile(filepath.Join(dir, journalFileName))
}

func pairRoot(configDir string) (string, error) {
	if configDir == "" {
		return "", localCode("copy_incomplete", "copy could not be saved")
	}
	dir := filepath.Join(configDir, pairFolderName)
	if err := makePrivateDir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

func ticketPath(configDir string, ticketHash []byte) (string, error) {
	if configDir == "" {
		return "", localCode("copy_incomplete", "copy could not be saved")
	}
	if len(ticketHash) != sha256.Size {
		return "", serverCode("bad_request", "ticket hash length is not the fixed size")
	}
	return filepath.Join(configDir, pairFolderName, "ticket-"+hex.EncodeToString(ticketHash)), nil
}

func makePrivateDir(path string) error {
	if path == "" || path == "." {
		return localCode("copy_incomplete", "copy could not be saved")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return localCode("copy_incomplete", "copy could not be saved")
	}
	return restrictDir(path)
}

func writeSecretFile(path string, data []byte) error {
	if err := makePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	partial := path + ".partial"
	if err := writeUnsynced(partial, data); err != nil {
		return err
	}
	if err := syncPath(partial); err != nil {
		return err
	}
	if err := replaceFile(partial, path); err != nil {
		return localCode("copy_incomplete", "copy could not be saved")
	}
	if err := restrictFile(path); err != nil {
		_ = os.Remove(path)
		return err
	}
	return syncDir(filepath.Dir(path))
}

func writeUnsynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return localCode("copy_incomplete", "copy could not be saved")
	}
	if err := restrictFile(path); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return localCode("copy_incomplete", "copy could not be saved")
	}
	return nil
}

func saveJournal(dir string, record journal) error {
	raw, err := marshalJournal(record)
	if err != nil {
		return localCode("copy_incomplete", "copy could not be saved")
	}
	// The partial is truncated and removed if its write fails. A keep has to
	// be on the installed journal before that, or stop still sees a temporary copy.
	if err := preserveKeep(dir, record, raw); err != nil {
		return err
	}
	partial := filepath.Join(dir, journalPartialName)
	if err := writeJournalPartial(partial, raw); err != nil {
		return err
	}
	if err := syncPath(partial); err != nil {
		return err
	}
	final := filepath.Join(dir, journalFileName)
	if err := installJournalFile(partial, final); err != nil {
		return localCode("copy_incomplete", "copy could not be saved")
	}
	if err := restrictFile(final); err != nil {
		return err
	}
	return syncDir(dir)
}

func readJournal(path string) (journal, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return journal{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var record journal
	if err := dec.Decode(&record); err != nil {
		return journal{}, err
	}
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		return journal{}, errors.New("trailing")
	}
	return record, nil
}

func marshalJournal(record journal) ([]byte, error) {
	if record.Phase != phaseCopyComplete && record.Phase != phaseDelivered {
		return nil, errors.New("phase")
	}
	if decodeHash(record.TicketHash) == nil || decodeHash(record.EnvelopeHash) == nil || decodeHash(record.CopyHash) == nil {
		return nil, errors.New("hash")
	}
	if record.Observed != "" && record.Observed != "expired" && record.Observed != "cancelled" {
		return nil, errors.New("observed")
	}
	return json.Marshal(record)
}

// installJournalFile moves a synced journal partial into place.
// A failed install leaves that partial on disk. Tests replace this.
var installJournalFile = replaceFile

// writeJournalPartial writes the unsynced journal partial. Tests replace this.
var writeJournalPartial = writeUnsynced

// preserveKeep installs a keep record before journal.partial is opened.
// An expiry write that fails before that partial survives must still leave
// the plaintext in place for proxy stop.
func preserveKeep(dir string, record journal, raw []byte) error {
	if keepCopy(record) {
		return installKeepJournal(dir, raw)
	}
	kept, err := partialKeeps(dir)
	if err != nil || !kept {
		return err
	}
	body, err := os.ReadFile(filepath.Join(dir, journalPartialName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return localCode("copy_incomplete", "copy could not be saved")
	}
	return installKeepJournal(dir, body)
}

func installKeepJournal(dir string, raw []byte) error {
	next := filepath.Join(dir, journalNextName)
	if err := writeUnsynced(next, raw); err != nil {
		return err
	}
	if err := syncPath(next); err != nil {
		_ = os.Remove(next)
		return err
	}
	final := filepath.Join(dir, journalFileName)
	if err := replaceFile(next, final); err != nil {
		return localCode("copy_incomplete", "copy could not be saved")
	}
	if err := restrictFile(final); err != nil {
		return err
	}
	return syncDir(dir)
}

func replaceFile(partial, final string) error {
	if err := os.Rename(partial, final); err == nil {
		return nil
	}
	if err := os.Remove(final); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(partial, final)
}

// syncPath flushes path before a copy can become copy_complete.
// openForSync returns a handle that can flush. A failed open or flush
// returns copy_incomplete and does not promote the partial file.
func syncPath(path string) error {
	f, err := openForSync(path)
	if err != nil {
		return localCode("copy_incomplete", "copy could not be saved")
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return localCode("copy_incomplete", "copy could not be saved")
	}
	return nil
}

func validatePairURI(raw []byte) error {
	if len(raw) == 0 || bytes.IndexByte(raw, 0) >= 0 || bytes.ContainsAny(raw, " \t\r\n") {
		return localCode("uri_invalid", "uri is not usable")
	}
	parsed, err := url.Parse(string(raw))
	if err != nil || parsed.Host == "" || parsed.User == nil || parsed.User.Username() == "" {
		return localCode("uri_invalid", "uri is not usable")
	}
	for _, scheme := range vocabulary.URISchemes {
		if parsed.Scheme == scheme {
			return nil
		}
	}
	return localCode("uri_invalid", "uri scheme is not allowed")
}

func hashEqual(left, right []byte) bool {
	sumLeft := sha256.Sum256(left)
	sumRight := sha256.Sum256(right)
	return subtle.ConstantTimeCompare(sumLeft[:], sumRight[:]) == 1
}

func decodeHash(encoded string) []byte {
	if len(encoded) != sha256.Size*2 || !isHexString(encoded) {
		return nil
	}
	raw, err := hex.DecodeString(encoded)
	if err != nil || len(raw) != sha256.Size {
		return nil
	}
	return raw
}

func isHexString(value string) bool {
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

func normalizePrefix(prefix string) (string, error) {
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	if prefix == "" {
		return "", nil
	}
	if strings.Contains(prefix, "..") || strings.ContainsAny(prefix, `/\`) || !isHexString(prefix) {
		return "", localCode("copy_incomplete", "no complete copy is available")
	}
	return prefix, nil
}

func terminalState(state string) bool {
	for _, item := range vocabulary.TerminalStates {
		if item == state {
			return true
		}
	}
	return false
}
