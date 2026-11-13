package pair

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type wireFile struct {
	Version int `json:"version"`
	Routes  struct {
		Page             string `json:"page"`
		SessionChallenge string `json:"session_challenge"`
		SessionHello     string `json:"session_hello"`
		SessionWait      string `json:"session_wait"`
		Tickets          string `json:"tickets"`
		TicketChallenge  string `json:"ticket_challenge"`
		TicketConfirm    string `json:"ticket_confirm"`
		TicketStatus     string `json:"ticket_status"`
		TicketRead       string `json:"ticket_read"`
		TicketAck        string `json:"ticket_ack"`
	} `json:"routes"`
	Signatures map[string]sigSpec `json:"signatures"`
	QR         struct {
		SessionFragmentParameter string `json:"session_fragment_parameter"`
		TicketPrefix             string `json:"ticket_prefix"`
	} `json:"qr"`
	Fingerprint struct {
		Bytes     int    `json:"bytes"`
		GroupHex  int    `json:"group_hex"`
		Separator string `json:"separator"`
	} `json:"fingerprint"`
	Limits struct {
		RequestMaxBytes int `json:"request_max_bytes"`
	} `json:"limits"`
	CapabilityBytes int `json:"capability_bytes"`
	NonceBytes      int `json:"nonce_bytes"`
	PubkeyBytes     int `json:"pubkey_bytes"`
}

type sigSpec struct {
	Scope        string   `json:"scope"`
	Method       string   `json:"method"`
	Path         string   `json:"path"`
	SignFields   []string `json:"sign_fields"`
	DigestFields []string `json:"digest_fields"`
}

type signParts struct {
	origin       string
	serverNonce  []byte
	nonce        []byte
	receiverPub  []byte
	pub          []byte
	sessionHash  []byte
	ticketHash   []byte
	issuerHash   []byte
	counter      uint64
	envelopeHash []byte
}

type resultBody struct {
	V           int       `json:"v"`
	Error       string    `json:"error"`
	State       string    `json:"state"`
	Nonce       string    `json:"nonce"`
	Envelope    string    `json:"envelope"`
	Fingerprint string    `json:"fingerprint"`
	ExpiresAt   int64     `json:"expires_at"`
	Pubkey      string    `json:"pubkey"`
	Hint        *hintBody `json:"hint"`
}

type hintBody struct {
	V          int    `json:"v"`
	State      string `json:"state"`
	TicketHash string `json:"ticket_hash"`
	SeedNonce  string `json:"seed_nonce"`
	ExpiresAt  int64  `json:"expires_at"`
}

type coordinator struct {
	base   *url.URL
	origin string
	http   *http.Client
}

var (
	wireOnce sync.Once
	wireSpec wireFile
	wireErr  error
)

func loadWire() error {
	wireOnce.Do(func() {
		if err := json.Unmarshal(vocabularyJSON, &wireSpec); err != nil {
			wireErr = err
			return
		}
		if wireSpec.Version != protocolVersion || wireSpec.Routes.Tickets == "" || wireSpec.Routes.TicketRead == "" {
			wireErr = errors.New("wire vocabulary is incomplete")
		}
	})
	if vocabularyErr != nil {
		return vocabularyErr
	}
	if wireErr != nil {
		return serverCode("unsupported_version", "envelope parameters are not the fixed set")
	}
	if wireSpec.Version != protocolVersion {
		return serverCode("unsupported_version", "envelope parameters are not the fixed set")
	}
	return nil
}

func dialCoordinator(raw string) (*coordinator, error) {
	if err := loadWire(); err != nil {
		return nil, err
	}
	base, origin, err := parseCoordinator(raw)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{
		Proxy: func(*http.Request) (*url.URL, error) { return nil, nil },
		DialContext: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:   false,
		MaxIdleConns:        2,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	return &coordinator{
		base:   base,
		origin: origin,
		http: &http.Client{
			Timeout:   20 * time.Second,
			Transport: transport,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

func (c *coordinator) close() {
	if c == nil || c.http == nil {
		return
	}
	if transport, ok := c.http.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func (c *coordinator) post(ctx context.Context, route string, payload any) (resultBody, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return resultBody{}, serverCode("bad_request", "coordinator request failed")
	}
	body := buf.Bytes()
	defer zeroBytes(body)
	endpoint := *c.base
	endpoint.Path = route
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return resultBody{}, serverCode("bad_request", "coordinator request failed")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	status := 0
	if resp != nil {
		status = resp.StatusCode
	}
	slog.Debug("pair", "route", route, "status", status)
	if err != nil {
		return resultBody{}, serverCode("bad_request", "coordinator request failed")
	}
	defer resp.Body.Close()
	limited := io.LimitReader(resp.Body, int64(wireSpec.Limits.RequestMaxBytes)+1)
	raw, err := io.ReadAll(limited)
	if err != nil || len(raw) > wireSpec.Limits.RequestMaxBytes {
		return resultBody{}, serverCode("too_large", "envelope exceeds the maximum size")
	}
	var decoded resultBody
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return resultBody{}, serverCode("bad_request", "coordinator request failed")
	}
	if decoded.V != protocolVersion {
		return resultBody{}, serverCode("unsupported_version", "envelope parameters are not the fixed set")
	}
	if decoded.Error != "" {
		return decoded, coordinatorResult(decoded)
	}
	if resp.StatusCode != wireSpecHTTPSuccess() {
		return resultBody{}, serverCode("bad_request", "coordinator request failed")
	}
	return decoded, nil
}

func wireSpecHTTPSuccess() int {
	return 200
}

func coordinatorResult(body resultBody) error {
	if body.Error == "" {
		return nil
	}
	return serverCode(body.Error, "coordinator request failed")
}

type receiver struct {
	dir     string
	hash    []byte
	cap     []byte
	key     ed25519.PrivateKey
	pub     ed25519.PublicKey
	counter uint64
}

func (c *coordinator) create(ctx context.Context, ticket, issuer, envelope []byte) (resultBody, error) {
	payload := struct {
		V        int    `json:"v"`
		Ticket   string `json:"ticket"`
		Issuer   string `json:"issuer_capability"`
		Envelope string `json:"envelope"`
	}{
		V:        protocolVersion,
		Ticket:   b64url.EncodeToString(ticket),
		Issuer:   b64url.EncodeToString(issuer),
		Envelope: string(envelope),
	}
	return c.post(ctx, wireSpec.Routes.Tickets, payload)
}

func (c *coordinator) hello(ctx context.Context, rec *receiver) (string, error) {
	nonce, err := c.sessionChallenge(ctx, rec, "hello")
	if err != nil {
		return "", err
	}
	nonceRaw, err := decodeFixed(nonce, wireSpec.NonceBytes)
	if err != nil {
		return "", err
	}
	sig, err := signValue("hello", signParts{
		origin:      c.origin,
		serverNonce: nonceRaw,
		receiverPub: rec.pub,
		pub:         rec.pub,
		sessionHash: rec.hash,
	}, rec.key)
	if err != nil {
		return "", err
	}
	body, err := c.post(ctx, wireSpec.Routes.SessionHello, struct {
		V         int    `json:"v"`
		Session   string `json:"session_capability"`
		Pubkey    string `json:"pubkey"`
		Nonce     string `json:"nonce"`
		Signature string `json:"signature"`
	}{
		V:         protocolVersion,
		Session:   b64url.EncodeToString(rec.cap),
		Pubkey:    b64url.EncodeToString(rec.pub),
		Nonce:     nonce,
		Signature: b64url.EncodeToString(sig),
	})
	if err != nil {
		return "", err
	}
	if body.Fingerprint == "" {
		return "", serverCode("bad_request", "coordinator request failed")
	}
	return body.Fingerprint, nil
}

func (c *coordinator) sessionChallenge(ctx context.Context, rec *receiver, purpose string) (string, error) {
	body, err := c.post(ctx, wireSpec.Routes.SessionChallenge, struct {
		V       int    `json:"v"`
		Session string `json:"session_capability"`
		Purpose string `json:"purpose"`
	}{
		V:       protocolVersion,
		Session: b64url.EncodeToString(rec.cap),
		Purpose: purpose,
	})
	if err != nil {
		return "", err
	}
	if _, err := decodeFixed(body.Nonce, wireSpec.NonceBytes); err != nil {
		return "", err
	}
	return body.Nonce, nil
}

func (c *coordinator) pollHint(ctx context.Context, rec *receiver) (*hintBody, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, serverCode("bad_request", "coordinator request failed")
		}
		nonce, err := c.sessionChallenge(ctx, rec, "wait")
		if err != nil {
			return nil, err
		}
		nonceRaw, err := decodeFixed(nonce, wireSpec.NonceBytes)
		if err != nil {
			return nil, err
		}
		sig, err := signValue("wait", signParts{
			origin:      c.origin,
			serverNonce: nonceRaw,
			receiverPub: rec.pub,
			sessionHash: rec.hash,
			counter:     rec.counter,
		}, rec.key)
		if err != nil {
			return nil, err
		}
		body, err := c.post(ctx, wireSpec.Routes.SessionWait, struct {
			V         int    `json:"v"`
			Session   string `json:"session_capability"`
			Pubkey    string `json:"pubkey"`
			Nonce     string `json:"nonce"`
			Counter   uint64 `json:"counter"`
			Signature string `json:"signature"`
		}{
			V:         protocolVersion,
			Session:   b64url.EncodeToString(rec.cap),
			Pubkey:    b64url.EncodeToString(rec.pub),
			Nonce:     nonce,
			Counter:   rec.counter,
			Signature: b64url.EncodeToString(sig),
		})
		if err != nil {
			return nil, err
		}
		rec.counter++
		if err := saveCounter(rec); err != nil {
			return nil, err
		}
		if body.Hint != nil && body.Hint.State != "" {
			return body.Hint, nil
		}
		timer := time.NewTimer(200 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, serverCode("bad_request", "coordinator request failed")
		case <-timer.C:
		}
	}
}

func (c *coordinator) readEnvelope(ctx context.Context, rec *receiver, ticketHash []byte, seed string) ([]byte, string, error) {
	counter, ok := loadReadOp(rec, ticketHash)
	if !ok {
		counter = 0
	}
	var nonce string
	var err error
	if seed != "" && counter == 0 {
		nonce, err = c.redeem(ctx, rec, ticketHash, seed)
		if err != nil {
			if codeOfError(err) == "unauthorized" {
				nonce, err = c.opNonce(ctx, ticketHash)
			}
			if err != nil {
				return nil, "", err
			}
		}
	} else {
		nonce, err = c.opNonce(ctx, ticketHash)
		if err != nil {
			return nil, "", err
		}
	}
	body, err := c.signedTicket(ctx, "read", wireSpec.Routes.TicketRead, rec, ticketHash, nonce, counter, nil)
	if err != nil {
		return nil, "", err
	}
	if terminalState(body.State) && body.Envelope == "" {
		return nil, body.State, nil
	}
	if body.State != "bound" || body.Envelope == "" {
		return nil, "", serverCode("bad_request", "coordinator request failed")
	}
	if err := saveReadOp(rec, ticketHash, counter+1); err != nil {
		return nil, "", err
	}
	return []byte(body.Envelope), body.State, nil
}

func (c *coordinator) ack(ctx context.Context, rec *receiver, ticketHash, envelopeHash []byte) (string, error) {
	counter, ok := loadReadOp(rec, ticketHash)
	if !ok {
		return "", localCode("ack_pending", "acknowledgment was not observed")
	}
	nonce, err := c.opNonce(ctx, ticketHash)
	if err != nil {
		return "", err
	}
	body, err := c.signedTicket(ctx, "ack", wireSpec.Routes.TicketAck, rec, ticketHash, nonce, counter, envelopeHash)
	if err != nil {
		if body.State != "" && terminalState(body.State) {
			return body.State, nil
		}
		return "", err
	}
	if terminalState(body.State) {
		return body.State, nil
	}
	return "", localCode("ack_pending", "acknowledgment was not observed")
}

func (c *coordinator) redeem(ctx context.Context, rec *receiver, ticketHash []byte, seed string) (string, error) {
	seedRaw, err := decodeFixed(seed, wireSpec.NonceBytes)
	if err != nil {
		return "", err
	}
	sig, err := signValue("challenge", signParts{
		origin:      c.origin,
		serverNonce: seedRaw,
		receiverPub: rec.pub,
		ticketHash:  ticketHash,
	}, rec.key)
	if err != nil {
		return "", err
	}
	body, err := c.post(ctx, wireSpec.Routes.TicketChallenge, struct {
		V          int    `json:"v"`
		TicketHash string `json:"ticket_hash"`
		Purpose    string `json:"purpose"`
		Pubkey     string `json:"pubkey"`
		Signature  string `json:"signature"`
	}{
		V:          protocolVersion,
		TicketHash: hexEncode(ticketHash),
		Purpose:    "op",
		Pubkey:     b64url.EncodeToString(rec.pub),
		Signature:  b64url.EncodeToString(sig),
	})
	if err != nil {
		return "", err
	}
	if _, err := decodeFixed(body.Nonce, wireSpec.NonceBytes); err != nil {
		return "", err
	}
	return body.Nonce, nil
}

func (c *coordinator) opNonce(ctx context.Context, ticketHash []byte) (string, error) {
	body, err := c.post(ctx, wireSpec.Routes.TicketChallenge, struct {
		V          int    `json:"v"`
		TicketHash string `json:"ticket_hash"`
		Purpose    string `json:"purpose"`
	}{
		V:          protocolVersion,
		TicketHash: hexEncode(ticketHash),
		Purpose:    "op",
	})
	if err != nil {
		return "", err
	}
	if _, err := decodeFixed(body.Nonce, wireSpec.NonceBytes); err != nil {
		return "", err
	}
	return body.Nonce, nil
}

func (c *coordinator) signedTicket(ctx context.Context, name, route string, rec *receiver, ticketHash []byte, nonce string, counter uint64, envelopeHash []byte) (resultBody, error) {
	nonceRaw, err := decodeFixed(nonce, wireSpec.NonceBytes)
	if err != nil {
		return resultBody{}, err
	}
	sig, err := signValue(name, signParts{
		origin:       c.origin,
		serverNonce:  nonceRaw,
		receiverPub:  rec.pub,
		ticketHash:   ticketHash,
		counter:      counter,
		envelopeHash: envelopeHash,
	}, rec.key)
	if err != nil {
		return resultBody{}, err
	}
	body, err := c.post(ctx, route, struct {
		V          int    `json:"v"`
		TicketHash string `json:"ticket_hash"`
		Pubkey     string `json:"pubkey"`
		Nonce      string `json:"nonce"`
		Counter    uint64 `json:"counter"`
		Signature  string `json:"signature"`
	}{
		V:          protocolVersion,
		TicketHash: hexEncode(ticketHash),
		Pubkey:     b64url.EncodeToString(rec.pub),
		Nonce:      nonce,
		Counter:    counter,
		Signature:  b64url.EncodeToString(sig),
	})
	return body, err
}

func (c *coordinator) status(ctx context.Context, ticket, issuer []byte) (string, error) {
	body, err := c.post(ctx, wireSpec.Routes.TicketStatus, struct {
		V      int    `json:"v"`
		Ticket string `json:"ticket"`
		Issuer string `json:"issuer_capability"`
	}{
		V:      protocolVersion,
		Ticket: b64url.EncodeToString(ticket),
		Issuer: b64url.EncodeToString(issuer),
	})
	if err != nil {
		return "", err
	}
	if body.State == "" {
		return "", serverCode("bad_request", "coordinator request failed")
	}
	return body.State, nil
}

func (c *coordinator) confirm(ctx context.Context, ticket, sessionCap, pub, sessionHash, ticketHash []byte) (resultBody, error) {
	challenged, err := c.post(ctx, wireSpec.Routes.TicketChallenge, struct {
		V          int    `json:"v"`
		TicketHash string `json:"ticket_hash"`
		Purpose    string `json:"purpose"`
	}{
		V:          protocolVersion,
		TicketHash: hexEncode(ticketHash),
		Purpose:    "confirm",
	})
	if err != nil {
		return resultBody{}, err
	}
	nonceRaw, err := decodeFixed(challenged.Nonce, wireSpec.NonceBytes)
	if err != nil {
		return resultBody{}, err
	}
	digest, err := digestBytes("confirm", signParts{
		nonce:       nonceRaw,
		sessionHash: sessionHash,
		ticketHash:  ticketHash,
		pub:         pub,
	})
	if err != nil {
		return resultBody{}, err
	}
	return c.post(ctx, wireSpec.Routes.TicketConfirm, struct {
		V       int    `json:"v"`
		Ticket  string `json:"ticket"`
		Session string `json:"session_capability"`
		Confirm bool   `json:"confirm"`
		Nonce   string `json:"nonce"`
		Digest  string `json:"digest"`
	}{
		V:       protocolVersion,
		Ticket:  b64url.EncodeToString(ticket),
		Session: b64url.EncodeToString(sessionCap),
		Confirm: true,
		Nonce:   challenged.Nonce,
		Digest:  b64url.EncodeToString(digest),
	})
}

func signValue(name string, parts signParts, key ed25519.PrivateKey) ([]byte, error) {
	spec, ok := wireSpec.Signatures[name]
	if !ok {
		return nil, serverCode("unsupported_version", "envelope parameters are not the fixed set")
	}
	digest, err := digestBytes(name, parts)
	if err != nil {
		return nil, err
	}
	if len(spec.SignFields) == 0 {
		return digest, nil
	}
	msg, err := concatFields(spec.SignFields, spec, parts, digest)
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(key, msg), nil
}

func digestBytes(name string, parts signParts) ([]byte, error) {
	spec, ok := wireSpec.Signatures[name]
	if !ok || len(spec.DigestFields) == 0 {
		return nil, serverCode("unsupported_version", "envelope parameters are not the fixed set")
	}
	msg, err := concatFields(spec.DigestFields, spec, parts, nil)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(msg)
	return sum[:], nil
}

func concatFields(fields []string, spec sigSpec, parts signParts, digest []byte) ([]byte, error) {
	var out []byte
	for _, field := range fields {
		part, err := fieldBytes(field, spec, parts, digest)
		if err != nil {
			return nil, err
		}
		out = append(out, part...)
	}
	return out, nil
}

func fieldBytes(field string, spec sigSpec, parts signParts, digest []byte) ([]byte, error) {
	switch field {
	case "0x00":
		return []byte{0}, nil
	case "0x01":
		return []byte{1}, nil
	case "scope":
		return []byte(spec.Scope), nil
	case "method":
		return []byte(spec.Method), nil
	case "path":
		return []byte(spec.Path), nil
	case "origin":
		return []byte(parts.origin), nil
	case "counter":
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], parts.counter)
		return buf[:], nil
	case "server_nonce":
		return exact(parts.serverNonce, wireSpec.NonceBytes)
	case "nonce":
		return exact(parts.nonce, wireSpec.NonceBytes)
	case "receiver_pubkey", "pubkey":
		raw := parts.receiverPub
		if field == "pubkey" {
			raw = parts.pub
		}
		return exact(raw, wireSpec.PubkeyBytes)
	case "session_hash", "ticket_hash", "issuer_hash", "envelope_sha256", "request_digest":
		return hashField(field, parts, digest)
	default:
		return nil, serverCode("unsupported_version", "envelope parameters are not the fixed set")
	}
}

func hashField(field string, parts signParts, digest []byte) ([]byte, error) {
	switch field {
	case "session_hash":
		return exact(parts.sessionHash, sha256.Size)
	case "ticket_hash":
		return exact(parts.ticketHash, sha256.Size)
	case "issuer_hash":
		return exact(parts.issuerHash, sha256.Size)
	case "envelope_sha256":
		return exact(parts.envelopeHash, sha256.Size)
	case "request_digest":
		return exact(digest, sha256.Size)
	default:
		return nil, serverCode("unsupported_version", "envelope parameters are not the fixed set")
	}
}

func exact(raw []byte, n int) ([]byte, error) {
	if len(raw) != n {
		return nil, serverCode("bad_request", "coordinator request failed")
	}
	return raw, nil
}

func decodeFixed(encoded string, n int) ([]byte, error) {
	raw, err := b64url.DecodeString(encoded)
	if err != nil || len(raw) != n {
		return nil, serverCode("bad_request", "coordinator request failed")
	}
	return raw, nil
}

func hexEncode(raw []byte) string {
	return strings.ToLower(hexBytes(raw))
}

func hexBytes(raw []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, len(raw)*2)
	for i, b := range raw {
		out[i*2] = digits[b>>4]
		out[i*2+1] = digits[b&0x0f]
	}
	return string(out)
}

func codeOfError(err error) string {
	if err == nil {
		return ""
	}
	text := err.Error()
	code, _, ok := strings.Cut(text, ":")
	if !ok {
		return ""
	}
	return code
}

func formatFingerprint(pub []byte) (string, error) {
	if err := loadWire(); err != nil {
		return "", err
	}
	sum := sha256.Sum256(pub)
	n := wireSpec.Fingerprint.Bytes
	group := wireSpec.Fingerprint.GroupHex
	if n <= 0 || group <= 0 || n > len(sum) || (n*2)%group != 0 {
		return "", serverCode("unsupported_version", "envelope parameters are not the fixed set")
	}
	hexed := hexEncode(sum[:n])
	var groups []string
	for i := 0; i < len(hexed); i += group {
		groups = append(groups, hexed[i:i+group])
	}
	return strings.Join(groups, wireSpec.Fingerprint.Separator), nil
}

func pageURL(origin string, capability []byte) (string, error) {
	if err := loadWire(); err != nil {
		return "", err
	}
	if wireSpec.Routes.Page == "" || wireSpec.QR.SessionFragmentParameter == "" || wireSpec.QR.TicketPrefix == "" {
		return "", serverCode("unsupported_version", "envelope parameters are not the fixed set")
	}
	return origin + wireSpec.Routes.Page + "#" + wireSpec.QR.SessionFragmentParameter + "=" + b64url.EncodeToString(capability), nil
}

func ticketText(ticket []byte) (string, error) {
	if err := loadWire(); err != nil {
		return "", err
	}
	return wireSpec.QR.TicketPrefix + b64url.EncodeToString(ticket), nil
}

func saveCounter(rec *receiver) error {
	text := strconv.FormatUint(rec.counter, 10)
	return writeSecretFile(filepath.Join(rec.dir, "counter"), []byte(text))
}

func loadCounter(dir string) (uint64, error) {
	raw, err := readTrim(filepath.Join(dir, "counter"))
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(string(raw), 10, 64)
}

func saveReadOp(rec *receiver, ticketHash []byte, next uint64) error {
	text := hexEncode(ticketHash) + " " + strconv.FormatUint(next, 10)
	return writeSecretFile(filepath.Join(rec.dir, "read-op"), []byte(text))
}

func loadReadOp(rec *receiver, ticketHash []byte) (uint64, bool) {
	raw, err := readTrim(filepath.Join(rec.dir, "read-op"))
	if err != nil {
		return 0, false
	}
	hashHex, counterText, ok := strings.Cut(string(raw), " ")
	if !ok || hashHex != hexEncode(ticketHash) {
		return 0, false
	}
	counter, err := strconv.ParseUint(counterText, 10, 64)
	if err != nil {
		return 0, false
	}
	return counter, true
}

func readTrim(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return bytes.TrimSpace(raw), nil
}
