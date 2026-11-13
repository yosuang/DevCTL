package pair

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

type idKeyFunc func(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte

// deriveEnvelopeKey is argon2.IDKey. IDKey takes no secret and no associated
// data, so the ticket hash is bound in the AEAD additional data instead.
// Tests replace this to prove a rejected envelope returns before the KDF.
var (
	kdfMu             sync.Mutex
	deriveEnvelopeKey idKeyFunc = argon2.IDKey
)

type wireEnvelope struct {
	V     uint32 `json:"v"`
	KDF   string `json:"kdf"`
	M     uint32 `json:"m"`
	T     uint32 `json:"t"`
	P     uint32 `json:"p"`
	Salt  string `json:"salt"`
	AEAD  string `json:"aead"`
	Nonce string `json:"nonce"`
	CT    string `json:"ct"`
}

type parsedEnvelope struct {
	wire  wireEnvelope
	salt  []byte
	nonce []byte
	ct    []byte
}

func kdf(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	kdfMu.Lock()
	fn := deriveEnvelopeKey
	kdfMu.Unlock()
	return fn(password, salt, time, memory, threads, keyLen)
}

func zeroBytes(b []byte) {
	clear(b)
	runtime.KeepAlive(b)
}

func checkCipherSizes() error {
	e := vocabulary.Envelope
	block, err := aes.NewCipher(make([]byte, e.KeyBytes))
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	if gcm.NonceSize() != e.NonceBytes || gcm.Overhead() != e.TagBytes {
		return serverCode("unsupported_version", "envelope parameters are not the fixed set")
	}
	return nil
}

func checkMarshalShape() error {
	raw, err := marshalWire(wireEnvelope{
		V:     uint32(vocabulary.Version),
		KDF:   vocabulary.Envelope.KDF,
		M:     vocabulary.Envelope.M,
		T:     vocabulary.Envelope.T,
		P:     vocabulary.Envelope.P,
		Salt:  "AA",
		AEAD:  vocabulary.Envelope.AEAD,
		Nonce: "AA",
		CT:    "AA",
	})
	if err != nil {
		return err
	}
	keys, err := objectKeys(raw)
	if err != nil {
		return err
	}
	if !sameStrings(keys, vocabulary.Envelope.Fields) {
		return serverCode("unsupported_version", "envelope parameters are not the fixed set")
	}
	return nil
}

// sealEnvelope encrypts plaintext for ticketHash.
// One trailing newline is removed first. The stored bytes are not re-encoded.
func sealEnvelope(passphrase string, ticketHash, plaintext []byte) ([]byte, error) {
	if vocabularyErr != nil {
		return nil, vocabularyErr
	}
	plain := stripOneTrailingNewline(plaintext)
	if len(plain) == 0 {
		return nil, localCode("uri_invalid", "plaintext is empty")
	}
	if len(plain) > vocabulary.Envelope.MaxBytes {
		return nil, serverCode("too_large", "envelope exceeds the maximum size")
	}
	fits, err := envelopeFits(len(plain))
	if err != nil {
		return nil, err
	}
	if !fits {
		return nil, serverCode("too_large", "envelope exceeds the maximum size")
	}
	if len(ticketHash) != aad.ticketHashLen {
		return nil, serverCode("bad_request", "ticket hash length is not the fixed size")
	}
	salt, err := randomBytes(vocabulary.Envelope.SaltBytes)
	if err != nil {
		return nil, err
	}
	nonce, err := randomBytes(vocabulary.Envelope.NonceBytes)
	if err != nil {
		return nil, err
	}
	key, err := deriveFixedKey(passphrase, salt)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	aead, err := openAEAD(key)
	if err != nil {
		return nil, err
	}
	ad, err := additionalData(ticketHash, salt)
	if err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plain, ad)
	raw, err := marshalWire(wireEnvelope{
		V:     uint32(vocabulary.Version),
		KDF:   vocabulary.Envelope.KDF,
		M:     vocabulary.Envelope.M,
		T:     vocabulary.Envelope.T,
		P:     vocabulary.Envelope.P,
		Salt:  b64url.EncodeToString(salt),
		AEAD:  vocabulary.Envelope.AEAD,
		Nonce: b64url.EncodeToString(nonce),
		CT:    b64url.EncodeToString(ct),
	})
	if err != nil {
		return nil, err
	}
	if len(raw) > vocabulary.Envelope.MaxBytes {
		return nil, serverCode("too_large", "envelope exceeds the maximum size")
	}
	return raw, nil
}

// openEnvelope decrypts an envelope bound to ticketHash.
// Parameters other than the fixed vocabulary are rejected before the KDF.
func openEnvelope(passphrase string, ticketHash, raw []byte) ([]byte, error) {
	parsed, err := parseEnvelope(raw)
	if err != nil {
		return nil, err
	}
	if len(ticketHash) != aad.ticketHashLen {
		return nil, serverCode("bad_request", "ticket hash length is not the fixed size")
	}
	key, err := deriveFixedKey(passphrase, parsed.salt)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(key)
	return decrypt(key, parsed, ticketHash)
}

// stripOneTrailingNewline removes one trailing newline.
// A newline is LF, or the CR LF pair. A second newline is kept.
func stripOneTrailingNewline(in []byte) []byte {
	if len(in) == 0 || in[len(in)-1] != '\n' {
		return in
	}
	in = in[:len(in)-1]
	if len(in) > 0 && in[len(in)-1] == '\r' {
		in = in[:len(in)-1]
	}
	return in
}

func envelopeFits(plainLen int) (bool, error) {
	e := vocabulary.Envelope
	raw, err := marshalWire(wireEnvelope{
		V:     uint32(vocabulary.Version),
		KDF:   e.KDF,
		M:     e.M,
		T:     e.T,
		P:     e.P,
		Salt:  strings.Repeat("A", b64url.EncodedLen(e.SaltBytes)),
		AEAD:  e.AEAD,
		Nonce: strings.Repeat("A", b64url.EncodedLen(e.NonceBytes)),
		CT:    strings.Repeat("A", b64url.EncodedLen(plainLen+e.TagBytes)),
	})
	if err != nil {
		return false, err
	}
	return len(raw) <= e.MaxBytes, nil
}

func deriveFixedKey(passphrase string, salt []byte) ([]byte, error) {
	e := vocabulary.Envelope
	if len(salt) != e.SaltBytes || e.T < 1 || e.P < 1 || e.P > 255 {
		return nil, serverCode("unsupported_version", "envelope parameters are not the fixed set")
	}
	password := []byte(passphrase)
	defer zeroBytes(password)
	key := kdf(password, salt, e.T, e.M, uint8(e.P), uint32(e.KeyBytes))
	if len(key) != e.KeyBytes {
		zeroBytes(key)
		return nil, serverCode("unsupported_version", "envelope parameters are not the fixed set")
	}
	return key, nil
}

func openAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, serverCode("bad_request", "envelope is malformed")
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, serverCode("bad_request", "envelope is malformed")
	}
	if aead.NonceSize() != vocabulary.Envelope.NonceBytes || aead.Overhead() != vocabulary.Envelope.TagBytes {
		return nil, serverCode("unsupported_version", "envelope parameters are not the fixed set")
	}
	return aead, nil
}

func decrypt(key []byte, parsed parsedEnvelope, ticketHash []byte) ([]byte, error) {
	aead, err := openAEAD(key)
	if err != nil {
		return nil, err
	}
	ad, err := additionalData(ticketHash, parsed.salt)
	if err != nil {
		return nil, err
	}
	plain, err := aead.Open(nil, parsed.nonce, parsed.ct, ad)
	if err != nil {
		return nil, localCode("passphrase_rejected", "authentication failed")
	}
	return plain, nil
}

func additionalData(ticketHash, salt []byte) ([]byte, error) {
	var out []byte
	for _, part := range aad.parts {
		switch part.kind {
		case aadASCII:
			out = append(out, part.ascii...)
		case aadZero:
			out = append(out, 0)
		case aadTicket:
			if len(ticketHash) != part.n {
				return nil, serverCode("bad_request", "ticket hash length is not the fixed size")
			}
			out = append(out, ticketHash...)
		case aadSalt:
			if len(salt) != part.n {
				return nil, serverCode("bad_request", "envelope is malformed")
			}
			out = append(out, salt...)
		default:
			return nil, serverCode("unsupported_version", "envelope parameters are not the fixed set")
		}
	}
	return out, nil
}

func randomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, serverCode("bad_request", "entropy source failed")
	}
	return buf, nil
}

func parseEnvelope(raw []byte) (parsedEnvelope, error) {
	if vocabularyErr != nil {
		return parsedEnvelope{}, vocabularyErr
	}
	if len(raw) > vocabulary.Envelope.MaxBytes {
		return parsedEnvelope{}, serverCode("too_large", "envelope exceeds the maximum size")
	}
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return parsedEnvelope{}, serverCode("unsupported_version", "envelope parameters are not the fixed set")
	}
	keys, err := objectKeys(raw)
	if err != nil {
		return parsedEnvelope{}, serverCode("bad_request", "envelope is malformed")
	}
	if !sameFieldSet(keys, vocabulary.Envelope.Fields) {
		return parsedEnvelope{}, serverCode("unsupported_version", "envelope parameters are not the fixed set")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var wire wireEnvelope
	if err := dec.Decode(&wire); err != nil {
		if strings.Contains(err.Error(), "unknown field") {
			return parsedEnvelope{}, serverCode("unsupported_version", "envelope parameters are not the fixed set")
		}
		return parsedEnvelope{}, serverCode("bad_request", "envelope is malformed")
	}
	e := vocabulary.Envelope
	if wire.V != uint32(vocabulary.Version) || wire.KDF != e.KDF || wire.AEAD != e.AEAD || wire.M != e.M || wire.T != e.T || wire.P != e.P {
		return parsedEnvelope{}, serverCode("unsupported_version", "envelope parameters are not the fixed set")
	}
	salt, err := b64url.DecodeString(wire.Salt)
	if err != nil || len(salt) != e.SaltBytes {
		return parsedEnvelope{}, serverCode("bad_request", "envelope is malformed")
	}
	nonce, err := b64url.DecodeString(wire.Nonce)
	if err != nil || len(nonce) != e.NonceBytes {
		return parsedEnvelope{}, serverCode("bad_request", "envelope is malformed")
	}
	ct, err := b64url.DecodeString(wire.CT)
	if err != nil || len(ct) <= e.TagBytes {
		return parsedEnvelope{}, serverCode("bad_request", "envelope is malformed")
	}
	return parsedEnvelope{wire: wire, salt: salt, nonce: nonce, ct: ct}, nil
}

func marshalWire(env wireEnvelope) ([]byte, error) {
	if vocabularyErr != nil {
		return nil, vocabularyErr
	}
	values := map[string]any{
		"v":     env.V,
		"kdf":   env.KDF,
		"m":     env.M,
		"t":     env.T,
		"p":     env.P,
		"salt":  env.Salt,
		"aead":  env.AEAD,
		"nonce": env.Nonce,
		"ct":    env.CT,
	}
	if len(values) != len(vocabulary.Envelope.Fields) {
		return nil, serverCode("unsupported_version", "envelope parameters are not the fixed set")
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, field := range vocabulary.Envelope.Fields {
		value, ok := values[field]
		if !ok {
			return nil, serverCode("unsupported_version", "envelope parameters are not the fixed set")
		}
		name, err := json.Marshal(field)
		if err != nil {
			return nil, serverCode("bad_request", "envelope is malformed")
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, serverCode("bad_request", "envelope is malformed")
		}
		if i > 0 {
			buf.WriteByte(',')
		}
		buf.Write(name)
		buf.WriteByte(':')
		buf.Write(encoded)
		delete(values, field)
	}
	if len(values) != 0 {
		return nil, serverCode("unsupported_version", "envelope parameters are not the fixed set")
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func objectKeys(raw []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok := tok.(json.Delim)
	if !ok || delim != '{' {
		return nil, errors.New("not an object")
	}
	var keys []string
	for dec.More() {
		tok, err = dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("key")
		}
		keys = append(keys, key)
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return nil, err
		}
	}
	tok, err = dec.Token()
	if err != nil {
		return nil, err
	}
	delim, ok = tok.(json.Delim)
	if !ok || delim != '}' {
		return nil, errors.New("end")
	}
	var extra struct{}
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("trailing")
	}
	return keys, nil
}
