package pair

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/argon2"
)

// examplePassphrase and exampleURI are fake fixtures. They are not secrets.
// 192.0.2.1 is the documentation address.
const examplePassphrase = "example-passphrase-not-a-secret"
const exampleURI = "hysteria2://example-auth-not-a-secret@192.0.2.1:443/?sni=example.invalid"

func TestArgon2IDKeyPublishedVector(t *testing.T) {
	kdfMu.Lock()
	current := deriveEnvelopeKey
	kdfMu.Unlock()
	if reflect.ValueOf(current).Pointer() != reflect.ValueOf(argon2.IDKey).Pointer() {
		t.Fatal("envelope KDF is not argon2.IDKey")
	}
	// Published golang.org/x/crypto argon2 IDKey vector.
	// password and somesalt are that vector's inputs, not a DevCTL secret.
	const published = "655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb"
	want, err := hex.DecodeString(published)
	if err != nil {
		t.Fatal("vector")
	}
	got := argon2.IDKey([]byte("password"), []byte("somesalt"), 1, 64, 1, uint32(len(want)))
	defer zeroBytes(got)
	if !bytes.Equal(got, want) {
		t.Fatalf("IDKey vector mismatch: got %x want %x", got, want)
	}
}

func TestVocabularyMatchesConstant(t *testing.T) {
	if vocabularyErr != nil {
		t.Fatal("vocabulary failed to load")
	}
	var doc struct {
		Version int `json:"version"`
	}
	if err := json.Unmarshal(vocabularyJSON, &doc); err != nil {
		t.Fatal("vocabulary json")
	}
	if doc.Version != protocolVersion || vocabulary.Version != protocolVersion || protocolVersion != 1 {
		t.Fatal("protocol version does not match v1.json")
	}
	e := vocabulary.Envelope
	if e.Name != "devctl-pair-v1" || e.KDF != "argon2id" || e.KDFVersion != "0x13" || argon2.Version != 0x13 {
		t.Fatal("kdf identity")
	}
	if e.M != 65536 || e.T != 3 || e.P != 4 {
		t.Fatal("kdf cost")
	}
	if e.SaltBytes != 16 || e.KeyBytes != 32 || e.NonceBytes != 12 || e.TagBytes != 16 {
		t.Fatal("sizes")
	}
	if e.AEAD != "aes-256-gcm" || e.Encoding != "base64url" || e.MaxBytes != 65536 {
		t.Fatal("aead")
	}
	wantAAD := []string{"ascii:devctl-pair-v1", "0x00", "ticket_hash:32", "salt:16"}
	if !slices.Equal(e.AAD, wantAAD) {
		t.Fatal("aad")
	}
	if !argon2MemoryStaysPut(e.M, e.P) {
		t.Fatal("memory would be rewritten before hashing")
	}
}

func TestStripOneTrailingNewline(t *testing.T) {
	uri := []byte(exampleURI)
	if !bytes.Equal(stripOneTrailingNewline(uri), uri) {
		t.Fatal("example URI was changed")
	}
	if !bytes.Equal(stripOneTrailingNewline(append(append([]byte{}, uri...), '\n')), uri) {
		t.Fatal("one newline was not stripped")
	}
	wantTwo := append(append([]byte{}, uri...), '\n')
	gotTwo := stripOneTrailingNewline(append(append([]byte{}, uri...), '\n', '\n'))
	if !bytes.Equal(gotTwo, wantTwo) {
		t.Fatal("a second newline was removed")
	}
	crlf := append(append([]byte{}, uri...), '\r', '\n')
	if !bytes.Equal(stripOneTrailingNewline(crlf), uri) {
		t.Fatal("CRLF was not one newline")
	}
	if len(stripOneTrailingNewline([]byte("\n"))) != 0 {
		t.Fatal("a lone newline was not removed")
	}
}

func TestEnvelopeRoundTrip(t *testing.T) {
	hash := exampleTicketHash(0x11)
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "exact", in: exampleURI, want: exampleURI},
		{name: "one newline", in: exampleURI + "\n", want: exampleURI},
		{name: "two newlines", in: exampleURI + "\n\n", want: exampleURI + "\n"},
		{name: "crlf", in: exampleURI + "\r\n", want: exampleURI},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := sealEnvelope(examplePassphrase, hash, []byte(tc.in))
			if err != nil {
				t.Fatalf("seal failed: %s", codeOf(err))
			}
			keys, err := objectKeys(raw)
			if err != nil || !slices.Equal(keys, vocabulary.Envelope.Fields) {
				t.Fatal("field order")
			}
			got, err := openEnvelope(examplePassphrase, hash, raw)
			if err != nil {
				t.Fatalf("open failed: %s", codeOf(err))
			}
			if string(got) != tc.want {
				t.Fatalf("plaintext length %d", len(got))
			}
			assertNoMaterial(t, err)
		})
	}
}

func TestEnvelopeWrongPassphrase(t *testing.T) {
	raw, hash := sealedExample(t)
	wrong := []byte(examplePassphrase)
	wrong[len(wrong)-1]++
	defer zeroBytes(wrong)
	got, err := openEnvelope(string(wrong), hash, raw)
	if got != nil || codeOf(err) != "passphrase_rejected" {
		t.Fatalf("wrong passphrase: %s", codeOf(err))
	}
	assertNoMaterial(t, err)
}

func TestEnvelopeTamperedCiphertext(t *testing.T) {
	raw, hash := sealedExample(t)
	edited := editEnvelope(t, raw, func(wire *wireEnvelope) {
		ct, err := b64url.DecodeString(wire.CT)
		if err != nil || len(ct) == 0 {
			t.Fatal("ciphertext")
		}
		ct[0] ^= 1
		wire.CT = b64url.EncodeToString(ct)
	})
	got, err := openEnvelope(examplePassphrase, hash, edited)
	if got != nil || codeOf(err) != "passphrase_rejected" {
		t.Fatalf("tamper: %s", codeOf(err))
	}
	assertNoMaterial(t, err)
}

func TestEnvelopeBadNonce(t *testing.T) {
	raw, hash := sealedExample(t)
	edited := editEnvelope(t, raw, func(wire *wireEnvelope) {
		nonce, err := b64url.DecodeString(wire.Nonce)
		if err != nil || len(nonce) == 0 {
			t.Fatal("nonce")
		}
		nonce[0] ^= 1
		wire.Nonce = b64url.EncodeToString(nonce)
	})
	got, err := openEnvelope(examplePassphrase, hash, edited)
	if got != nil || codeOf(err) != "passphrase_rejected" {
		t.Fatalf("bad nonce: %s", codeOf(err))
	}
	assertNoMaterial(t, err)
}

func TestEnvelopeBadAAD(t *testing.T) {
	raw, _ := sealedExample(t)
	got, err := openEnvelope(examplePassphrase, exampleTicketHash(0x22), raw)
	if got != nil || codeOf(err) != "passphrase_rejected" {
		t.Fatalf("bad aad: %s", codeOf(err))
	}
	assertNoMaterial(t, err)
}

func TestEnvelopeTruncation(t *testing.T) {
	raw, hash := sealedExample(t)
	called := guardKDF(t)
	got, err := openEnvelope(examplePassphrase, hash, raw[:len(raw)/2])
	if got != nil || *called || codeOf(err) != "bad_request" {
		t.Fatalf("truncated envelope: %s called %v", codeOf(err), *called)
	}
	assertNoMaterial(t, err)
	*called = false
	short := editEnvelope(t, raw, func(wire *wireEnvelope) {
		wire.CT = b64url.EncodeToString(bytes.Repeat([]byte{0x33}, vocabulary.Envelope.TagBytes))
	})
	got, err = openEnvelope(examplePassphrase, hash, short)
	if got != nil || *called || codeOf(err) != "bad_request" {
		t.Fatalf("truncated ciphertext: %s called %v", codeOf(err), *called)
	}
	assertNoMaterial(t, err)
}

func TestEnvelopeRejectsMemoryBeforeKDF(t *testing.T) {
	if vocabulary.Envelope.M != 65536 {
		t.Fatal("vocabulary memory is not 65536 KiB")
	}
	called := guardKDF(t)
	for _, memory := range []string{"0", "1", "65535", "65537", "1073741824", "4294967295", "1.073741824e9", "65536.5", `"65536"`} {
		*called = false
		raw := mutateField(t, "m", memory)
		got, err := openEnvelope(examplePassphrase, exampleTicketHash(0x11), raw)
		want := "unsupported_version"
		// Fractions, strings, and exponents are not the integer parameter.
		if memory == "65536.5" || memory == `"65536"` || memory == "1.073741824e9" {
			want = "bad_request"
		}
		if got != nil || *called || codeOf(err) != want {
			t.Fatalf("m %s: code %s called %v", memory, codeOf(err), *called)
		}
		assertNoMaterial(t, err)
	}
	// A second m, with the huge value last, must not reach IDKey either.
	for _, memory := range []string{`"m":1073741824,"m":65536`, `"m":65536,"m":1073741824`} {
		*called = false
		base := fixedEnvelope(t)
		if !bytes.Contains(base, []byte(`"m":65536`)) {
			t.Fatal("shape has no memory field")
		}
		raw := bytes.Replace(base, []byte(`"m":65536`), []byte(memory), 1)
		got, err := openEnvelope(examplePassphrase, exampleTicketHash(0x11), raw)
		if got != nil || *called || codeOf(err) != "unsupported_version" {
			t.Fatalf("duplicate m: code %s called %v", codeOf(err), *called)
		}
		assertNoMaterial(t, err)
	}
}

func TestEnvelopeRejectsParametersBeforeKDF(t *testing.T) {
	called := guardKDF(t)
	replacements := []struct {
		field string
		value string
		code  string
	}{
		{field: "v", value: "2", code: "unsupported_version"},
		{field: "kdf", value: `"argon2i"`, code: "unsupported_version"},
		{field: "aead", value: `"aes-128-gcm"`, code: "unsupported_version"},
		{field: "t", value: "1", code: "unsupported_version"},
		{field: "p", value: "1", code: "unsupported_version"},
	}
	for _, tc := range replacements {
		*called = false
		raw := mutateField(t, tc.field, tc.value)
		got, err := openEnvelope(examplePassphrase, exampleTicketHash(0x11), raw)
		if got != nil || *called || codeOf(err) != tc.code {
			t.Fatalf("%s: code %s called %v", tc.field, codeOf(err), *called)
		}
		assertNoMaterial(t, err)
	}

	*called = false
	raw := mutateField(t, "salt", quotedB64(t, bytes.Repeat([]byte{0x11}, vocabulary.Envelope.SaltBytes-1)))
	got, err := openEnvelope(examplePassphrase, exampleTicketHash(0x11), raw)
	if got != nil || *called || codeOf(err) != "bad_request" {
		t.Fatalf("short salt: %s called %v", codeOf(err), *called)
	}

	*called = false
	padded := base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, vocabulary.Envelope.SaltBytes))
	raw = mutateField(t, "salt", mustJSON(t, padded))
	got, err = openEnvelope(examplePassphrase, exampleTicketHash(0x11), raw)
	if got != nil || *called || codeOf(err) != "bad_request" {
		t.Fatalf("padded salt: %s called %v", codeOf(err), *called)
	}

	*called = false
	fields := envelopeFields(t, fixedEnvelope(t))
	fields["extra"] = json.RawMessage("1")
	got, err = openEnvelope(examplePassphrase, exampleTicketHash(0x11), mustMarshalFields(t, fields))
	if got != nil || *called || codeOf(err) != "unsupported_version" {
		t.Fatalf("unknown field: %s called %v", codeOf(err), *called)
	}
	assertNoMaterial(t, err)

	*called = false
	fields = envelopeFields(t, fixedEnvelope(t))
	fields[examplePassphrase] = json.RawMessage("1")
	got, err = openEnvelope(examplePassphrase, exampleTicketHash(0x11), mustMarshalFields(t, fields))
	if got != nil || *called || codeOf(err) != "unsupported_version" {
		t.Fatalf("unknown name: %s called %v", codeOf(err), *called)
	}
	assertNoMaterial(t, err)

	*called = false
	oversized := bytes.Repeat([]byte{'x'}, vocabulary.Envelope.MaxBytes+1)
	got, err = openEnvelope(examplePassphrase, exampleTicketHash(0x11), oversized)
	if got != nil || *called || codeOf(err) != "too_large" {
		t.Fatalf("too large: %s called %v", codeOf(err), *called)
	}

	*called = false
	got, err = openEnvelope(examplePassphrase, exampleTicketHash(0x11), []byte("\n"))
	if got != nil || *called || codeOf(err) != "unsupported_version" {
		t.Fatalf("not an object: %s called %v", codeOf(err), *called)
	}

	*called = false
	got, err = openEnvelope(examplePassphrase, []byte{0x01}, fixedEnvelope(t))
	if got != nil || *called || codeOf(err) != "bad_request" {
		t.Fatalf("short ticket hash: %s called %v", codeOf(err), *called)
	}

	*called = false
	got, err = sealEnvelope(examplePassphrase, exampleTicketHash(0x11), []byte("\n"))
	if *called || codeOf(err) != "uri_invalid" {
		t.Fatalf("empty plaintext: %s called %v", codeOf(err), *called)
	}
	assertNoMaterial(t, err)
}

func TestEnvelopeFixedParametersReachKDF(t *testing.T) {
	var memory, timeCost uint32
	var threads uint8
	called := false
	swapKDF(t, func(_, _ []byte, time, mem uint32, parallelism uint8, keyLen uint32) []byte {
		called = true
		timeCost = time
		memory = mem
		threads = parallelism
		return make([]byte, keyLen)
	})
	got, err := openEnvelope(examplePassphrase, exampleTicketHash(0x11), fixedEnvelope(t))
	if !called {
		t.Fatal("IDKey did not run")
	}
	if memory != 65536 || timeCost != 3 || threads != 4 {
		t.Fatal("IDKey parameters were not the fixed set")
	}
	if got != nil || codeOf(err) != "passphrase_rejected" {
		t.Fatalf("expected authentication failure: %s", codeOf(err))
	}
	assertNoMaterial(t, err)
}

var (
	sealedOnce sync.Once
	sealedRaw  []byte
	sealedHash []byte
	sealedErr  error
)

func sealedExample(t *testing.T) ([]byte, []byte) {
	t.Helper()
	sealedOnce.Do(func() {
		sealedHash = exampleTicketHash(0x11)
		sealedRaw, sealedErr = sealEnvelope(examplePassphrase, sealedHash, []byte(exampleURI+"\n"))
	})
	if sealedErr != nil {
		t.Fatal("seal failed")
	}
	return sealedRaw, sealedHash
}

func exampleTicketHash(fill byte) []byte {
	return bytes.Repeat([]byte{fill}, aad.ticketHashLen)
}

func swapKDF(t *testing.T, fn idKeyFunc) {
	t.Helper()
	kdfMu.Lock()
	prev := deriveEnvelopeKey
	deriveEnvelopeKey = fn
	kdfMu.Unlock()
	t.Cleanup(func() {
		kdfMu.Lock()
		deriveEnvelopeKey = prev
		kdfMu.Unlock()
	})
}

func guardKDF(t *testing.T) *bool {
	t.Helper()
	called := false
	swapKDF(t, func(_, _ []byte, _, _ uint32, _ uint8, keyLen uint32) []byte {
		called = true
		if keyLen == 0 {
			return nil
		}
		return make([]byte, keyLen)
	})
	return &called
}

func fixedEnvelope(t *testing.T) []byte {
	t.Helper()
	if vocabularyErr != nil {
		t.Fatal("vocabulary")
	}
	e := vocabulary.Envelope
	raw, err := marshalWire(wireEnvelope{
		V:     uint32(vocabulary.Version),
		KDF:   e.KDF,
		M:     e.M,
		T:     e.T,
		P:     e.P,
		Salt:  b64url.EncodeToString(bytes.Repeat([]byte{0x11}, e.SaltBytes)),
		AEAD:  e.AEAD,
		Nonce: b64url.EncodeToString(bytes.Repeat([]byte{0x22}, e.NonceBytes)),
		CT:    b64url.EncodeToString(bytes.Repeat([]byte{0x33}, e.TagBytes+1)),
	})
	if err != nil {
		t.Fatal("shape")
	}
	return raw
}

func editEnvelope(t *testing.T, raw []byte, fn func(*wireEnvelope)) []byte {
	t.Helper()
	parsed, err := parseEnvelope(raw)
	if err != nil {
		t.Fatal("example envelope did not parse")
	}
	fn(&parsed.wire)
	out, err := marshalWire(parsed.wire)
	if err != nil {
		t.Fatal("marshal")
	}
	return out
}

func mutateField(t *testing.T, field, rawJSON string) []byte {
	t.Helper()
	fields := envelopeFields(t, fixedEnvelope(t))
	fields[field] = json.RawMessage(rawJSON)
	return mustMarshalFields(t, fields)
}

func envelopeFields(t *testing.T, raw []byte) map[string]json.RawMessage {
	t.Helper()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal("fields")
	}
	return fields
}

func mustMarshalFields(t *testing.T, fields map[string]json.RawMessage) []byte {
	t.Helper()
	out, err := json.Marshal(fields)
	if err != nil {
		t.Fatal("marshal fields")
	}
	return out
}

func mustJSON(t *testing.T, value string) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal("json")
	}
	return string(raw)
}

func quotedB64(t *testing.T, raw []byte) string {
	t.Helper()
	return mustJSON(t, b64url.EncodeToString(raw))
}

func codeOf(err error) string {
	var coded *codeError
	if errors.As(err, &coded) {
		return coded.code
	}
	return ""
}

func assertNoMaterial(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	text := err.Error()
	for _, material := range []string{examplePassphrase, exampleURI, "192.0.2.1", "example-auth-not-a-secret"} {
		if strings.Contains(text, material) {
			t.Fatal("error text contains example material")
		}
	}
}
