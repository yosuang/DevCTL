// Package pair seals and opens the DevCTL pairing envelope.
// The wire vocabulary is the embedded protocol/v1.json file.
package pair

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// protocolVersion is the pairing vocabulary version compiled into this package.
// v1.json is the source of the value. script/build.go rebuilds when a non-test
// Go file changes, so a vocabulary edit has to touch this constant. Tests fail
// when the constant and v1.json disagree.
const protocolVersion = 1

// vocabularyJSON is the pairing vocabulary embedded in the binary.
//
//go:embed protocol/v1.json
var vocabularyJSON []byte

type vocabularyFile struct {
	Version int `json:"version"`
	Errors  struct {
		Server []string `json:"server"`
		Local  []string `json:"local"`
	} `json:"errors"`
	Limits struct {
		EnvelopeMaxBytes int `json:"envelope_max_bytes"`
	} `json:"limits"`
	Envelope envelopeParams `json:"envelope"`
}

type envelopeParams struct {
	Name       string   `json:"name"`
	KDF        string   `json:"kdf"`
	KDFVersion string   `json:"kdf_version"`
	M          uint32   `json:"m"`
	T          uint32   `json:"t"`
	P          uint32   `json:"p"`
	SaltBytes  int      `json:"salt_bytes"`
	KeyBytes   int      `json:"key_bytes"`
	AEAD       string   `json:"aead"`
	Encoding   string   `json:"encoding"`
	NonceBytes int      `json:"nonce_bytes"`
	TagBytes   int      `json:"tag_bytes"`
	Fields     []string `json:"fields"`
	AAD        []string `json:"aad"`
	MaxBytes   int      `json:"max_bytes"`
}

type aadKind int

const (
	aadASCII aadKind = iota
	aadZero
	aadTicket
	aadSalt
)

type aadPart struct {
	kind  aadKind
	ascii []byte
	n     int
}

type aadLayout struct {
	parts         []aadPart
	ticketHashLen int
}

type codeError struct {
	code string
	text string
}

func (e *codeError) Error() string {
	return e.code + ": " + e.text
}

var (
	vocabulary    vocabularyFile
	vocabularyErr error
	b64url        *base64.Encoding
	aad           aadLayout
)

func init() {
	loaded, enc, layout, err := loadVocabulary(vocabularyJSON)
	vocabulary = loaded
	b64url = enc
	aad = layout
	if err != nil {
		vocabularyErr = err
		return
	}
	if err := checkCipherSizes(); err != nil {
		vocabularyErr = err
		return
	}
	if err := checkMarshalShape(); err != nil {
		vocabularyErr = err
	}
}

func loadVocabulary(raw []byte) (vocabularyFile, *base64.Encoding, aadLayout, error) {
	var file vocabularyFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return vocabularyFile{}, nil, aadLayout{}, err
	}
	params, err := strictEnvelope(raw)
	if err != nil {
		return vocabularyFile{}, nil, aadLayout{}, err
	}
	file.Envelope = params
	if file.Version != protocolVersion {
		return vocabularyFile{}, nil, aadLayout{}, fmt.Errorf("protocol version %d does not match v1.json version %d", protocolVersion, file.Version)
	}
	if err := requireCode(file.Errors.Server, "bad_request"); err != nil {
		return vocabularyFile{}, nil, aadLayout{}, err
	}
	if err := requireCode(file.Errors.Server, "unsupported_version"); err != nil {
		return vocabularyFile{}, nil, aadLayout{}, err
	}
	if err := requireCode(file.Errors.Server, "too_large"); err != nil {
		return vocabularyFile{}, nil, aadLayout{}, err
	}
	if err := requireCode(file.Errors.Local, "passphrase_rejected"); err != nil {
		return vocabularyFile{}, nil, aadLayout{}, err
	}
	if err := requireCode(file.Errors.Local, "uri_invalid"); err != nil {
		return vocabularyFile{}, nil, aadLayout{}, err
	}
	e := file.Envelope
	if e.Name == "" || e.KDF == "" || e.AEAD == "" || e.Encoding == "" {
		return vocabularyFile{}, nil, aadLayout{}, errors.New("v1.json envelope name is empty")
	}
	if e.KDF != "argon2id" {
		return vocabularyFile{}, nil, aadLayout{}, errors.New("v1.json kdf is not implemented")
	}
	kdfVersion, err := parseKDFVersion(e.KDFVersion)
	if err != nil {
		return vocabularyFile{}, nil, aadLayout{}, err
	}
	if kdfVersion != argon2.Version {
		return vocabularyFile{}, nil, aadLayout{}, errors.New("v1.json kdf_version does not match argon2.Version")
	}
	if e.AEAD != "aes-256-gcm" {
		return vocabularyFile{}, nil, aadLayout{}, errors.New("v1.json aead is not implemented")
	}
	if e.KeyBytes != 32 || e.NonceBytes != 12 || e.TagBytes != 16 {
		return vocabularyFile{}, nil, aadLayout{}, errors.New("v1.json aes-256-gcm sizes are inconsistent")
	}
	if e.T < 1 || e.P < 1 || e.P > 255 || e.SaltBytes < 1 || e.MaxBytes < 1 {
		return vocabularyFile{}, nil, aadLayout{}, errors.New("v1.json envelope parameters are empty")
	}
	if !argon2MemoryStaysPut(e.M, e.P) {
		return vocabularyFile{}, nil, aadLayout{}, errors.New("v1.json memory would be rewritten by argon2")
	}
	if e.MaxBytes != file.Limits.EnvelopeMaxBytes {
		return vocabularyFile{}, nil, aadLayout{}, errors.New("v1.json envelope size limits disagree")
	}
	if !sameStrings(e.Fields, wireFieldNames()) {
		return vocabularyFile{}, nil, aadLayout{}, errors.New("v1.json envelope fields do not match the Go envelope")
	}
	enc, err := encodingFor(e.Encoding)
	if err != nil {
		return vocabularyFile{}, nil, aadLayout{}, err
	}
	layout, err := compileAAD(e)
	if err != nil {
		return vocabularyFile{}, nil, aadLayout{}, err
	}
	return file, enc, layout, nil
}

func strictEnvelope(raw []byte) (envelopeParams, error) {
	var probe struct {
		Envelope json.RawMessage `json:"envelope"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return envelopeParams{}, err
	}
	dec := json.NewDecoder(bytes.NewReader(probe.Envelope))
	dec.DisallowUnknownFields()
	var params envelopeParams
	if err := dec.Decode(&params); err != nil {
		return envelopeParams{}, err
	}
	return params, nil
}

func requireCode(list []string, code string) error {
	for _, item := range list {
		if item == code {
			return nil
		}
	}
	return fmt.Errorf("v1.json is missing error code %s", code)
}

func parseKDFVersion(s string) (int, error) {
	if !strings.HasPrefix(s, "0x") && !strings.HasPrefix(s, "0X") {
		return 0, errors.New("v1.json kdf_version is not hexadecimal")
	}
	v, err := strconv.ParseUint(s[2:], 16, 16)
	if err != nil {
		return 0, err
	}
	return int(v), nil
}

func encodingFor(name string) (*base64.Encoding, error) {
	if name != "base64url" {
		return nil, errors.New("v1.json envelope encoding is not implemented")
	}
	return base64.RawURLEncoding.Strict(), nil
}

// argon2MemoryStaysPut reports whether IDKey will hash at this memory size.
// The library rounds memory down to a multiple of 4*threads KiB and raises it
// to at least 8*threads KiB. Vocabulary values that would change are refused.
func argon2MemoryStaysPut(memory, threads uint32) bool {
	if threads < 1 {
		return false
	}
	unit := 4 * threads
	if memory < 8*threads || memory%unit != 0 {
		return false
	}
	return true
}

func compileAAD(e envelopeParams) (aadLayout, error) {
	var layout aadLayout
	var asciiN, zeroN, ticketN, saltN int
	for _, spec := range e.AAD {
		switch {
		case strings.HasPrefix(spec, "ascii:"):
			text := spec[len("ascii:"):]
			if text != e.Name || text == "" {
				return aadLayout{}, errors.New("v1.json aad name does not match the envelope name")
			}
			layout.parts = append(layout.parts, aadPart{kind: aadASCII, ascii: []byte(text)})
			asciiN++
		case spec == "0x00":
			layout.parts = append(layout.parts, aadPart{kind: aadZero})
			zeroN++
		case strings.HasPrefix(spec, "ticket_hash:"):
			n, err := strconv.Atoi(spec[len("ticket_hash:"):])
			if err != nil || n <= 0 {
				return aadLayout{}, errors.New("v1.json aad ticket hash length is invalid")
			}
			layout.ticketHashLen = n
			layout.parts = append(layout.parts, aadPart{kind: aadTicket, n: n})
			ticketN++
		case strings.HasPrefix(spec, "salt:"):
			n, err := strconv.Atoi(spec[len("salt:"):])
			if err != nil || n != e.SaltBytes {
				return aadLayout{}, errors.New("v1.json aad salt length does not match salt_bytes")
			}
			layout.parts = append(layout.parts, aadPart{kind: aadSalt, n: n})
			saltN++
		default:
			return aadLayout{}, errors.New("v1.json aad part is not recognized")
		}
	}
	if asciiN != 1 || zeroN != 1 || ticketN != 1 || saltN != 1 {
		return aadLayout{}, errors.New("v1.json aad is incomplete")
	}
	return layout, nil
}

func wireFieldNames() []string {
	t := reflect.TypeOf(wireEnvelope{})
	names := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}
		names = append(names, name)
	}
	return names
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func sameFieldSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := make(map[string]int, len(want))
	for _, key := range want {
		seen[key]++
	}
	for _, key := range got {
		seen[key]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

func serverCode(code, text string) error {
	return vocabCode(vocabulary.Errors.Server, code, text)
}

func localCode(code, text string) error {
	return vocabCode(vocabulary.Errors.Local, code, text)
}

func vocabCode(list []string, code, text string) error {
	for _, item := range list {
		if item == code {
			return &codeError{code: item, text: text}
		}
	}
	return &codeError{code: "bad_request", text: "envelope is malformed"}
}
