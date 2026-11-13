package proxy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestPinSHA256MatchesLeafHash(t *testing.T) {
	// #given a certificate and the SHA-256 of its DER
	// #when colon and hyphen forms are written into the runtime config
	// #then the emitted fingerprint is the lowercase hex both verifiers accept
	//
	// Hysteria normalizeCertHash lowercases and strips ":" and "-", then
	// compares that string with hex(SHA-256(leaf DER)).
	// https://github.com/apernet/hysteria/blob/master/app/cmd/client.go
	//
	// Mihomo NewFingerprintVerifier trims space, strips ":" only, hex-decodes
	// 32 bytes, and compares those bytes with SHA-256(cert.Raw).
	// https://github.com/MetaCubeX/mihomo/blob/Meta/component/ca/fingerprint.go
	cert := newCert(t)
	other := newCert(t)
	sum := sha256.Sum256(cert.Raw)
	pin := hex.EncodeToString(sum[:])
	colon := colonPin(pin)
	hyphen := strings.ReplaceAll(colon, ":", "-")
	if !hysteriaAccepts(colon, cert) || !hysteriaAccepts(hyphen, cert) || !hysteriaAccepts(pin, cert) {
		t.Fatal("hysteria fixture")
	}
	if !leafFingerprintAccepts(pin, cert) || !leafFingerprintAccepts(colon, cert) || leafFingerprintAccepts(hyphen, cert) {
		t.Fatal("fingerprint fixture")
	}
	for _, input := range []string{pin, colon, hyphen} {
		body, err := renderURI("hysteria2://example-auth-not-a-secret@192.0.2.1/?pinSHA256=" + input)
		if err != nil {
			t.Fatal(err)
		}
		item := proxyItem(t, assertSafeConfig(t, body, 1080))
		got, _ := item["fingerprint"].(string)
		if got != pin || strings.ContainsAny(got, ":-") {
			t.Fatal("emitted fingerprint")
		}
		if !hysteriaAccepts(got, cert) || !leafFingerprintAccepts(got, cert) {
			t.Fatal("emitted pin rejected")
		}
		if hysteriaAccepts(got, other) || leafFingerprintAccepts(got, other) {
			t.Fatal("different certificate")
		}
	}
}

func newCert(t *testing.T) *x509.Certificate {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.invalid"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func hysteriaAccepts(pin string, cert *x509.Certificate) bool {
	sum := sha256.Sum256(cert.Raw)
	normalized := strings.ToLower(pin)
	normalized = strings.ReplaceAll(normalized, ":", "")
	normalized = strings.ReplaceAll(normalized, "-", "")
	return normalized == hex.EncodeToString(sum[:])
}

func leafFingerprintAccepts(pin string, cert *x509.Certificate) bool {
	switch pin {
	case "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized":
		return false
	}
	cleaned := strings.TrimSpace(strings.ReplaceAll(pin, ":", ""))
	raw, err := hex.DecodeString(cleaned)
	if err != nil || len(raw) != 32 {
		return false
	}
	sum := sha256.Sum256(cert.Raw)
	return bytes.Equal(raw, sum[:])
}
