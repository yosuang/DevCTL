package pair

import (
	"bytes"
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestIssueReprintsStoredTicket(t *testing.T) {
	// #given an issuer capability is already on disk
	// #when pair issue runs
	// #then it reprints dct1. and does not upload a second envelope
	dir := t.TempDir()
	ticket := bytes.Repeat([]byte{0x41}, 32)
	sum := sha256.Sum256(ticket)
	if err := storeIssuer(dir, sum[:], ticket, bytes.Repeat([]byte{0x42}, 32)); err != nil {
		t.Fatal(err)
	}
	posts := &postCounter{}
	srv := httptest.NewServer(posts)
	defer srv.Close()
	var out bytes.Buffer
	prev := userOut
	userOut = &out
	t.Cleanup(func() { userOut = prev })
	err := Issue(t.Context(), srv.URL, failPrompt{}, dir)
	text, textErr := ticketText(ticket)
	if err != nil || textErr != nil || out.String() != text+"\n" {
		t.Fatalf("out %q err %v textErr %v", out.String(), err, textErr)
	}
	if posts.n() != 0 {
		t.Fatalf("uploads %d", posts.n())
	}
}

func TestIssueTwoCapabilitiesDoesNotUpload(t *testing.T) {
	// #given two issuer capabilities are already on disk
	// #when pair issue runs
	// #then it reports ticket_ambiguous and does not upload
	dir := t.TempDir()
	for _, fill := range []byte{0x51, 0x52} {
		ticket := bytes.Repeat([]byte{fill}, 32)
		sum := sha256.Sum256(ticket)
		if err := storeIssuer(dir, sum[:], ticket, bytes.Repeat([]byte{0x53}, 32)); err != nil {
			t.Fatal(err)
		}
	}
	posts := &postCounter{}
	srv := httptest.NewServer(posts)
	defer srv.Close()
	err := Issue(t.Context(), srv.URL, failPrompt{}, dir)
	if codeOf(err) != "ticket_ambiguous" {
		t.Fatalf("err %v", err)
	}
	if posts.n() != 0 {
		t.Fatalf("uploads %d", posts.n())
	}
}

func TestIssueUploadsWhenNoCapabilityIsStored(t *testing.T) {
	// #given no issuer capability is on disk
	// #when pair issue runs
	// #then it uploads one envelope and prints dct1.
	useFastKDF(t)
	dir := t.TempDir()
	posts := &postCounter{}
	srv := httptest.NewServer(posts)
	defer srv.Close()
	var out bytes.Buffer
	prev := userOut
	userOut = &out
	t.Cleanup(func() { userOut = prev })
	err := Issue(t.Context(), srv.URL, &callPrompt{uri: exampleURI, pass: examplePassphrase}, dir)
	if err != nil || posts.n() != 1 || len(out.String()) < len("dct1.") || out.String()[:5] != "dct1." {
		t.Fatalf("out %q posts %d err %v", out.String(), posts.n(), err)
	}
}

type failPrompt struct{}

func (failPrompt) URI() (string, error) {
	return "", localCode("uri_invalid", "uri is not usable")
}

func (failPrompt) Passphrase(bool) (string, error) {
	return "", localCode("passphrase_rejected", "passphrase is too short")
}

type callPrompt struct {
	uri  string
	pass string
}

func (p *callPrompt) URI() (string, error) { return p.uri, nil }

func (p *callPrompt) Passphrase(bool) (string, error) { return p.pass, nil }

type postCounter struct {
	mu   sync.Mutex
	seen int
}

func (p *postCounter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/tickets" && r.Method == http.MethodPost {
		p.mu.Lock()
		p.seen++
		p.mu.Unlock()
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"v":1,"state":"open"}`))
}

func (p *postCounter) n() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.seen
}
