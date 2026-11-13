package pair

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestReadSpentSeedUsesOpNonce(t *testing.T) {
	// #given the hint still carries a seed the server has already spent
	// #when pair receive reads the bound ticket
	// #then a bad_request redeem is followed by an op-nonce read
	srv := &fakeCoordinator{seedSpent: true, readOp: 0, envelope: "sealed-envelope"}
	httpSrv := httptest.NewServer(srv)
	defer httpSrv.Close()
	client := testClient(t, httpSrv.URL)
	rec := testReceiver(t)
	hash := bytes.Repeat([]byte{0x11}, 32)
	env, state, err := client.readEnvelope(t.Context(), rec, hash, srv.nonce())
	if err != nil || state != "bound" || string(env) != srv.envelope {
		t.Fatalf("env %q state %s err %v", env, state, err)
	}
	if got := srv.readCounters(); len(got) != 1 || got[0] != 0 {
		t.Fatalf("reads %v", got)
	}
	next, ok := loadReadOp(rec, hash)
	if !ok || next != 1 {
		t.Fatalf("counter %d ok %v", next, ok)
	}
}

func TestReadLostCounterTriesNext(t *testing.T) {
	// #given a read was applied and the saved counter was lost
	// #when the same key reads again with the old seed
	// #then counter 0 conflicts and the next counter returns the envelope
	srv := &fakeCoordinator{seedSpent: true, readOp: 1, envelope: "still-bound"}
	httpSrv := httptest.NewServer(srv)
	defer httpSrv.Close()
	client := testClient(t, httpSrv.URL)
	rec := testReceiver(t)
	hash := bytes.Repeat([]byte{0x22}, 32)
	env, state, err := client.readEnvelope(t.Context(), rec, hash, srv.nonce())
	if err != nil || state != "bound" || string(env) != srv.envelope {
		t.Fatalf("env %q state %s err %v", env, state, err)
	}
	if got := srv.readCounters(); len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("reads %v", got)
	}
	next, ok := loadReadOp(rec, hash)
	if !ok || next != 2 {
		t.Fatalf("counter %d ok %v", next, ok)
	}
}

func TestReadOpKeepsEarlierTicket(t *testing.T) {
	// #given one session has already read two tickets
	// #when each ticket is read again
	// #then each keeps its own counter
	srv := &fakeCoordinator{seedSpent: true, readOp: 4, envelope: "ticket-a"}
	httpSrv := httptest.NewServer(srv)
	defer httpSrv.Close()
	client := testClient(t, httpSrv.URL)
	rec := testReceiver(t)
	hashA := bytes.Repeat([]byte{0x31}, 32)
	hashB := bytes.Repeat([]byte{0x32}, 32)
	if err := saveReadOp(rec, hashA, 4); err != nil {
		t.Fatal(err)
	}
	if err := saveReadOp(rec, hashB, 9); err != nil {
		t.Fatal(err)
	}
	env, _, err := client.readEnvelope(t.Context(), rec, hashA, "")
	if err != nil || string(env) != srv.envelope {
		t.Fatalf("env %q err %v", env, err)
	}
	if got, ok := loadReadOp(rec, hashB); !ok || got != 9 {
		t.Fatalf("earlier counter %d ok %v", got, ok)
	}
	if got := srv.readCounters(); len(got) != 1 || got[0] != 4 {
		t.Fatalf("reads %v", got)
	}
}

func TestWaitConflictCatchesServerCounter(t *testing.T) {
	// #given the server counted a wait this client did not store
	// #when pair receive waits again on the same session
	// #then the old counter conflicts once and the following wait is accepted
	srv := &fakeCoordinator{waitOp: 1, hintState: "bound"}
	httpSrv := httptest.NewServer(srv)
	defer httpSrv.Close()
	client := testClient(t, httpSrv.URL)
	rec := testReceiver(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	hint, err := client.pollHint(ctx, rec)
	if err != nil || hint == nil || hint.State != "bound" {
		t.Fatalf("hint %+v err %v", hint, err)
	}
	if got := srv.waitCounters(); len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("waits %v", got)
	}
	if rec.counter != 2 {
		t.Fatalf("session counter %d", rec.counter)
	}
	stored, err := loadCounter(rec.dir)
	if err != nil || stored != 2 {
		t.Fatalf("stored %d err %v", stored, err)
	}
}

func testClient(t *testing.T, raw string) *coordinator {
	t.Helper()
	client, err := dialCoordinator(raw)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.close)
	return client
}

func testReceiver(t *testing.T) *receiver {
	t.Helper()
	rec, err := createReceiver(t.TempDir())
	if err != nil || rec == nil {
		t.Fatal(err)
	}
	return rec
}

type fakeCoordinator struct {
	mu        sync.Mutex
	readOp    uint64
	waitOp    uint64
	seedSpent bool
	envelope  string
	hintState string
	reads     []uint64
	waits     []uint64
}

func (f *fakeCoordinator) nonce() string {
	return b64url.EncodeToString(bytes.Repeat([]byte{0x07}, 32))
}

func (f *fakeCoordinator) readCounters() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint64(nil), f.reads...)
}

func (f *fakeCoordinator) waitCounters() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uint64(nil), f.waits...)
}

func (f *fakeCoordinator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	_ = json.NewDecoder(r.Body).Decode(&body)
	switch r.URL.Path {
	case "/v1/sessions/challenge", "/v1/tickets/challenge":
		if r.URL.Path == "/v1/tickets/challenge" {
			if _, signed := body["signature"]; signed && f.seedSpent {
				writeResult(w, http.StatusBadRequest, map[string]any{"v": 1, "error": "bad_request"})
				return
			}
		}
		writeResult(w, http.StatusOK, map[string]any{"v": 1, "nonce": f.nonce()})
	case "/v1/tickets/read":
		counter := uint64(body["counter"].(float64))
		f.mu.Lock()
		f.reads = append(f.reads, counter)
		ok := counter == f.readOp
		if ok {
			f.readOp++
		}
		f.mu.Unlock()
		if !ok {
			writeResult(w, http.StatusConflict, map[string]any{"v": 1, "error": "conflict"})
			return
		}
		writeResult(w, http.StatusOK, map[string]any{"v": 1, "state": "bound", "envelope": f.envelope})
	case "/v1/sessions/wait":
		counter := uint64(body["counter"].(float64))
		f.mu.Lock()
		f.waits = append(f.waits, counter)
		ok := counter == f.waitOp
		if ok {
			f.waitOp++
		}
		f.mu.Unlock()
		if !ok {
			writeResult(w, http.StatusConflict, map[string]any{"v": 1, "error": "conflict"})
			return
		}
		writeResult(w, http.StatusOK, map[string]any{
			"v": 1,
			"hint": map[string]any{
				"v":           1,
				"state":       f.hintState,
				"ticket_hash": "11",
				"seed_nonce":  f.nonce(),
				"expires_at":  1,
			},
		})
	default:
		http.NotFound(w, r)
	}
}

func writeResult(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func TestWirePathsMatchSignatures(t *testing.T) {
	if err := loadWire(); err != nil {
		t.Fatal(err)
	}
	checks := []struct {
		name string
		path string
	}{
		{name: "read", path: wireSpec.Routes.TicketRead},
		{name: "ack", path: wireSpec.Routes.TicketAck},
		{name: "wait", path: wireSpec.Routes.SessionWait},
		{name: "challenge", path: wireSpec.Routes.TicketChallenge},
	}
	for _, check := range checks {
		if wireSpec.Signatures[check.name].Path != check.path || check.path == "" {
			t.Fatalf("%s path %q", check.name, wireSpec.Signatures[check.name].Path)
		}
	}
	if wireSpec.QR.TicketPrefix != "dct1." || wireSpec.QR.SessionFragmentParameter != "sc" {
		t.Fatalf("qr %+v", wireSpec.QR)
	}
	if wireSpec.Routes.Page != "/p" {
		t.Fatal(wireSpec.Routes.Page)
	}
}
