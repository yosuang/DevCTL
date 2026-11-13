package pair

import "testing"

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
