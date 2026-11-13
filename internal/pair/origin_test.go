package pair

import "testing"

func TestParseCoordinator(t *testing.T) {
	cases := []struct {
		raw    string
		origin string
		ok     bool
	}{
		{raw: "http://127.0.0.1:8787", origin: "http://127.0.0.1:8787", ok: true},
		{raw: "http://localhost:8787/", origin: "http://localhost:8787", ok: true},
		{raw: "http://[::1]:8787", origin: "http://[::1]:8787", ok: true},
		{raw: "https://pair.example.invalid", origin: "https://pair.example.invalid:443", ok: true},
		{raw: "http://127.0.0.1:8787/v1", ok: false},
		{raw: "http://192.0.2.1:8787", ok: false},
		{raw: "http://localhost.example:8787", ok: false},
		{raw: "http://user:pass@127.0.0.1:8787", ok: false},
		{raw: "http://127.0.0.1:8787?ticket=1", ok: false},
		{raw: "http://127.0.0.1:8787#sc=1", ok: false},
		{raw: "", ok: false},
		{raw: "https://", ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			_, origin, err := parseCoordinator(tc.raw)
			if tc.ok {
				if err != nil || origin != tc.origin {
					t.Fatalf("origin %q err %v", origin, err)
				}
				return
			}
			if err == nil || codeOf(err) != "bad_request" {
				t.Fatalf("err %v", err)
			}
			if err.Error() != "bad_request: coordinator url is not allowed" {
				t.Fatalf("text %q", err.Error())
			}
		})
	}
}
