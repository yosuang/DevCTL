package pair

import (
	"net"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// coordinatorIDNA is the URL hostname algorithm the coordinator uses.
// Labels are lowercase, and Unicode labels are punycode. Transitional
// mapping is off, matching URL domain-to-ASCII with beStrict false.
var coordinatorIDNA = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.Transitional(false),
	idna.VerifyDNSLength(false),
	idna.StrictDomainName(false),
	idna.CheckHyphens(false),
	idna.CheckJoiners(true),
)

// parseCoordinator checks the coordinator origin.
// http is allowed only for localhost, 127.0.0.1, and ::1.
// There is no default origin.
func parseCoordinator(raw string) (*url.URL, string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.Opaque != "" || parsed.User != nil {
		return nil, "", serverCode("bad_request", "coordinator url is not allowed")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, "", serverCode("bad_request", "coordinator url is not allowed")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, "", serverCode("bad_request", "coordinator url is not allowed")
	}
	host, err := canonicalHost(parsed.Hostname())
	if err != nil || host == "" || strings.Contains(host, "%") {
		return nil, "", serverCode("bad_request", "coordinator url is not allowed")
	}
	if parsed.Scheme == "http" && !loopbackHost(host) {
		return nil, "", serverCode("bad_request", "coordinator url is not allowed")
	}
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	} else if !allowedPort(port) {
		return nil, "", serverCode("bad_request", "coordinator url is not allowed")
	}
	base := &url.URL{Scheme: parsed.Scheme, Host: net.JoinHostPort(host, port)}
	return base, base.String(), nil
}

// canonicalHost returns the host a URL parser will put in request.url.
// DNS names are lowercased and converted to punycode.
// IP addresses use net.IP.String, which drops leading zeros and compresses
// the longest run of zero groups. That is the host the signature covers.
func canonicalHost(host string) (string, error) {
	if host == "" {
		return "", serverCode("bad_request", "coordinator url is not allowed")
	}
	unescaped, err := url.PathUnescape(host)
	if err != nil || strings.Contains(unescaped, "%") {
		return "", serverCode("bad_request", "coordinator url is not allowed")
	}
	if ip := net.ParseIP(unescaped); ip != nil {
		return ip.String(), nil
	}
	ascii, err := coordinatorIDNA.ToASCII(unescaped)
	if err != nil || ascii == "" {
		return "", serverCode("bad_request", "coordinator url is not allowed")
	}
	return ascii, nil
}

func loopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func allowedPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}
