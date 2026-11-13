package pair

import (
	"net"
	"net/url"
	"strconv"
	"strings"
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
	host := parsed.Hostname()
	if host == "" || strings.Contains(host, "%") {
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
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	origin := parsed.Scheme + "://" + host + ":" + port
	base := &url.URL{Scheme: parsed.Scheme, Host: net.JoinHostPort(parsed.Hostname(), port)}
	if base.String() != origin {
		// JoinHostPort brackets IPv6. The signed origin uses that same host.
		origin = base.String()
	}
	return base, origin, nil
}

func loopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func allowedPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}
