package proxy

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net/url"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var errBadPin = errors.New("pin")

// outboundType is the set of URI schemes this package can write.
// The keys must match v1.json uri_schemes. Tests compare the two.
var outboundType = map[string]string{
	"hysteria2": "hysteria2",
	"hy2":       "hysteria2",
}

// allowedQuery is the Hysteria 2 URI query set from the URI scheme page.
// ech is recognized and refused: its Mihomo field was not checked end to end.
var allowedQuery = map[string]struct{}{
	"obfs":          {},
	"obfs-password": {},
	"sni":           {},
	"insecure":      {},
	"pinSHA256":     {},
	"ech":           {},
}

// runtimeConfig uses keys from the Mihomo general, SOCKS listener, and
// Hysteria2 proxy pages. up and down are omitted: those pages treat them as
// optional, and this package does not invent a rate. tun, iptables,
// tproxy-port, and the external controller are not written.
type runtimeConfig struct {
	AllowLAN        bool       `yaml:"allow-lan"`
	BindAddress     yamlString `yaml:"bind-address"`
	Mode            yamlString `yaml:"mode"`
	FindProcessMode yamlString `yaml:"find-process-mode"`
	LogLevel        yamlString `yaml:"log-level"`
	IPv6            bool       `yaml:"ipv6"`
	GeoAutoUpdate   bool       `yaml:"geo-auto-update"`
	Proxies         []proxyOut `yaml:"proxies"`
	Listeners       []socksIn  `yaml:"listeners"`
	Rules           []string   `yaml:"rules"`
}

type proxyOut struct {
	Name           yamlString `yaml:"name"`
	Type           yamlString `yaml:"type"`
	Server         yamlString `yaml:"server"`
	Port           int        `yaml:"port"`
	Password       yamlString `yaml:"password"`
	Obfs           yamlString `yaml:"obfs,omitempty"`
	ObfsPassword   yamlString `yaml:"obfs-password,omitempty"`
	SNI            yamlString `yaml:"sni,omitempty"`
	SkipCertVerify *bool      `yaml:"skip-cert-verify,omitempty"`
	Fingerprint    yamlString `yaml:"fingerprint,omitempty"`
}

type socksIn struct {
	Name   yamlString `yaml:"name"`
	Type   yamlString `yaml:"type"`
	Listen yamlString `yaml:"listen"`
	Port   int        `yaml:"port"`
	UDP    bool       `yaml:"udp"`
}

// yamlString forces a YAML string so values such as "true" stay strings.
type yamlString string

func (s yamlString) MarshalYAML() (any, error) {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: string(s)}, nil
}

func parseURI(raw []byte) (proxyOut, error) {
	var zero proxyOut
	if len(raw) == 0 || bytes.IndexByte(raw, 0) >= 0 || bytes.ContainsAny(raw, " \t\r\n") {
		return zero, local("uri_invalid", "uri is not usable")
	}
	if portHop(raw) {
		return zero, local("uri_unsupported", "uri parameter is not supported")
	}
	parsed, err := url.Parse(string(raw))
	if err != nil {
		return zero, local("uri_invalid", "uri is not usable")
	}
	scheme := parsed.Scheme
	if strings.HasSuffix(scheme, "+realm") {
		return zero, local("uri_unsupported", "uri parameter is not supported")
	}
	kind, ok := outboundType[scheme]
	if !ok {
		return zero, local("uri_invalid", "uri is not usable")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return zero, local("uri_invalid", "uri is not usable")
	}
	if parsed.User == nil || parsed.Hostname() == "" {
		return zero, local("uri_invalid", "uri is not usable")
	}
	user := parsed.User.Username()
	pass, hasPass := parsed.User.Password()
	auth := user
	if hasPass {
		auth = user + ":" + pass
	}
	if auth == "" {
		return zero, local("uri_invalid", "uri is not usable")
	}
	serverPort := 443
	if text := parsed.Port(); text != "" {
		n, convErr := strconv.Atoi(text)
		if convErr != nil || n < 1 || n > 65535 {
			return zero, local("uri_invalid", "uri is not usable")
		}
		serverPort = n
	}
	query := parsed.Query()
	for key, values := range query {
		if _, known := allowedQuery[key]; !known || len(values) != 1 {
			return zero, local("uri_invalid", "uri is not usable")
		}
	}
	if _, ok := query["ech"]; ok {
		return zero, local("uri_unsupported", "uri parameter is not supported")
	}
	out := proxyOut{
		Name:     "devctl",
		Type:     yamlString(kind),
		Server:   yamlString(parsed.Hostname()),
		Port:     serverPort,
		Password: yamlString(auth),
	}
	if obfs, ok := query["obfs"]; ok {
		if obfs[0] != "salamander" && obfs[0] != "gecko" {
			return zero, local("uri_invalid", "uri is not usable")
		}
		pw, ok := query["obfs-password"]
		if !ok || pw[0] == "" {
			return zero, local("uri_invalid", "uri is not usable")
		}
		out.Obfs = yamlString(obfs[0])
		out.ObfsPassword = yamlString(pw[0])
	} else if _, ok := query["obfs-password"]; ok {
		return zero, local("uri_invalid", "uri is not usable")
	}
	if sni, ok := query["sni"]; ok {
		if sni[0] == "" || strings.ContainsAny(sni[0], " \t") {
			return zero, local("uri_invalid", "uri is not usable")
		}
		out.SNI = yamlString(sni[0])
	}
	if insecure, ok := query["insecure"]; ok {
		var skip bool
		switch insecure[0] {
		case "1":
			skip = true
		case "0":
			skip = false
		default:
			return zero, local("uri_invalid", "uri is not usable")
		}
		out.SkipCertVerify = &skip
	}
	if pin, ok := query["pinSHA256"]; ok {
		fp, pinErr := certificateFingerprint(pin[0])
		if pinErr != nil {
			return zero, local("uri_invalid", "uri is not usable")
		}
		out.Fingerprint = yamlString(fp)
	}
	return out, nil
}

func renderConfig(out proxyOut, port int) ([]byte, error) {
	if port < 1 || port > 65535 {
		return nil, errNotListening
	}
	cfg := runtimeConfig{
		AllowLAN:        false,
		BindAddress:     loopbackHost,
		Mode:            "rule",
		FindProcessMode: "off",
		LogLevel:        "warning",
		IPv6:            false,
		GeoAutoUpdate:   false,
		Proxies:         []proxyOut{out},
		Listeners: []socksIn{{
			Name:   "loopback",
			Type:   "socks",
			Listen: loopbackHost,
			Port:   port,
			UDP:    true,
		}},
		Rules: []string{"MATCH,devctl"},
	}
	body, err := yaml.Marshal(&cfg)
	if err != nil {
		return nil, local("uri_invalid", "uri is not usable")
	}
	return body, nil
}

// certificateFingerprint returns the lowercase hex SHA-256 pin Mihomo's
// verifier accepts. Hysteria strips ":" and "-"; Mihomo strips ":" and then
// hex-decodes 32 bytes. The emitted form is the intersection, not a copy of
// an unchecked pin.
func certificateFingerprint(pin string) (string, error) {
	cleaned := strings.ToLower(pin)
	cleaned = strings.ReplaceAll(cleaned, ":", "")
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	if len(cleaned) != hex.EncodedLen(32) {
		return "", errBadPin
	}
	raw, err := hex.DecodeString(cleaned)
	if err != nil || len(raw) != 32 {
		return "", errBadPin
	}
	return hex.EncodeToString(raw), nil
}

func portHop(raw []byte) bool {
	rest := string(raw)
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	var port string
	if strings.HasPrefix(rest, "[") {
		end := strings.Index(rest, "]")
		if end >= 0 && end+1 < len(rest) && rest[end+1] == ':' {
			port = rest[end+2:]
		}
	} else if i := strings.LastIndex(rest, ":"); i >= 0 {
		port = rest[i+1:]
	}
	return strings.ContainsAny(port, ",-")
}
