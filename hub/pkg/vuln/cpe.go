package vuln

import (
	"errors"
	"strings"
)

// CPE23 represents a parsed Common Platform Enumeration 2.3 formatted string.
type CPE23 struct {
	Part            string `json:"part"`
	Vendor          string `json:"vendor"`
	Product         string `json:"product"`
	Version         string `json:"version"`
	Update          string `json:"update"`
	Edition         string `json:"edition"`
	Language        string `json:"language"`
	SoftwareEdition string `json:"software_edition"`
	TargetSoftware  string `json:"target_software"`
	TargetHardware  string `json:"target_hardware"`
	Other           string `json:"other"`
}

// ParseCPE parses a CPE 2.3 formatted string or legacy CPE 2.2 URI.
func ParseCPE(raw string) (*CPE23, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty cpe string")
	}

	if strings.HasPrefix(raw, "cpe:2.3:") {
		return parseCPE23Formatted(raw)
	}
	if strings.HasPrefix(raw, "cpe:/") {
		return parseCPE22URI(raw)
	}

	// Plain keyword fallback
	return &CPE23{
		Part:    "a",
		Vendor:  "*",
		Product: unescapeCPEComponent(raw),
		Version: "*",
	}, nil
}

func parseCPE23Formatted(raw string) (*CPE23, error) {
	body := strings.TrimPrefix(raw, "cpe:2.3:")
	tokens := splitCPEEscaped(body)

	cpe := &CPE23{
		Part:            "*",
		Vendor:          "*",
		Product:         "*",
		Version:         "*",
		Update:          "*",
		Edition:         "*",
		Language:        "*",
		SoftwareEdition: "*",
		TargetSoftware:  "*",
		TargetHardware:  "*",
		Other:           "*",
	}

	fields := []*string{
		&cpe.Part, &cpe.Vendor, &cpe.Product, &cpe.Version,
		&cpe.Update, &cpe.Edition, &cpe.Language, &cpe.SoftwareEdition,
		&cpe.TargetSoftware, &cpe.TargetHardware, &cpe.Other,
	}

	for i, token := range tokens {
		if i < len(fields) {
			val := unescapeCPEComponent(token)
			if val == "" {
				val = "*"
			}
			*fields[i] = val
		}
	}

	return cpe, nil
}

func parseCPE22URI(raw string) (*CPE23, error) {
	body := strings.TrimPrefix(raw, "cpe:/")
	tokens := splitCPEEscaped(body)

	cpe := &CPE23{
		Part:            "*",
		Vendor:          "*",
		Product:         "*",
		Version:         "*",
		Update:          "*",
		Edition:         "*",
		Language:        "*",
		SoftwareEdition: "*",
		TargetSoftware:  "*",
		TargetHardware:  "*",
		Other:           "*",
	}

	fields := []*string{
		&cpe.Part, &cpe.Vendor, &cpe.Product, &cpe.Version,
		&cpe.Update, &cpe.Edition, &cpe.Language,
	}

	for i, token := range tokens {
		if i < len(fields) {
			val := unescapeCPEComponent(token)
			if val == "" {
				val = "*"
			}
			*fields[i] = val
		}
	}

	return cpe, nil
}

func splitCPEEscaped(s string) []string {
	var tokens []string
	var cur strings.Builder
	escaped := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escaped {
			cur.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == ':' {
			tokens = append(tokens, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(ch)
	}
	tokens = append(tokens, cur.String())
	return tokens
}

func unescapeCPEComponent(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "*" || s == "-" {
		return s
	}
	var out strings.Builder
	escaped := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escaped {
			out.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		out.WriteByte(ch)
	}
	return strings.ToLower(out.String())
}

// MatchesProduct checks whether an installed software product matches the CPE product.
func (c *CPE23) MatchesProduct(vendor, product string) (bool, float64) {
	if c.Product == "*" {
		return true, 0.50
	}

	target := strings.ToLower(strings.TrimSpace(product))
	cpeProd := strings.ToLower(strings.TrimSpace(c.Product))

	if target == cpeProd {
		return true, 1.00
	}

	// Clean dashes and underscores
	targetNorm := strings.ReplaceAll(target, "_", "-")
	cpeProdNorm := strings.ReplaceAll(cpeProd, "_", "-")

	if targetNorm == cpeProdNorm {
		return true, 1.00
	}

	// Prefix matching with package suffixes: e.g. "openssh-server" vs "openssh"
	if strings.HasPrefix(targetNorm, cpeProdNorm+"-") {
		return true, 0.95
	}

	// Suffix matching: e.g. "libwebp" vs "libwebp7" or "libwebp-dev"
	if strings.HasPrefix(targetNorm, cpeProdNorm) && len(targetNorm) > len(cpeProdNorm) {
		rest := targetNorm[len(cpeProdNorm):]
		if rest[0] >= '0' && rest[0] <= '9' {
			return true, 0.95
		}
	}

	// Strip "lib" prefix
	if strings.HasPrefix(targetNorm, "lib") && targetNorm[3:] == cpeProdNorm {
		return true, 0.92
	}
	if strings.HasPrefix(cpeProdNorm, "lib") && cpeProdNorm[3:] == targetNorm {
		return true, 0.92
	}

	// Specific well-known project aliases
	aliases := map[string][]string{
		"openssh":     {"openssh-server", "openssh-client", "openssh-sftp-server"},
		"http_server": {"apache2", "httpd", "apache"},
		"apache2":     {"http_server", "httpd"},
		"nginx":       {"nginx-core", "nginx-full", "nginx-light", "nginx-extras"},
		"sudo":        {"sudo-ldap"},
		"curl":        {"libcurl4", "libcurl3", "libcurl"},
		"xz":          {"xz-utils", "liblzma5", "xz_utils"},
		"xz_utils":    {"xz-utils", "liblzma5", "xz"},
		"coreutils":   {"coreutils"},
		"libwebp":     {"libwebp7", "libwebp-dev", "libwebp-tools"},
	}

	if list, ok := aliases[cpeProdNorm]; ok {
		for _, a := range list {
			if targetNorm == a || strings.HasPrefix(targetNorm, a+"-") {
				return true, 0.90
			}
		}
	}

	return false, 0.0
}
