package vuln

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// ParsedVersion breaks a version string down into epoch, upstream, and revision components.
type ParsedVersion struct {
	Raw        string
	Epoch      int
	Upstream   string
	Revision   string
	HasEpoch   bool
	Tokens     []versionToken
}

type tokenType int

const (
	tokenNum tokenType = iota
	tokenStr
	tokenTilde
	tokenPrerelease
	tokenPatch
)

type versionToken struct {
	typ    tokenType
	strVal string
	numVal uint64
}

// ParseVersion parses a version string into comparable components.
func ParseVersion(v string) *ParsedVersion {
	pv := &ParsedVersion{Raw: v}
	v = strings.TrimSpace(v)
	if v == "" {
		return pv
	}

	// 1. Check for Debian/RPM epoch (e.g. "1:8.9p1-3ubuntu0.6")
	if colonIdx := strings.Index(v, ":"); colonIdx > 0 {
		if epochNum, err := strconv.Atoi(v[:colonIdx]); err == nil {
			pv.Epoch = epochNum
			pv.HasEpoch = true
			v = v[colonIdx+1:]
		}
	}

	// 2. Check for Debian revision (e.g. "8.9p1-3ubuntu0.6")
	// Per Debian Policy §5.6.12, debian_revision must start with a digit.
	// Hyphens followed by letters indicate upstream prerelease tags (e.g. "2.0-beta9").
	if lastHyphen := strings.LastIndex(v, "-"); lastHyphen > 0 && lastHyphen+1 < len(v) {
		if unicode.IsDigit(rune(v[lastHyphen+1])) {
			pv.Upstream = v[:lastHyphen]
			pv.Revision = v[lastHyphen+1:]
		} else {
			pv.Upstream = v
		}
	} else {
		pv.Upstream = v
	}

	pv.Tokens = tokenizeVersion(pv.Upstream)
	return pv
}

func tokenizeVersion(s string) []versionToken {
	var tokens []versionToken
	i := 0
	n := len(s)

	for i < n {
		ch := rune(s[i])

		if ch == '~' {
			tokens = append(tokens, versionToken{typ: tokenTilde, strVal: "~"})
			i++
			continue
		}

		if unicode.IsDigit(ch) {
			start := i
			for i < n && unicode.IsDigit(rune(s[i])) {
				i++
			}
			numStr := s[start:i]
			val, _ := strconv.ParseUint(numStr, 10, 64)
			tokens = append(tokens, versionToken{typ: tokenNum, strVal: numStr, numVal: val})
			continue
		}

		// Letters and punctuation
		start := i
		for i < n && !unicode.IsDigit(rune(s[i])) && s[i] != '~' {
			i++
		}
		chunk := strings.ToLower(s[start:i])

		// Categorize prereleases vs patches vs separators
		clean := strings.Trim(chunk, ".-_+")
		switch {
		case clean == "alpha" || clean == "a" || clean == "beta" || clean == "b" || clean == "rc" || clean == "pre" || clean == "dev":
			tokens = append(tokens, versionToken{typ: tokenPrerelease, strVal: clean})
		case clean == "p" || clean == "patch" || clean == "pl" || clean == "sp":
			tokens = append(tokens, versionToken{typ: tokenPatch, strVal: clean})
		default:
			tokens = append(tokens, versionToken{typ: tokenStr, strVal: clean})
		}
	}

	return tokens
}

// CompareVersions compares two version strings.
// Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2.
func CompareVersions(v1, v2 string) int {
	pv1 := ParseVersion(v1)
	pv2 := ParseVersion(v2)

	// If both have explicit epochs, compare epochs first
	if pv1.HasEpoch && pv2.HasEpoch {
		if pv1.Epoch < pv2.Epoch {
			return -1
		}
		if pv1.Epoch > pv2.Epoch {
			return 1
		}
	}

	// Compare upstream tokens
	t1 := pv1.Tokens
	t2 := pv2.Tokens
	l1 := len(t1)
	l2 := len(t2)
	minLen := l1
	if l2 < minLen {
		minLen = l2
	}

	for i := 0; i < minLen; i++ {
		tok1 := t1[i]
		tok2 := t2[i]

		// Tilde handling: tilde is always smaller than anything
		if tok1.typ == tokenTilde && tok2.typ != tokenTilde {
			return -1
		}
		if tok2.typ == tokenTilde && tok1.typ != tokenTilde {
			return 1
		}

		// Prerelease handling
		if tok1.typ == tokenPrerelease && tok2.typ != tokenPrerelease {
			return -1
		}
		if tok2.typ == tokenPrerelease && tok1.typ != tokenPrerelease {
			return 1
		}

		// Numeric comparison
		if tok1.typ == tokenNum && tok2.typ == tokenNum {
			if tok1.numVal < tok2.numVal {
				return -1
			}
			if tok1.numVal > tok2.numVal {
				return 1
			}
			continue
		}

		// Numeric vs String
		if tok1.typ == tokenNum && tok2.typ != tokenNum {
			return 1
		}
		if tok1.typ != tokenNum && tok2.typ == tokenNum {
			return -1
		}

		// String vs String
		if tok1.strVal != tok2.strVal {
			if tok1.strVal < tok2.strVal {
				return -1
			}
			return 1
		}
	}

	// If prefixes matched, examine trailing tokens
	if l1 < l2 {
		// If next token in v2 is a prerelease or tilde, then v1 (final) is GREATER than v2 (prerelease)
		if t2[l1].typ == tokenPrerelease || t2[l1].typ == tokenTilde {
			return 1
		}
		return -1
	}
	if l1 > l2 {
		// If next token in v1 is a prerelease or tilde, v1 is SMALLER than v2
		if t1[l2].typ == tokenPrerelease || t1[l2].typ == tokenTilde {
			return -1
		}
		return 1
	}

	// If upstream matched and both have revisions, compare revisions
	if pv1.Revision != "" && pv2.Revision != "" {
		rev1Tokens := tokenizeVersion(pv1.Revision)
		rev2Tokens := tokenizeVersion(pv2.Revision)
		rMin := len(rev1Tokens)
		if len(rev2Tokens) < rMin {
			rMin = len(rev2Tokens)
		}
		for i := 0; i < rMin; i++ {
			rt1 := rev1Tokens[i]
			rt2 := rev2Tokens[i]
			if rt1.typ == tokenNum && rt2.typ == tokenNum {
				if rt1.numVal < rt2.numVal {
					return -1
				}
				if rt1.numVal > rt2.numVal {
					return 1
				}
				continue
			}
			if rt1.strVal != rt2.strVal {
				if rt1.strVal < rt2.strVal {
					return -1
				}
				return 1
			}
		}
		if len(rev1Tokens) < len(rev2Tokens) {
			return -1
		}
		if len(rev1Tokens) > len(rev2Tokens) {
			return 1
		}
	}

	return 0
}

// EvaluateVersionRange tests an installed version against CPE match criteria boundaries.
func EvaluateVersionRange(installedVer string, criteria CPEMatchCriteria) (MatchStatus, string, string) {
	installedVer = strings.TrimSpace(installedVer)
	if installedVer == "" || installedVer == "-" {
		return MatchStatusInsufficientData, "Installed software missing version", "unknown"
	}

	rangeParts := []string{}
	start := "["
	if criteria.VersionStartExcluding != "" {
		start = "(" + criteria.VersionStartExcluding
	} else if criteria.VersionStartIncluding != "" {
		start = "[" + criteria.VersionStartIncluding
	} else {
		start = "(*"
	}
	rangeParts = append(rangeParts, start)

	end := "*)"
	if criteria.VersionEndExcluding != "" {
		end = criteria.VersionEndExcluding + ")"
	} else if criteria.VersionEndIncluding != "" {
		end = criteria.VersionEndIncluding + "]"
	}
	rangeParts = append(rangeParts, end)
	rangeStr := strings.Join(rangeParts, ", ")

	// 1. Check versionStartIncluding (>= start)
	if criteria.VersionStartIncluding != "" {
		cmp := CompareVersions(installedVer, criteria.VersionStartIncluding)
		if cmp < 0 {
			return MatchStatusNotAffected,
				fmt.Sprintf("Installed version %s is older than affected start boundary %s", installedVer, criteria.VersionStartIncluding),
				rangeStr
		}
	}

	// 2. Check versionStartExcluding (> start)
	if criteria.VersionStartExcluding != "" {
		cmp := CompareVersions(installedVer, criteria.VersionStartExcluding)
		if cmp <= 0 {
			return MatchStatusNotAffected,
				fmt.Sprintf("Installed version %s is at or below excluded start boundary %s", installedVer, criteria.VersionStartExcluding),
				rangeStr
		}
	}

	// 3. Check versionEndIncluding (<= end)
	if criteria.VersionEndIncluding != "" {
		cmp := CompareVersions(installedVer, criteria.VersionEndIncluding)
		if cmp > 0 {
			return MatchStatusNotAffected,
				fmt.Sprintf("Installed version %s is newer than affected end boundary %s (patched)", installedVer, criteria.VersionEndIncluding),
				rangeStr
		}
	}

	// 4. Check versionEndExcluding (< end)
	if criteria.VersionEndExcluding != "" {
		cmp := CompareVersions(installedVer, criteria.VersionEndExcluding)
		if cmp >= 0 {
			return MatchStatusNotAffected,
				fmt.Sprintf("Installed version %s is at or above excluded end boundary %s (patched)", installedVer, criteria.VersionEndExcluding),
				rangeStr
		}
	}

	// 5. If no range boundaries are set, check exact CPE version
	if criteria.VersionStartIncluding == "" && criteria.VersionStartExcluding == "" &&
		criteria.VersionEndIncluding == "" && criteria.VersionEndExcluding == "" {
		cpe, err := ParseCPE(criteria.Criteria)
		if err == nil && cpe.Version != "*" && cpe.Version != "-" {
			cmp := CompareVersions(installedVer, cpe.Version)
			if cmp != 0 {
				return MatchStatusNotAffected,
					fmt.Sprintf("Installed version %s does not match exact CPE version %s", installedVer, cpe.Version),
					cpe.Version
			}
			return MatchStatusMatched,
				fmt.Sprintf("Installed version %s exactly matches CPE version %s", installedVer, cpe.Version),
				cpe.Version
		}
	}

	return MatchStatusMatched,
		fmt.Sprintf("Installed version %s falls within vulnerable range %s", installedVer, rangeStr),
		rangeStr
}
