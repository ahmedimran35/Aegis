// Package rules: minimal OWASP CRS-to-Aegis rule converter.
//
// Supports the CRS directive subset used in paranoia-levels 1-2 rules:
//
//   SecRule VARIABLES "OPERATOR" "TRANSFORMATIONS:action,id:NNNNNN,..."
//
// Examples handled:
//
//   SecRule ARGS "@rx union\s+select" "id:942100,phase:2,block,severity:CRITICAL,msg:'SQLi'"
//   SecRule REQUEST_HEADERS:User-Agent "@contains sqlmap" "id:913100,...log,..."
//
// Out of scope (returns error or warning):
//   - chained rules (no "chain" directive support yet)
//   - Lua-script-backed operators (@pmFromFile, @geoLookup)
//   - complex variable lists (TX:foo, REQUEST_COOKIES_NAMES)
//
// For full CRS coverage, see the upstream ModSecurity rule set — Aegis
// imports only the regex/contains operators.
package rules

import (
	"bufio"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// CRSRule is an intermediate representation parsed from one SecRule line.
type CRSRule struct {
	ID          int
	Phase       int
	Action      string // block, log, drop, deny
	Severity    string
	Msg         string
	Variable    string
	Operator    string // rx, contains, eq, ge, etc.
	OperatorArg string // the regex pattern or value
}

// CRSImportResult bundles imported rules + warnings.
type CRSImportResult struct {
	Rules    []TemplateRule
	Warnings []string
	Skipped  int
}

// secRuleRE captures a single SecRule directive.
var secRuleRE = regexp.MustCompile(`(?i)^\s*SecRule\s+(\S+)\s+"([^"]+)"\s+"([^"]+)"`)

// operatorRE extracts the operator name and its argument from the second
// quoted string, e.g. "@rx pattern" or "@contains value".
var operatorRE = regexp.MustCompile(`@(\w+)\s+(.*)`)

// parseCRSLine parses one SecRule line into a CRSRule.
func parseCRSLine(line string) (*CRSRule, error) {
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(strings.ToUpper(line), "SECRULE") {
		return nil, fmt.Errorf("not a SecRule line")
	}
	m := secRuleRE.FindStringSubmatch(line)
	if m == nil {
		return nil, fmt.Errorf("malformed SecRule")
	}
	variable, operatorPart, actionsPart := m[1], m[2], m[3]

	// Skip chained rules for now.
	if strings.Contains(strings.ToLower(actionsPart), ",chain,") ||
		strings.HasSuffix(strings.ToLower(strings.TrimSpace(actionsPart)), ",chain") {
		return nil, fmt.Errorf("chained rules not supported")
	}

	// Operator + arg.
	opMatch := operatorRE.FindStringSubmatch(operatorPart)
	if opMatch == nil {
		return nil, fmt.Errorf("unrecognized operator: %s", operatorPart)
	}
	opName, opArg := opMatch[1], strings.TrimSpace(opMatch[2])

	rule := &CRSRule{
		Variable:    variable,
		Operator:    strings.ToLower(opName),
		OperatorArg: opArg,
		Phase:       2, // default
		Action:      "log",
		Severity:    "medium",
	}

	// Parse actions (comma-separated, key:value or keyword).
	for _, a := range strings.Split(actionsPart, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		kv := strings.SplitN(a, ":", 2)
		key := strings.ToLower(kv[0])
		val := ""
		if len(kv) == 2 {
			val = kv[1]
		}
		switch key {
		case "id":
			if n, err := strconv.Atoi(val); err == nil {
				rule.ID = n
			}
		case "phase":
			if n, err := strconv.Atoi(val); err == nil {
				rule.Phase = n
			}
		case "block", "deny", "drop":
			rule.Action = "block"
		case "log", "pass":
			if rule.Action != "block" {
				rule.Action = "log"
			}
		case "severity":
			rule.Severity = mapCRSSeverity(val)
		case "msg":
			rule.Msg = strings.Trim(val, "'\"")
		}
	}
	return rule, nil
}

// mapCRSSeverity converts CRS severity strings (CRITICAL, HIGH, MEDIUM,
// LOW, INFORMATIONAL) into Aegis rule severities.
func mapCRSSeverity(s string) string {
	switch strings.ToUpper(s) {
	case "CRITICAL", "EMERGENCY":
		return "critical"
	case "HIGH", "ERROR":
		return "high"
	case "MEDIUM", "WARNING":
		return "medium"
	case "LOW", "NOTICE":
		return "low"
	default:
		return "info"
	}
}

// toTemplateRule converts a parsed CRS rule into an Aegis TemplateRule.
func (r *CRSRule) toTemplateRule() TemplateRule {
	matchType := "regex"
	switch r.Operator {
	case "rx":
		matchType = "regex"
	case "contains":
		matchType = "contains"
	case "eq", "streq":
		matchType = "equals"
	case "beginswith":
		matchType = "begins_with"
	case "endswith":
		matchType = "ends_with"
	}
	name := r.Msg
	if name == "" {
		name = fmt.Sprintf("crs-rule-%d", r.ID)
	}
	return TemplateRule{
		Name:          sanitizeName(name),
		Pattern:       r.OperatorArg,
		MatchType:     matchType,
		Action:        r.Action,
		Severity:      r.Severity,
		Priority:      mapPhaseToPriority(r.Phase),
		ParanoiaLevel: 1,
		Description:   fmt.Sprintf("Imported from CRS rule %d: %s", r.ID, r.Msg),
	}
}

// mapPhaseToPriority converts CRS phase to Aegis priority. Higher = later.
func mapPhaseToPriority(phase int) int {
	switch phase {
	case 1:
		return 100
	case 2:
		return 50
	case 3:
		return 20
	case 4:
		return 10
	default:
		return 50
	}
}

// sanitizeName converts a human-readable rule name into a valid Aegis
// rule identifier (lowercase, dashes, no spaces).
func sanitizeName(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "'", "")
	s = strings.ReplaceAll(s, "\"", "")
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// ImportCRS reads CRS configuration text and converts each SecRule into
// an Aegis TemplateRule. Unsupported rules produce a warning, not a fatal
// error, so partial imports work.
func ImportCRS(text string) CRSImportResult {
	result := CRSImportResult{}
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		rule, err := parseCRSLine(line)
		if err != nil {
			result.Skipped++
			result.Warnings = append(result.Warnings,
				fmt.Sprintf("skipped: %s (%v)", truncate(line, 80), err))
			continue
		}
		result.Rules = append(result.Rules, rule.toTemplateRule())
	}
	return result
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}