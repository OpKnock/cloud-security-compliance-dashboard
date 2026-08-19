package compliance

import (
	"sort"
	"strings"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

type Provider string

const (
	ProviderAWS   Provider = "aws"
	ProviderAzure Provider = "azure"
	ProviderGCP   Provider = "gcp"
)

type Finding struct {
	ID           string   `json:"id"`
	Provider     Provider `json:"provider"`
	Service      string   `json:"service"`
	Resource     string   `json:"resource"`
	Severity     Severity `json:"severity"`
	Description  string   `json:"description"`
	CISControl   string   `json:"cis_control"`
	Frameworks   []string `json:"frameworks"`
	Remediation  string   `json:"remediation"`
}

type Check struct {
	ID          string
	Provider    Provider
	Service     string
	Description string
	Severity    Severity
	CISControl  string
	Frameworks  []string
	Remediation string
	Pass        func(resource map[string]any) bool
}

type Scanner interface {
	Provider() Provider
	Checks() []Check
}

func CheckResource(scanner Scanner, resource map[string]any) []Finding {
	var findings []Finding
	service := str(resource["service"])
	for _, check := range scanner.Checks() {
		if service != "" && check.Service != service {
			continue
		}
		if check.Pass(resource) {
			continue
		}
		findings = append(findings, Finding{
			ID:          check.ID,
			Provider:    scanner.Provider(),
			Service:     check.Service,
			Resource:    resourceName(resource),
			Severity:    check.Severity,
			Description: check.Description,
			CISControl:  check.CISControl,
			Frameworks:  append([]string{}, check.Frameworks...),
			Remediation: check.Remediation,
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		return severityRank(findings[i].Severity) < severityRank(findings[j].Severity)
	})
	return findings
}

func resourceName(resource map[string]any) string {
	if name, ok := resource["name"].(string); ok {
		return name
	}
	if arn, ok := resource["arn"].(string); ok {
		return arn
	}
	return "unknown"
}

func severityRank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityHigh:
		return 1
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 3
	}
	return 4
}

func FrameworksFor(s Severity) []string {
	switch s {
	case SeverityCritical, SeverityHigh:
		return []string{"cis", "soc2", "hipaa", "pci-dss"}
	default:
		return []string{"cis", "soc2"}
	}
}

func normalize(v any) bool {
	b, ok := v.(bool)
	if ok {
		return b
	}
	s, ok := v.(string)
	if ok {
		return strings.EqualFold(s, "true")
	}
	return false
}

func allowed(s map[string]any, keys ...string) bool {
	if len(keys) == 0 {
		return false
	}
	for _, k := range keys {
		if s == nil || s[k] == nil {
			return false
		}
	}
	return true
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return strings.ToLower(s)
	}
	return ""
}
