package compliance

import (
	"fmt"
	"sort"
	"strings"
)

type Score struct {
	Framework string  `json:"framework"`
	Provider  Provider `json:"provider"`
	Passed    int     `json:"passed"`
	Total     int     `json:"total"`
	Percent   float64 `json:"percent"`
}

type Report struct {
	Findings []Finding `json:"findings"`
	Scores   []Score   `json:"scores"`
	Total    int       `json:"total"`
	Critical int       `json:"critical"`
	High     int       `json:"high"`
	Medium   int       `json:"medium"`
	Low      int       `json:"low"`
	Overall  float64   `json:"overall"`
}

func BuildReport(scanners []Scanner, resources map[Provider][]map[string]any) *Report {
	var findings []Finding
	for _, scanner := range scanners {
		for _, resource := range resources[scanner.Provider()] {
			findings = append(findings, CheckResource(scanner, resource)...)
		}
	}

	report := &Report{Findings: findings}
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			report.Critical++
		case SeverityHigh:
			report.High++
		case SeverityMedium:
			report.Medium++
		case SeverityLow:
			report.Low++
		}
	}

	report.Total = len(findings)
	frameworks := []string{"cis", "soc2", "hipaa", "pci-dss"}
	for _, framework := range frameworks {
		for _, scanner := range scanners {
			passed, total := 0, 0
			for _, check := range scanner.Checks() {
				if !contains(check.Frameworks, framework) {
					continue
				}
				total++
				passed++
				for _, f := range findings {
					if f.Provider == scanner.Provider() && f.ID == check.ID {
						passed--
						break
					}
				}
			}
			percent := 0.0
			if total > 0 {
				percent = float64(passed) / float64(total) * 100
			}
			report.Scores = append(report.Scores, Score{
				Framework: framework,
				Provider:  scanner.Provider(),
				Passed:    passed,
				Total:     total,
				Percent:   round2(percent),
			})
		}
	}
	sort.Slice(report.Scores, func(i, j int) bool {
		if report.Scores[i].Framework != report.Scores[j].Framework {
			return report.Scores[i].Framework < report.Scores[j].Framework
		}
		return report.Scores[i].Provider < report.Scores[j].Provider
	})

	totalScore := 0.0
	count := 0
	for _, s := range report.Scores {
		if s.Total > 0 {
			totalScore += s.Percent
			count++
		}
	}
	if count > 0 {
		report.Overall = round2(totalScore / float64(count))
	}
	return report
}

func contains(list []string, value string) bool {
	for _, v := range list {
		if v == value {
			return true
		}
	}
	return false
}

func round2(v float64) float64 {
	return float64(int(v*100)) / 100
}

func (r *Report) Markdown() string {
	var b strings.Builder
	b.WriteString("# Cloud Compliance Dashboard\n\n")
	b.WriteString(fmt.Sprintf("**Overall compliance: %.1f%%**\n\n", r.Overall))
	b.WriteString("| Severity | Count |\n|---|---|\n")
	b.WriteString(fmt.Sprintf("| critical | %d |\n", r.Critical))
	b.WriteString(fmt.Sprintf("| high | %d |\n", r.High))
	b.WriteString(fmt.Sprintf("| medium | %d |\n", r.Medium))
	b.WriteString(fmt.Sprintf("| low | %d |\n\n", r.Low))
	b.WriteString("## Scores by framework/provider\n\n")
	b.WriteString("| Framework | Provider | Passed | Total | Percent |\n|---|---|---|---|---|\n")
	for _, s := range r.Scores {
		b.WriteString(fmt.Sprintf("| %s | %s | %d | %d | %.1f%% |\n", s.Framework, s.Provider, s.Passed, s.Total, s.Percent))
	}
	b.WriteString("\n## Findings\n\n")
	for _, f := range r.Findings {
		b.WriteString(fmt.Sprintf("- **[%s]** %s (%s) - %s\n", f.Severity, f.ID, f.Provider, f.Description))
		b.WriteString(fmt.Sprintf("  - Remediation: `%s`\n", f.Remediation))
	}
	return b.String()
}
