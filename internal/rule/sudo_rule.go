package rule

import (
	"fmt"
	"strings"

	"github.com/casablanque-code/secscore/internal/model"
)

type SudoRule struct{}

func NewSudoRule() *SudoRule { return &SudoRule{} }

func (r *SudoRule) Name() string { return "sudo" }

func (r *SudoRule) Evaluate(snapshot model.Snapshot) []model.Finding {
	var findings []model.Finding

	for _, entry := range snapshot.Sudoers {
		severity := model.SeverityWarning
		penalty := 15
		desc := fmt.Sprintf("User/group %q has passwordless sudo access.", entry.User)

		// NOPASSWD: ALL is the worst case
		if strings.Contains(strings.ToUpper(entry.Raw), "NOPASSWD: ALL") ||
			strings.Contains(strings.ToUpper(entry.Raw), "NOPASSWD:ALL") {
			severity = model.SeverityCritical
			penalty = 25
			desc = fmt.Sprintf("User/group %q has unrestricted passwordless sudo (NOPASSWD: ALL).", entry.User)
		}

		findings = append(findings, model.Finding{
			ID:             fmt.Sprintf("sudo-nopasswd-%s", sanitizeID(entry.User)),
			Severity:       severity,
			Title:          fmt.Sprintf("NOPASSWD sudo: %s", entry.User),
			Description:    desc + fmt.Sprintf(" Source: %s", entry.Source),
			Recommendation: "Restrict sudo to specific commands or require password: remove NOPASSWD from sudoers.",
			Penalty:        penalty,
			Evidence: []model.Evidence{
				{Source: entry.Source, Details: entry.Raw},
			},
		})
	}

	return findings
}

func sanitizeID(s string) string {
	s = strings.TrimPrefix(s, "%")
	return strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, s)
}
