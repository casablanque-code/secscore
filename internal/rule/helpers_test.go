package rule

import (
	"testing"

	"secscore/internal/model"
)

// assertFinding checks that a finding with the given ID and severity exists.
func assertFinding(t *testing.T, findings []model.Finding, id string, sev model.Severity) {
	t.Helper()
	f := findByID(findings, id)
	if f == nil {
		t.Errorf("expected finding %q not found; got: %v", id, findingIDs(findings))
		return
	}
	if f.Severity != sev {
		t.Errorf("finding %q: severity=%q want %q", id, f.Severity, sev)
	}
}

func findByID(findings []model.Finding, id string) *model.Finding {
	for i := range findings {
		if findings[i].ID == id {
			return &findings[i]
		}
	}
	return nil
}

func findingIDs(findings []model.Finding) []string {
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = string(f.Severity) + ":" + f.ID
	}
	return ids
}
