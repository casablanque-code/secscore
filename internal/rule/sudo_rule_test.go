package rule

import (
	"testing"

	"secscore/internal/model"
)

func TestSudoRule_NopasswdAll_Critical(t *testing.T) {
	snap := model.Snapshot{
		Sudoers: []model.SudoEntry{
			{
				User:   "deploy",
				Source: "/etc/sudoers",
				Raw:    "deploy ALL=(ALL) NOPASSWD: ALL",
			},
		},
	}

	findings := NewSudoRule().Evaluate(snap)

	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := findings[0]
	if f.Severity != model.SeverityCritical {
		t.Errorf("NOPASSWD: ALL should be CRITICAL, got %q", f.Severity)
	}
	if f.Penalty < 20 {
		t.Errorf("NOPASSWD: ALL penalty should be ≥20, got %d", f.Penalty)
	}
}

func TestSudoRule_NopasswdScoped_Warning(t *testing.T) {
	// Scoped NOPASSWD (specific command) — WARNING not CRITICAL
	snap := model.Snapshot{
		Sudoers: []model.SudoEntry{
			{
				User:   "deploy",
				Source: "/etc/sudoers.d/deploy",
				Raw:    "deploy ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart myapp",
			},
		},
	}

	findings := NewSudoRule().Evaluate(snap)

	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if findings[0].Severity != model.SeverityWarning {
		t.Errorf("scoped NOPASSWD should be WARNING, got %q", findings[0].Severity)
	}
}

func TestSudoRule_NoEntries_NoFindings(t *testing.T) {
	snap := model.Snapshot{Sudoers: []model.SudoEntry{}}
	findings := NewSudoRule().Evaluate(snap)
	if len(findings) != 0 {
		t.Errorf("expected no findings for empty sudoers, got %d", len(findings))
	}
}

func TestSudoRule_MultipleEntries(t *testing.T) {
	snap := model.Snapshot{
		Sudoers: []model.SudoEntry{
			{User: "alice", Source: "/etc/sudoers", Raw: "alice ALL=(ALL) NOPASSWD: ALL"},
			{User: "bob", Source: "/etc/sudoers.d/bob", Raw: "bob ALL=(ALL) NOPASSWD: /usr/bin/apt"},
		},
	}

	findings := NewSudoRule().Evaluate(snap)

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// alice gets CRITICAL, bob gets WARNING
	aliceFound, bobFound := false, false
	for _, f := range findings {
		if f.ID == "sudo-nopasswd-alice" && f.Severity == model.SeverityCritical {
			aliceFound = true
		}
		if f.ID == "sudo-nopasswd-bob" && f.Severity == model.SeverityWarning {
			bobFound = true
		}
	}
	if !aliceFound {
		t.Errorf("expected CRITICAL for alice NOPASSWD:ALL, findings: %+v", findingIDs(findings))
	}
	if !bobFound {
		t.Errorf("expected WARNING for bob scoped NOPASSWD, findings: %+v", findingIDs(findings))
	}
}

func TestSudoRule_GroupEntry(t *testing.T) {
	snap := model.Snapshot{
		Sudoers: []model.SudoEntry{
			{User: "%sudo", Source: "/etc/sudoers", Raw: "%sudo ALL=(ALL) NOPASSWD: ALL"},
		},
	}

	findings := NewSudoRule().Evaluate(snap)
	if len(findings) == 0 {
		t.Fatal("expected finding for group NOPASSWD: ALL")
	}
	if findings[0].Severity != model.SeverityCritical {
		t.Errorf("group NOPASSWD: ALL should be CRITICAL, got %q", findings[0].Severity)
	}
}
