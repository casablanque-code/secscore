package rule

import (
	"testing"

	"secscore/internal/model"
)

func TestUFWCorrelation_Inactive(t *testing.T) {
	snap := model.Snapshot{UFWStatus: model.UFWInactive}
	findings := NewUFWCorrelationRule().Evaluate(snap)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].ID != "ufw-inactive" {
		t.Errorf("expected ufw-inactive, got %q", findings[0].ID)
	}
	if findings[0].Severity != model.SeverityCritical {
		t.Errorf("expected CRITICAL, got %q", findings[0].Severity)
	}
}

func TestUFWCorrelation_Unknown(t *testing.T) {
	snap := model.Snapshot{UFWStatus: model.UFWUnknown}
	findings := NewUFWCorrelationRule().Evaluate(snap)

	if len(findings) != 1 || findings[0].ID != "ufw-not-found" {
		t.Errorf("expected ufw-not-found finding")
	}
	if findings[0].Severity != model.SeverityWarning {
		t.Errorf("expected WARNING for missing ufw")
	}
}

func TestUFWCorrelation_PortAllowed_NoWarning(t *testing.T) {
	// Port is open AND there's an ALLOW rule → INFO, no warning
	snap := model.Snapshot{
		UFWStatus: model.UFWActive,
		UFWRules: []model.UFWRule{
			{Port: 22, Proto: "tcp", Action: "ALLOW", From: "Anywhere"},
		},
		HostListeners: []model.HostListener{
			{Proto: "tcp", Address: "0.0.0.0:22", Port: 22},
		},
	}

	findings := NewUFWCorrelationRule().Evaluate(snap)

	for _, f := range findings {
		if f.Severity == model.SeverityWarning || f.Severity == model.SeverityCritical {
			t.Errorf("expected no warnings/criticals for explicitly allowed port, got: %s %s", f.Severity, f.ID)
		}
	}
}

func TestUFWCorrelation_PortNoRule_Warning(t *testing.T) {
	// Port is open, no ufw rule at all → WARNING
	snap := model.Snapshot{
		UFWStatus:     model.UFWActive,
		UFWRules:      []model.UFWRule{},
		HostListeners: []model.HostListener{
			{Proto: "tcp", Address: "0.0.0.0:9090", Port: 9090},
		},
	}

	findings := NewUFWCorrelationRule().Evaluate(snap)

	found := false
	for _, f := range findings {
		if f.ID == "ufw-no-rule-9090-tcp" && f.Severity == model.SeverityWarning {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ufw-no-rule-9090-tcp WARNING, findings: %+v", findings)
	}
}

func TestUFWCorrelation_DeniedButOpen_Critical(t *testing.T) {
	// Port has DENY rule but is still open → CRITICAL (Docker bypass scenario)
	snap := model.Snapshot{
		UFWStatus: model.UFWActive,
		UFWRules: []model.UFWRule{
			{Port: 5432, Proto: "tcp", Action: "DENY", From: "Anywhere"},
		},
		HostListeners: []model.HostListener{
			{Proto: "tcp", Address: "0.0.0.0:5432", Port: 5432},
		},
	}

	findings := NewUFWCorrelationRule().Evaluate(snap)

	found := false
	for _, f := range findings {
		if f.ID == "ufw-denied-but-open-5432-tcp" && f.Severity == model.SeverityCritical {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ufw-denied-but-open-5432-tcp CRITICAL, findings: %+v", findings)
	}
}

func TestUFWCorrelation_LocalhostIgnored(t *testing.T) {
	// Localhost listeners should be ignored entirely
	snap := model.Snapshot{
		UFWStatus: model.UFWActive,
		UFWRules:  []model.UFWRule{},
		HostListeners: []model.HostListener{
			{Proto: "tcp", Address: "127.0.0.1:9000", Port: 9000},
			{Proto: "tcp", Address: "[::1]:8080", Port: 8080},
		},
	}

	findings := NewUFWCorrelationRule().Evaluate(snap)

	for _, f := range findings {
		if f.Severity == model.SeverityWarning {
			t.Errorf("localhost listeners should not generate warnings, got: %s", f.ID)
		}
	}
}

func TestUFWCorrelation_LimitBonus(t *testing.T) {
	snap := model.Snapshot{
		UFWStatus: model.UFWActive,
		UFWRules: []model.UFWRule{
			{Port: 22, Proto: "tcp", Action: "LIMIT", From: "Anywhere"},
		},
		HostListeners: []model.HostListener{
			{Proto: "tcp", Address: "0.0.0.0:22", Port: 22},
		},
	}

	findings := NewUFWCorrelationRule().Evaluate(snap)

	foundBonus := false
	for _, f := range findings {
		if f.ID == "ufw-limited-22-tcp" && f.Penalty < 0 {
			foundBonus = true
		}
	}
	if !foundBonus {
		t.Errorf("expected bonus finding for LIMIT rule, findings: %+v", findings)
	}
}

func TestUFWCorrelation_AllCoveredBonus(t *testing.T) {
	snap := model.Snapshot{
		UFWStatus: model.UFWActive,
		UFWRules: []model.UFWRule{
			{Port: 22, Proto: "tcp", Action: "ALLOW", From: "Anywhere"},
			{Port: 443, Proto: "tcp", Action: "ALLOW", From: "Anywhere"},
		},
		HostListeners: []model.HostListener{
			{Proto: "tcp", Address: "0.0.0.0:22", Port: 22},
			{Proto: "tcp", Address: "0.0.0.0:443", Port: 443},
		},
	}

	findings := NewUFWCorrelationRule().Evaluate(snap)

	found := false
	for _, f := range findings {
		if f.ID == "ufw-fully-covered" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected ufw-fully-covered bonus when all ports have rules")
	}
}
