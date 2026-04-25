package engine

import (
	"testing"

	"github.com/casablanque-code/secscore/internal/model"
	"github.com/casablanque-code/secscore/internal/rule"
	"github.com/casablanque-code/secscore/internal/scanner"
)

// fakeScanner allows injecting a pre-built snapshot for engine integration tests.
type fakeScanner struct {
	snap model.Snapshot
}

func (f *fakeScanner) Name() string { return "fake" }
func (f *fakeScanner) Scan(s *model.Snapshot) error {
	s.Services = f.snap.Services
	s.HostListeners = f.snap.HostListeners
	s.UFWStatus = f.snap.UFWStatus
	s.UFWRules = f.snap.UFWRules
	s.SSHD = f.snap.SSHD
	s.Sysctl = f.snap.Sysctl
	s.Sudoers = f.snap.Sudoers
	return nil
}

var _ scanner.Scanner = (*fakeScanner)(nil)

func TestEngine_CleanSystem_Score100(t *testing.T) {
	// A well-configured system should score 100
	snap := model.Snapshot{
		UFWStatus: model.UFWActive,
		UFWRules: []model.UFWRule{
			{Port: 22, Proto: "tcp", Action: "ALLOW", From: "Anywhere"},
		},
		HostListeners: []model.HostListener{
			{Proto: "tcp", Address: "0.0.0.0:22", Port: 22, Process: "sshd"},
		},
		SSHD: model.SSHDConfig{
			Found:           true,
			PermitRootLogin: "no",
			PasswordAuth:    "no",
			MaxAuthTries:    3,
			Port:            22,
		},
		Sysctl: model.SysctlValues{
			Available: true,
			Params: map[string]string{
				"kernel.randomize_va_space": "2",
				"net.ipv4.tcp_syncookies":   "1",
			},
		},
		WorldWritable: []model.WorldWritableFile{}, // empty slice = scanned, clean
	}

	eng := New([]scanner.Scanner{&fakeScanner{snap}}, []rule.Rule{
		rule.NewUFWCorrelationRule(),
		rule.NewSSHDRule(),
		rule.NewSysctlRule(),
		rule.NewSudoRule(),
		rule.NewWorldWritableRule(),
	})

	report, err := eng.Run(true)
	if err != nil {
		t.Fatalf("engine error: %v", err)
	}
	if report.HasCritical() {
		for _, f := range report.Findings {
			if f.Severity == model.SeverityCritical {
				t.Errorf("unexpected CRITICAL: %s — %s", f.ID, f.Title)
			}
		}
	}
	if report.Score < 90 {
		t.Errorf("clean system: score=%d want ≥90", report.Score)
	}
}

func TestEngine_CriticalSystem_LowScore(t *testing.T) {
	// A poorly configured system should score low
	snap := model.Snapshot{
		UFWStatus: model.UFWInactive,
		SSHD: model.SSHDConfig{
			Found:                true,
			PermitRootLogin:      "yes",
			PasswordAuth:         "yes",
			PermitEmptyPasswords: "yes",
			MaxAuthTries:         6,
		},
		Sysctl: model.SysctlValues{
			Available: true,
			Params: map[string]string{
				"kernel.randomize_va_space": "0",
			},
		},
	}

	eng := New([]scanner.Scanner{&fakeScanner{snap}}, []rule.Rule{
		rule.NewUFWCorrelationRule(),
		rule.NewSSHDRule(),
		rule.NewSysctlRule(),
	})

	report, err := eng.Run(true)
	if err != nil {
		t.Fatalf("engine error: %v", err)
	}
	if !report.HasCritical() {
		t.Error("expected at least one CRITICAL finding")
	}
	if report.Score > 20 {
		t.Errorf("poorly configured system: score=%d want ≤20", report.Score)
	}
}

func TestEngine_Deduplication(t *testing.T) {
	// Same finding ID from multiple rule evaluations should appear only once
	snap := model.Snapshot{UFWStatus: model.UFWInactive}

	// Two rules that would both emit "ufw-inactive" if they could
	eng := New(
		[]scanner.Scanner{&fakeScanner{snap}},
		[]rule.Rule{
			rule.NewUFWCorrelationRule(),
			rule.NewUFWCorrelationRule(), // duplicate rule
		},
	)

	report, err := eng.Run(false)
	if err != nil {
		t.Fatal(err)
	}

	count := 0
	for _, f := range report.Findings {
		if f.ID == "ufw-inactive" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected 1 ufw-inactive finding after dedup, got %d", count)
	}
}
