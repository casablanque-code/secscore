package rule

import (
	"testing"

	"github.com/casablanque-code/secscore/internal/model"
)

func sshdSnap(cfg model.SSHDConfig) model.Snapshot {
	return model.Snapshot{SSHD: cfg}
}

func TestSSHDRule_RootLoginYes_Critical(t *testing.T) {
	snap := sshdSnap(model.SSHDConfig{
		Found:           true,
		PermitRootLogin: "yes",
		PasswordAuth:    "no",
		MaxAuthTries:    3,
	})

	findings := NewSSHDRule().Evaluate(snap)
	assertFinding(t, findings, "sshd-root-login", model.SeverityCritical)
}

func TestSSHDRule_RootLoginNo_Bonus(t *testing.T) {
	snap := sshdSnap(model.SSHDConfig{
		Found:           true,
		PermitRootLogin: "no",
		PasswordAuth:    "no",
		MaxAuthTries:    3,
	})

	findings := NewSSHDRule().Evaluate(snap)
	f := findByID(findings, "sshd-root-login-disabled")
	if f == nil {
		t.Fatal("expected sshd-root-login-disabled bonus finding")
	}
	if f.Penalty >= 0 {
		t.Errorf("expected negative penalty (bonus), got %d", f.Penalty)
	}
}

func TestSSHDRule_PasswordAuthNo_Bonus(t *testing.T) {
	snap := sshdSnap(model.SSHDConfig{
		Found:           true,
		PermitRootLogin: "no",
		PasswordAuth:    "no",
		MaxAuthTries:    3,
	})

	findings := NewSSHDRule().Evaluate(snap)
	f := findByID(findings, "sshd-password-auth-disabled")
	if f == nil {
		t.Fatal("expected sshd-password-auth-disabled bonus")
	}
	if f.Penalty >= 0 {
		t.Errorf("expected negative penalty, got %d", f.Penalty)
	}
}

func TestSSHDRule_EmptyPasswordsCritical(t *testing.T) {
	snap := sshdSnap(model.SSHDConfig{
		Found:                true,
		PermitRootLogin:      "no",
		PasswordAuth:         "no",
		PermitEmptyPasswords: "yes",
		MaxAuthTries:         3,
	})

	findings := NewSSHDRule().Evaluate(snap)
	assertFinding(t, findings, "sshd-empty-passwords", model.SeverityCritical)
}

func TestSSHDRule_HighMaxAuthTries(t *testing.T) {
	snap := sshdSnap(model.SSHDConfig{
		Found:           true,
		PermitRootLogin: "no",
		PasswordAuth:    "no",
		MaxAuthTries:    6,
	})

	findings := NewSSHDRule().Evaluate(snap)
	assertFinding(t, findings, "sshd-max-auth-tries", model.SeverityWarning)
}

func TestSSHDRule_NonStandardPort_Bonus(t *testing.T) {
	snap := sshdSnap(model.SSHDConfig{
		Found:           true,
		PermitRootLogin: "no",
		PasswordAuth:    "no",
		MaxAuthTries:    3,
		Port:            2222,
	})

	findings := NewSSHDRule().Evaluate(snap)
	f := findByID(findings, "sshd-nonstandard-port")
	if f == nil {
		t.Fatal("expected sshd-nonstandard-port finding")
	}
	if f.Penalty >= 0 {
		t.Errorf("expected bonus (negative penalty), got %d", f.Penalty)
	}
}

func TestSSHDRule_NotFound_NoFindings(t *testing.T) {
	snap := sshdSnap(model.SSHDConfig{Found: false})
	findings := NewSSHDRule().Evaluate(snap)
	if len(findings) != 0 {
		t.Errorf("expected no findings when sshd not found, got %d", len(findings))
	}
}

