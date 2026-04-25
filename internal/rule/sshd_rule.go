package rule

import (
	"fmt"

	"github.com/casablanque-code/secscore/internal/model"
)

const sshdConfig = "/etc/ssh/sshd_config"

var reloadSSHD = model.Action{
	Kind: model.ActionCommand,
	Cmd:  []string{"systemctl", "reload", "sshd"},
}

type SSHDRule struct{}

func NewSSHDRule() *SSHDRule    { return &SSHDRule{} }
func (r *SSHDRule) Name() string { return "sshd" }

func (r *SSHDRule) Evaluate(snapshot model.Snapshot) []model.Finding {
	cfg := snapshot.SSHD
	if !cfg.Found {
		return nil
	}

	var findings []model.Finding

	// ── PermitRootLogin ──────────────────────────────────────────────────────
	switch cfg.PermitRootLogin {
	case "yes":
		findings = append(findings, model.Finding{
			ID:             "sshd-root-login",
			Severity:       model.SeverityCritical,
			Title:          "SSH: PermitRootLogin yes",
			Description:    "Direct root login over SSH. A compromised credential gives immediate full access.",
			Recommendation: "Set PermitRootLogin no in /etc/ssh/sshd_config, then: systemctl reload sshd",
			Penalty:        20,
			Fix: &model.Fix{
				Description: "Set PermitRootLogin no in sshd_config and reload sshd",
				Actions: []model.Action{
					{
						Kind:    model.ActionFileEdit,
						File:    sshdConfig,
						Search:  "permitrootlogin",
						Replace: "PermitRootLogin no",
						Append:  "PermitRootLogin no",
					},
					reloadSSHD,
				},
			},
		})
	case "prohibit-password", "without-password":
		findings = append(findings, model.Finding{
			ID:             "sshd-root-login-pubkey",
			Severity:       model.SeverityWarning,
			Title:          "SSH: root login allowed (pubkey only)",
			Description:    "Root login is restricted to pubkey auth. Lower risk, but still not ideal.",
			Recommendation: "Set PermitRootLogin no and use a non-root user with sudo.",
			Penalty:        8,
			Fix: &model.Fix{
				Description: "Set PermitRootLogin no in sshd_config and reload sshd",
				Actions: []model.Action{
					{
						Kind:    model.ActionFileEdit,
						File:    sshdConfig,
						Search:  "permitrootlogin",
						Replace: "PermitRootLogin no",
						Append:  "PermitRootLogin no",
					},
					reloadSSHD,
				},
			},
		})
	case "no", "forced-commands-only":
		findings = append(findings, model.Finding{
			ID:             "sshd-root-login-disabled",
			Severity:       model.SeverityInfo,
			Title:          "SSH: root login disabled",
			Description:    "PermitRootLogin is set to no.",
			Recommendation: "No action needed.",
			Penalty:        -8,
		})
	}

	// ── PasswordAuthentication ───────────────────────────────────────────────
	if cfg.PasswordAuth == "yes" {
		findings = append(findings, model.Finding{
			ID:             "sshd-password-auth",
			Severity:       model.SeverityWarning,
			Title:          "SSH: password authentication enabled",
			Description:    "Password auth exposes SSH to brute-force. Key-based auth is significantly more secure.",
			Recommendation: "Set PasswordAuthentication no (ensure you have a working key first).",
			Penalty:        10,
			Fix: &model.Fix{
				Description: "Set PasswordAuthentication no and reload sshd",
				Actions: []model.Action{
					{
						Kind:    model.ActionFileEdit,
						File:    sshdConfig,
						Search:  "passwordauthentication",
						Replace: "PasswordAuthentication no",
						Append:  "PasswordAuthentication no",
					},
					reloadSSHD,
				},
			},
		})
	} else {
		findings = append(findings, model.Finding{
			ID:             "sshd-password-auth-disabled",
			Severity:       model.SeverityInfo,
			Title:          "SSH: password authentication disabled",
			Description:    "Only key-based authentication is accepted.",
			Recommendation: "No action needed.",
			Penalty:        -8,
		})
	}

	// ── PermitEmptyPasswords ─────────────────────────────────────────────────
	if cfg.PermitEmptyPasswords == "yes" {
		findings = append(findings, model.Finding{
			ID:             "sshd-empty-passwords",
			Severity:       model.SeverityCritical,
			Title:          "SSH: empty passwords permitted",
			Description:    "Accounts with no password can be accessed over SSH without any credentials.",
			Recommendation: "Set PermitEmptyPasswords no immediately.",
			Penalty:        30,
			Fix: &model.Fix{
				Description: "Set PermitEmptyPasswords no and reload sshd",
				Actions: []model.Action{
					{
						Kind:    model.ActionFileEdit,
						File:    sshdConfig,
						Search:  "permitemptypasswords",
						Replace: "PermitEmptyPasswords no",
						Append:  "PermitEmptyPasswords no",
					},
					reloadSSHD,
				},
			},
		})
	}

	// ── MaxAuthTries ─────────────────────────────────────────────────────────
	if cfg.MaxAuthTries > 3 {
		findings = append(findings, model.Finding{
			ID:       "sshd-max-auth-tries",
			Severity: model.SeverityWarning,
			Title:    fmt.Sprintf("SSH: MaxAuthTries %d (recommended ≤3)", cfg.MaxAuthTries),
			Description: "More attempts per connection give attackers more guesses before disconnect.",
			Recommendation: "Set MaxAuthTries 3 in sshd_config.",
			Penalty: 5,
			Fix: &model.Fix{
				Description: "Set MaxAuthTries 3 and reload sshd",
				Actions: []model.Action{
					{
						Kind:    model.ActionFileEdit,
						File:    sshdConfig,
						Search:  "maxauthtries",
						Replace: "MaxAuthTries 3",
						Append:  "MaxAuthTries 3",
					},
					reloadSSHD,
				},
			},
		})
	}

	// ── Non-standard port ────────────────────────────────────────────────────
	if cfg.Port != 22 {
		findings = append(findings, model.Finding{
			ID:             "sshd-nonstandard-port",
			Severity:       model.SeverityInfo,
			Title:          fmt.Sprintf("SSH: running on non-standard port %d", cfg.Port),
			Description:    "Reduces automated scanner noise. Not a security control by itself.",
			Recommendation: "No action needed.",
			Penalty:        -3,
		})
	}

	return findings
}
