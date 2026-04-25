package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempSSHDConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseSSHDConfig_Hardened(t *testing.T) {
	content := `
Port 2222
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
`
	path := writeTempSSHDConfig(t, content)

	// Temporarily override search paths by calling the internal parser directly.
	// We test via a helper that accepts a path.
	cfg := parseSSHDConfigFromPath(path)

	if !cfg.Found {
		t.Fatal("expected Found=true")
	}
	if cfg.Port != 2222 {
		t.Errorf("Port: got %d want 2222", cfg.Port)
	}
	if cfg.PermitRootLogin != "no" {
		t.Errorf("PermitRootLogin: got %q want no", cfg.PermitRootLogin)
	}
	if cfg.PasswordAuth != "no" {
		t.Errorf("PasswordAuth: got %q want no", cfg.PasswordAuth)
	}
	if cfg.MaxAuthTries != 3 {
		t.Errorf("MaxAuthTries: got %d want 3", cfg.MaxAuthTries)
	}
}

func TestParseSSHDConfig_InsecureDefaults(t *testing.T) {
	content := `
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
MaxAuthTries 6
`
	path := writeTempSSHDConfig(t, content)
	cfg := parseSSHDConfigFromPath(path)

	if cfg.PermitRootLogin != "yes" {
		t.Errorf("PermitRootLogin: got %q want yes", cfg.PermitRootLogin)
	}
	if cfg.PermitEmptyPasswords != "yes" {
		t.Errorf("PermitEmptyPasswords: got %q want yes", cfg.PermitEmptyPasswords)
	}
	if cfg.MaxAuthTries != 6 {
		t.Errorf("MaxAuthTries: got %d want 6", cfg.MaxAuthTries)
	}
}

func TestParseSSHDConfig_CommentsIgnored(t *testing.T) {
	content := `
# This is a comment
#PermitRootLogin yes
PermitRootLogin no
# PasswordAuthentication yes
PasswordAuthentication no
`
	path := writeTempSSHDConfig(t, content)
	cfg := parseSSHDConfigFromPath(path)

	if cfg.PermitRootLogin != "no" {
		t.Errorf("commented-out directive should not override: got %q", cfg.PermitRootLogin)
	}
	if cfg.PasswordAuth != "no" {
		t.Errorf("commented-out directive should not override: got %q", cfg.PasswordAuth)
	}
}

func TestParseSSHDConfig_MissingFile(t *testing.T) {
	cfg := parseSSHDConfigFromPath("/nonexistent/path/sshd_config")
	if cfg.Found {
		t.Error("expected Found=false for missing file")
	}
	// Defaults should be populated (openssh defaults = insecure for our purposes)
	if cfg.PermitRootLogin != "yes" {
		t.Errorf("default PermitRootLogin should be yes, got %q", cfg.PermitRootLogin)
	}
}
