package scanner

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"secscore/internal/model"
)

type SSHDScanner struct{}

func NewSSHDScanner() *SSHDScanner  { return &SSHDScanner{} }
func (s *SSHDScanner) Name() string { return "sshd" }

func (s *SSHDScanner) Scan(snapshot *model.Snapshot) error {
	snapshot.SSHD = parseSSHDConfig()
	return nil
}

func parseSSHDConfig() model.SSHDConfig {
	paths := []string{"/etc/ssh/sshd_config", "/etc/sshd_config"}
	for _, p := range paths {
		if cfg := parseSSHDConfigFromPath(p); cfg.Found {
			return cfg
		}
	}
	return defaultSSHDConfig()
}

// parseSSHDConfigFromPath is exported for testing.
func parseSSHDConfigFromPath(path string) model.SSHDConfig {
	cfg := defaultSSHDConfig()

	f, err := os.Open(path)
	if err != nil {
		return cfg
	}
	defer f.Close()
	cfg.Found = true

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		key := strings.ToLower(parts[0])
		val := strings.ToLower(strings.Join(parts[1:], " "))
		cfg.Raw[key] = val

		switch key {
		case "port":
			if p, err := strconv.Atoi(val); err == nil && p > 0 {
				cfg.Port = p
			}
		case "permitrootlogin":
			cfg.PermitRootLogin = val
		case "passwordauthentication":
			cfg.PasswordAuth = val
		case "pubkeyauthentication":
			cfg.PubkeyAuthentication = val
		case "permitemptypasswords":
			cfg.PermitEmptyPasswords = val
		case "protocol":
			cfg.Protocol = val
		case "maxauthtries":
			if n, err := strconv.Atoi(val); err == nil && n > 0 {
				cfg.MaxAuthTries = n
			}
		}
	}
	return cfg
}

func defaultSSHDConfig() model.SSHDConfig {
	return model.SSHDConfig{
		Raw:                  make(map[string]string),
		Port:                 22,
		PermitRootLogin:      "yes",
		PasswordAuth:         "yes",
		PubkeyAuthentication: "yes",
		PermitEmptyPasswords: "no",
		Protocol:             "2",
		MaxAuthTries:         6,
	}
}
