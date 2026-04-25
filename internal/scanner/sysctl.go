package scanner

import (
	"os/exec"
	"strings"

	"secscore/internal/model"
)

type SysctlScanner struct{}

func NewSysctlScanner() *SysctlScanner { return &SysctlScanner{} }

func (s *SysctlScanner) Name() string { return "sysctl" }

var sysctlWatchlist = []string{
	"net.ipv4.ip_forward",
	"net.ipv6.conf.all.forwarding",
	"kernel.dmesg_restrict",
	"kernel.kptr_restrict",
	"fs.suid_dumpable",
	"net.ipv4.conf.all.accept_redirects",
	"net.ipv6.conf.all.accept_redirects",
	"net.ipv4.conf.all.send_redirects",
	"net.ipv4.conf.all.rp_filter",
	"net.ipv4.tcp_syncookies",
	"kernel.randomize_va_space",
}

func (s *SysctlScanner) Scan(snapshot *model.Snapshot) error {
	sv := model.SysctlValues{Params: make(map[string]string)}

	if _, err := exec.LookPath("sysctl"); err != nil {
		snapshot.Sysctl = sv
		return nil
	}

	// try bulk first
	args := append([]string{"-n"}, sysctlWatchlist...)
	out, err := exec.Command("sysctl", args...).Output()
	if err == nil {
		sv.Available = true
		lines := strings.Split(strings.TrimSpace(string(out)), "\n")
		for i, val := range lines {
			if i < len(sysctlWatchlist) {
				sv.Params[sysctlWatchlist[i]] = strings.TrimSpace(val)
			}
		}
		snapshot.Sysctl = sv
		return nil
	}

	// fallback: one by one
	for _, key := range sysctlWatchlist {
		res, err := exec.Command("sysctl", "-n", key).Output()
		if err == nil {
			sv.Params[key] = strings.TrimSpace(string(res))
			sv.Available = true
		}
	}
	snapshot.Sysctl = sv
	return nil
}
