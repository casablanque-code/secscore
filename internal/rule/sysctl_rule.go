package rule

import (
	"fmt"

	"github.com/casablanque-code/secscore/internal/model"
)

type SysctlRule struct{}

func NewSysctlRule() *SysctlRule  { return &SysctlRule{} }
func (r *SysctlRule) Name() string { return "sysctl" }

type sysctlCheck struct {
	key      string
	badVal   string
	severity model.Severity
	title    string
	desc     string
	fix      string
	penalty  int
}

var sysctlChecks = []sysctlCheck{
	{
		key: "net.ipv4.ip_forward", badVal: "1",
		severity: model.SeverityWarning,
		title:    "IP forwarding enabled (net.ipv4.ip_forward=1)",
		desc:     "Host forwards packets — unexpected on a non-router/non-VPN server.",
		fix:      "sysctl -w net.ipv4.ip_forward=0  (or add to ignore_sysctl in profiles.yaml if this is a VPN/WSL host)",
		penalty:  10,
	},
	{
		key: "kernel.dmesg_restrict", badVal: "0",
		severity: model.SeverityWarning,
		title:    "dmesg unrestricted (kernel.dmesg_restrict=0)",
		desc:     "Any local user can read kernel ring buffer — may leak sensitive addresses.",
		fix:      "sysctl -w kernel.dmesg_restrict=1",
		penalty:  5,
	},
	{
		key: "kernel.kptr_restrict", badVal: "0",
		severity: model.SeverityWarning,
		title:    "Kernel pointer exposure (kernel.kptr_restrict=0)",
		desc:     "Kernel symbol addresses visible to unprivileged users.",
		fix:      "sysctl -w kernel.kptr_restrict=2",
		penalty:  5,
	},
	{
		key: "fs.suid_dumpable", badVal: "2",
		severity: model.SeverityWarning,
		title:    "Core dumps for setuid programs (fs.suid_dumpable=2)",
		desc:     "setuid programs can dump core, potentially leaking sensitive data.",
		fix:      "sysctl -w fs.suid_dumpable=0",
		penalty:  5,
	},
	{
		key: "net.ipv4.conf.all.accept_redirects", badVal: "1",
		severity: model.SeverityWarning,
		title:    "ICMP redirects accepted",
		desc:     "Host accepts ICMP redirects — can be used for MITM attacks.",
		fix:      "sysctl -w net.ipv4.conf.all.accept_redirects=0",
		penalty:  5,
	},
	{
		key: "net.ipv4.tcp_syncookies", badVal: "0",
		severity: model.SeverityWarning,
		title:    "SYN cookies disabled",
		desc:     "Host is vulnerable to SYN flood attacks.",
		fix:      "sysctl -w net.ipv4.tcp_syncookies=1",
		penalty:  10,
	},
	{
		key: "kernel.randomize_va_space", badVal: "0",
		severity: model.SeverityCritical,
		title:    "ASLR disabled (kernel.randomize_va_space=0)",
		desc:     "Address Space Layout Randomization is off — memory exploitation is significantly easier.",
		fix:      "sysctl -w kernel.randomize_va_space=2",
		penalty:  20,
	},
}

func (r *SysctlRule) Evaluate(snapshot model.Snapshot) []model.Finding {
	sv := snapshot.Sysctl
	if !sv.Available {
		return nil
	}

	var findings []model.Finding
	for _, chk := range sysctlChecks {
		if model.SysctlIgnored(chk.key) {
			continue
		}
		val, ok := sv.Params[chk.key]
		if !ok || val != chk.badVal {
			continue
		}
		findings = append(findings, model.Finding{
			ID:             fmt.Sprintf("sysctl-%s", chk.key),
			Severity:       chk.severity,
			Title:          chk.title,
			Description:    chk.desc,
			Recommendation: chk.fix,
			Penalty:        chk.penalty,
		})
	}
	return findings
}
