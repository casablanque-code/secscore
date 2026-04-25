package scanner

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"secscore/internal/model"
)

type UFWScanner struct{}

func NewUFWScanner() *UFWScanner {
	return &UFWScanner{}
}

func (s *UFWScanner) Name() string {
	return "ufw"
}

func (s *UFWScanner) Scan(snapshot *model.Snapshot) error {
	if _, err := exec.LookPath("ufw"); err != nil {
		snapshot.UFWStatus = model.UFWUnknown
		return nil
	}

	// ufw status numbered gives us both status and rules
	cmd := exec.Command("ufw", "status", "numbered")
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		snapshot.UFWStatus = model.UFWUnknown
		return fmt.Errorf("ufw scanner: %w", err)
	}

	snapshot.UFWStatus, snapshot.UFWRules = parseUFWOutput(out.String())
	return nil
}

// Example lines from `ufw status numbered`:
//
//	Status: active
//	     To                         Action      From
//	     --                         ------      ----
//	[ 1] 22/tcp                     ALLOW IN    Anywhere
//	[ 2] 80/tcp                     ALLOW IN    Anywhere
//	[ 3] 443                        ALLOW IN    Anywhere
//	[ 4] 9000/tcp                   DENY IN     Anywhere
var ufwRuleRe = regexp.MustCompile(
	`^\[\s*(\d+)\]\s+(\S+)\s+(ALLOW|DENY|LIMIT|REJECT)\s+(?:IN\s+|OUT\s+)?(.+)$`,
)

func parseUFWOutput(raw string) (model.UFWStatus, []model.UFWRule) {
	status := model.UFWUnknown
	var rules []model.UFWRule

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "Status:") {
			val := strings.TrimSpace(strings.TrimPrefix(line, "Status:"))
			switch strings.ToLower(val) {
			case "active":
				status = model.UFWActive
			case "inactive":
				status = model.UFWInactive
			}
			continue
		}

		m := ufwRuleRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}

		num, _ := strconv.Atoi(m[1])
		toField := strings.TrimSpace(m[2])   // e.g. "22/tcp", "443", "Anywhere"
		action := strings.TrimSpace(m[3])
		from := strings.TrimSpace(m[4])

		port, proto := parseUFWToField(toField)

		rules = append(rules, model.UFWRule{
			Number: num,
			Port:   port,
			Proto:  proto,
			Action: action,
			From:   from,
			To:     toField,
			Raw:    line,
		})
	}

	return status, rules
}

// parseUFWToField parses "22/tcp", "443", "8080/udp", "Anywhere" etc.
func parseUFWToField(s string) (port int, proto string) {
	proto = "any"
	if parts := strings.SplitN(s, "/", 2); len(parts) == 2 {
		proto = parts[1]
		port, _ = strconv.Atoi(parts[0])
	} else {
		port, _ = strconv.Atoi(s)
	}
	return
}

// AllowedFromAnywhere returns true if any ALLOW rule permits access to this port from anywhere.
func UFWAllowsPort(rules []model.UFWRule, port int, proto string) bool {
	for _, r := range rules {
		if r.Action != "ALLOW" {
			continue
		}
		// port 0 in rule = "any port"
		if r.Port != 0 && r.Port != port {
			continue
		}
		if r.Proto != "any" && r.Proto != proto {
			continue
		}
		from := strings.ToLower(r.From)
		if strings.Contains(from, "anywhere") || r.From == "0.0.0.0/0" || r.From == "::/0" {
			return true
		}
	}
	return false
}
