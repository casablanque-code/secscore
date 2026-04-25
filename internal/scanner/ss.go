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

type SSScanner struct{}

func NewSSScanner() *SSScanner {
	return &SSScanner{}
}

func (s *SSScanner) Name() string {
	return "ss"
}

func (s *SSScanner) Scan(snapshot *model.Snapshot) error {
	if _, err := exec.LookPath("ss"); err != nil {
		return nil
	}

	// -p requires root; if not root, still run without it — we get ports at least
	args := []string{"-tuln"}
	if snapshot.IsRoot {
		args = []string{"-tulnp"}
	}

	cmd := exec.Command("ss", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ss scanner: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	lines := strings.Split(stdout.String(), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Netid") {
			continue
		}

		listener, ok := parseSSLine(line)
		if ok {
			snapshot.HostListeners = append(snapshot.HostListeners, listener)
		}
	}

	return nil
}

// portSuffixRe matches the port at the end of an address like 0.0.0.0:22 or [::]:443
var portSuffixRe = regexp.MustCompile(`[:\[].*:(\d+)$|^(\d+)$`)

// processRe matches the users:(("sshd",pid=1234,fd=3)) part
var processRe = regexp.MustCompile(`users:\(\("([^"]+)",pid=(\d+)`)

func parseSSLine(line string) (model.HostListener, bool) {
	fields := strings.Fields(line)
	// ss -tuln:  Netid State Recv-Q Send-Q Local-Addr Peer-Addr
	// ss -tulnp: same + Process column at end
	if len(fields) < 5 {
		return model.HostListener{}, false
	}

	proto := fields[0]
	localAddr := fields[4]

	port, ok := extractPort(localAddr)
	if !ok {
		return model.HostListener{}, false
	}

	listener := model.HostListener{
		Proto:   proto,
		Address: localAddr,
		Port:    port,
		Raw:     line,
	}

	// parse process info if present (requires root / -p flag)
	for _, f := range fields[5:] {
		if m := processRe.FindStringSubmatch(f); m != nil {
			listener.Process = m[1]
			listener.PID, _ = strconv.Atoi(m[2])
			break
		}
	}

	return listener, true
}

func extractPort(addr string) (int, bool) {
	// handle [::1]:80, 0.0.0.0:22, *:443
	idx := strings.LastIndex(addr, ":")
	if idx == -1 {
		return 0, false
	}
	p, err := strconv.Atoi(addr[idx+1:])
	if err != nil {
		return 0, false
	}
	return p, true
}
