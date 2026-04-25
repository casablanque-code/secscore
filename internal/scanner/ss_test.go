package scanner

import (
	"testing"
)

func TestParseSSLine_Basic(t *testing.T) {
	cases := []struct {
		line        string
		wantPort    int
		wantProto   string
		wantOK      bool
	}{
		// ss -tuln output
		{
			"tcp   LISTEN 0  128  0.0.0.0:22   0.0.0.0:*",
			22, "tcp", true,
		},
		{
			"tcp   LISTEN 0  128  0.0.0.0:7777  0.0.0.0:*",
			7777, "tcp", true,
		},
		{
			"udp   UNCONN 0  0    0.0.0.0:5353  0.0.0.0:*",
			5353, "udp", true,
		},
		{
			"tcp   LISTEN 0  128  [::]:443      [::]:*",
			443, "tcp", true,
		},
		{
			"tcp   LISTEN 0  128  127.0.0.1:9000  0.0.0.0:*",
			9000, "tcp", true,
		},
		// header line — should not parse
		{
			"Netid State  Recv-Q Send-Q Local Address:Port",
			0, "", false,
		},
		// too few fields
		{
			"tcp LISTEN",
			0, "", false,
		},
	}

	for _, c := range cases {
		l, ok := parseSSLine(c.line)
		if ok != c.wantOK {
			t.Errorf("parseSSLine(%q): ok=%v want %v", c.line, ok, c.wantOK)
			continue
		}
		if !c.wantOK {
			continue
		}
		if l.Port != c.wantPort {
			t.Errorf("parseSSLine(%q): port=%d want %d", c.line, l.Port, c.wantPort)
		}
		if l.Proto != c.wantProto {
			t.Errorf("parseSSLine(%q): proto=%q want %q", c.line, l.Proto, c.wantProto)
		}
	}
}

func TestParseSSLine_WithProcess(t *testing.T) {
	// ss -tulnp output (root)
	line := `tcp   LISTEN 0  128  0.0.0.0:22  0.0.0.0:*  users:(("sshd",pid=1234,fd=3))`

	l, ok := parseSSLine(line)
	if !ok {
		t.Fatal("expected successful parse")
	}
	if l.Port != 22 {
		t.Errorf("port: got %d want 22", l.Port)
	}
	if l.Process != "sshd" {
		t.Errorf("process: got %q want sshd", l.Process)
	}
	if l.PID != 1234 {
		t.Errorf("pid: got %d want 1234", l.PID)
	}
}

func TestExtractPort(t *testing.T) {
	cases := []struct {
		addr     string
		wantPort int
		wantOK   bool
	}{
		{"0.0.0.0:22", 22, true},
		{"127.0.0.1:9000", 9000, true},
		{"[::]:443", 443, true},
		{"[::1]:8080", 8080, true},
		{"*:7777", 7777, true},
		{"noport", 0, false},
		{"", 0, false},
	}

	for _, c := range cases {
		port, ok := extractPort(c.addr)
		if ok != c.wantOK || port != c.wantPort {
			t.Errorf("extractPort(%q): got (%d,%v) want (%d,%v)",
				c.addr, port, ok, c.wantPort, c.wantOK)
		}
	}
}
