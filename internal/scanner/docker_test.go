package scanner

import (
	"testing"
)

func TestParseDockerPorts_PublicBinding(t *testing.T) {
	services := parseDockerPorts("abc123", "portainer/portainer-ce", "portainer", "0.0.0.0:9000->9000/tcp")

	if len(services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services))
	}
	s := services[0]
	if s.Port != 9000 {
		t.Errorf("host port: got %d want 9000", s.Port)
	}
	if s.HostIP != "0.0.0.0" {
		t.Errorf("hostIP: got %q want 0.0.0.0", s.HostIP)
	}
	if s.ContainerPort != 9000 {
		t.Errorf("containerPort: got %d want 9000", s.ContainerPort)
	}
	if s.Protocol != "tcp" {
		t.Errorf("protocol: got %q want tcp", s.Protocol)
	}
}

func TestParseDockerPorts_LoopbackBinding(t *testing.T) {
	services := parseDockerPorts("abc123", "grafana/grafana", "grafana", "127.0.0.1:3000->3000/tcp")

	if len(services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services))
	}
	if services[0].HostIP != "127.0.0.1" {
		t.Errorf("hostIP: got %q want 127.0.0.1", services[0].HostIP)
	}
}

func TestParseDockerPorts_MultiPort(t *testing.T) {
	portsField := "0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp"
	services := parseDockerPorts("abc123", "nginx", "nginx", portsField)

	if len(services) != 2 {
		t.Fatalf("expected 2 services, got %d", len(services))
	}
}

func TestParseDockerPorts_UDP(t *testing.T) {
	services := parseDockerPorts("abc123", "some/dns", "dns", "0.0.0.0:53->53/udp")

	if len(services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services))
	}
	if services[0].Protocol != "udp" {
		t.Errorf("protocol: got %q want udp", services[0].Protocol)
	}
}

func TestParseDockerPorts_NoPortMapping(t *testing.T) {
	services := parseDockerPorts("abc123", "redis", "redis", "")
	if len(services) != 0 {
		t.Errorf("expected 0 services for empty ports, got %d", len(services))
	}
}

func TestParseDockerPorts_IPv6Binding(t *testing.T) {
	services := parseDockerPorts("abc123", "nginx", "nginx", ":::8080->8080/tcp")
	if len(services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(services))
	}
	if services[0].HostIP != "::" {
		t.Errorf("hostIP: got %q want ::", services[0].HostIP)
	}
}

func TestNormalizeDockerHostIP(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"", "0.0.0.0"},
		{"::", "::"},
		{"0.0.0.0", "0.0.0.0"},
		{"127.0.0.1", "127.0.0.1"},
	}
	for _, c := range cases {
		got := normalizeDockerHostIP(c.input)
		if got != c.want {
			t.Errorf("normalizeDockerHostIP(%q): got %q want %q", c.input, got, c.want)
		}
	}
}
