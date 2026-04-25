package scanner

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/casablanque-code/secscore/internal/model"
)

type DockerScanner struct{}

func NewDockerScanner() *DockerScanner {
	return &DockerScanner{}
}

func (s *DockerScanner) Name() string {
	return "docker"
}

func (s *DockerScanner) Scan(snapshot *model.Snapshot) error {
	if _, err := exec.LookPath("docker"); err != nil {
		return nil
	}

	cmd := exec.Command("docker", "ps", "--format", "{{.ID}}|{{.Image}}|{{.Names}}|{{.Ports}}")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker scanner failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}

	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, "|", 4)
		if len(parts) != 4 {
			continue
		}

		containerID := parts[0]
		image := parts[1]
		name := parts[2]
		portsField := parts[3]

		services := parseDockerPorts(containerID, image, name, portsField)
		snapshot.Services = append(snapshot.Services, services...)
	}

	return nil
}

var dockerPortRe = regexp.MustCompile(`(?:(?P<hostip>[\d\.:]+):)?(?P<hostport>\d+)->(?P<containerport>\d+)/(tcp|udp)`)

func parseDockerPorts(containerID, image, name, portsField string) []model.Service {
	var out []model.Service

	if strings.TrimSpace(portsField) == "" {
		return out
	}

	chunks := strings.Split(portsField, ",")
	for _, chunk := range chunks {
		chunk = strings.TrimSpace(chunk)
		if chunk == "" || !strings.Contains(chunk, "->") {
			continue
		}

		matches := dockerPortRe.FindStringSubmatch(chunk)
		if matches == nil {
			continue
		}

		hostIP := ""
		hostPort := 0
		containerPort := 0
		proto := "tcp"

		for i, namePart := range dockerPortRe.SubexpNames() {
			if i == 0 || namePart == "" {
				continue
			}
			switch namePart {
			case "hostip":
				hostIP = matches[i]
			case "hostport":
				hostPort, _ = strconv.Atoi(matches[i])
			case "containerport":
				containerPort, _ = strconv.Atoi(matches[i])
			}
		}

		if strings.Contains(chunk, "/udp") {
			proto = "udp"
		}

		service := model.Service{
			Name:          name,
			ContainerID:   containerID,
			Image:         image,
			Port:          hostPort,
			HostIP:        normalizeDockerHostIP(hostIP),
			ContainerPort: containerPort,
			Protocol:      proto,
			Type:          model.DetectServiceType(name, image, containerPort),
			Source:        "docker",
			HTTP: detectHTTP(name, image),
		}

		out = append(out, service)
	}

	return out
}

func detectHTTP(name, image string) bool {
	s := strings.ToLower(name + " " + image)

	if model.LoadedProfiles != nil {
		for _, p := range model.LoadedProfiles.Services {
			if strings.Contains(s, p.Match) {
				return p.HTTP
			}
		}
	}

	return false
}

func normalizeDockerHostIP(ip string) string {
	ip = strings.TrimSpace(ip)
	switch ip {
	case "":
		return "0.0.0.0"
	case "::":
		return "::"
	default:
		return ip
	}
}
