package model

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityWarning  Severity = "WARNING"
	SeverityInfo     Severity = "INFO"
)

type Evidence struct {
	Source  string
	Details string
}

type Finding struct {
	ID             string
	Severity       Severity
	Title          string
	Description    string
	Recommendation string
	Penalty        int
	Evidence       []Evidence
	Fix            *Fix // nil if no automated fix is available
}

type ServiceType string

const (
	ServiceTypeUnknown ServiceType = "unknown"
	ServiceTypeAdmin   ServiceType = "admin"
	ServiceTypeApp     ServiceType = "app"
	ServiceTypeInfra   ServiceType = "infra"
)

type Service struct {
	Name          string
	ContainerID   string
	Image         string
	Port          int
	HostIP        string
	ContainerPort int
	Protocol      string
	Type          ServiceType
	Source        string
	HTTP          bool
}

type HostListener struct {
	Proto   string
	Address string
	Port    int
	Process string
	PID     int
	Raw     string
}

// --- UFW ---

type UFWStatus string

const (
	UFWActive   UFWStatus = "active"
	UFWInactive UFWStatus = "inactive"
	UFWUnknown  UFWStatus = "unknown"
)

type UFWRule struct {
	Number int
	Port   int    // 0 = any / not parsed
	Proto  string // tcp / udp / any
	Action string // ALLOW / DENY / LIMIT / REJECT
	From   string
	To     string
	Raw    string
}

// --- SSHD ---

type SSHDConfig struct {
	Found                bool
	Port                 int
	PermitRootLogin      string
	PasswordAuth         string
	PubkeyAuthentication string
	PermitEmptyPasswords string
	Protocol             string
	MaxAuthTries         int
	Raw                  map[string]string
}

// --- Sysctl ---

type SysctlValues struct {
	Available bool
	Params    map[string]string
}

// --- Sudo ---

type SudoEntry struct {
	User    string
	Command string
	Source  string
	Raw     string
}

// --- Snapshot ---

type Snapshot struct {
	Services      []Service
	HostListeners []HostListener

	UFWStatus UFWStatus
	UFWRules  []UFWRule

	SSHD    SSHDConfig
	Sysctl  SysctlValues
	Sudoers []SudoEntry

	IsRoot         bool
	WorldWritable  []WorldWritableFile
}

type Report struct {
	Score    int
	Findings []Finding
}

func (r Report) HasCritical() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityCritical {
			return true
		}
	}
	return false
}

func (r Report) HasWarning() bool {
	for _, f := range r.Findings {
		if f.Severity == SeverityWarning {
			return true
		}
	}
	return false
}

// WorldWritableFile is a file or directory with o+w permissions in a sensitive path.
type WorldWritableFile struct {
	Path  string
	Mode  uint32 // os.FileMode as uint32 to avoid import
	IsDir bool
}
