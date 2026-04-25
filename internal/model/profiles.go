package model

type ServiceProfile struct {
	Match       string `yaml:"match"`
	Type        string `yaml:"type"`
	HTTP        bool   `yaml:"http"`
	BehindProxy bool   `yaml:"behind_proxy"`
}

type Profiles struct {
	Services      []ServiceProfile `yaml:"services"`
	ProxyNames    []string         `yaml:"proxy_names"`
	IgnoreSysctl  []string         `yaml:"ignore_sysctl"`
}
