package model

import "strings"

func DetectServiceType(name, image string, port int) ServiceType {
	s := strings.ToLower(name + " " + image)
	if LoadedProfiles != nil {
		for _, p := range LoadedProfiles.Services {
			if strings.Contains(s, strings.ToLower(p.Match)) {
				switch p.Type {
				case "admin":
					return ServiceTypeAdmin
				case "infra":
					return ServiceTypeInfra
				default:
					return ServiceTypeApp
				}
			}
		}
	}
	return ServiceTypeApp
}

func IsBehindProxy(name, image string) bool {
	if LoadedProfiles == nil {
		return false
	}
	s := strings.ToLower(name + " " + image)
	for _, p := range LoadedProfiles.Services {
		if strings.Contains(s, strings.ToLower(p.Match)) {
			return p.BehindProxy
		}
	}
	return false
}

// IsProxyContainer matches only against container NAME, not image.
// This prevents false positives like zabbix-web-nginx matching "nginx".
func IsProxyContainer(name, image string) bool {
	if LoadedProfiles == nil {
		return false
	}
	n := strings.ToLower(name)
	for _, px := range LoadedProfiles.ProxyNames {
		px = strings.ToLower(px)
		// require the proxy name to be a whole word in the container name
		if n == px || strings.HasPrefix(n, px+"-") || strings.HasSuffix(n, "-"+px) ||
			strings.Contains(n, "-"+px+"-") || strings.HasPrefix(n, px+"_") ||
			strings.Contains(n, "_"+px+"_") || strings.HasSuffix(n, "_"+px) {
			return true
		}
	}
	return false
}

func SysctlIgnored(key string) bool {
	if LoadedProfiles == nil {
		return false
	}
	for _, k := range LoadedProfiles.IgnoreSysctl {
		if k == key {
			return true
		}
	}
	return false
}
