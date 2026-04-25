# secscore

Local security analyzer for Linux servers. Scans the running system and produces a scored report of findings — no agents, no cloud, no external dependencies. Single binary, runs in seconds.

```
  Score   100/100  ████████████████████████████████████  Excellent
  ✖  0 critical   ▲  0 warning   ●  14 info
```

---

## How it works

secscore collects system state through **scanners**, then evaluates it through **rules** that produce findings with severity and penalty/bonus points. The final score reflects the overall security posture of the host.

Key design decision: rules check **intention**, not just state. If a port is open and you have an explicit `ufw allow` rule for it — that's intentional, no warning. If a port is open with no firewall rule at all — that's unknown intent, and worth flagging.

---

## What it checks

| Scanner | Source |
|---|---|
| `docker` | Running containers and host port bindings |
| `ss` | Host-level listeners via `ss -tulnp` |
| `ufw` | Firewall status and rules via `ufw status numbered` |
| `sshd` | `/etc/ssh/sshd_config` |
| `sysctl` | Kernel security parameters |
| `sudo` | `/etc/sudoers` and `/etc/sudoers.d/*` |
| `world-writable` | Files/dirs with `o+w` in sensitive paths |

### Rules

**Service exposure** — detects admin/infra containers bound to `0.0.0.0` instead of `127.0.0.1`. Aware of reverse proxies: if a service is marked `behind_proxy: true` in `profiles.yaml`, a public binding is downgraded from CRITICAL to WARNING. If a proxy container (tollgate, nginx, traefik) is running, findings mention it.

**UFW correlation** — correlates `ss` listeners with ufw rules:

| Port state | ufw rule | Result |
|---|---|---|
| Open | `ALLOW` or `LIMIT` | INFO — intentional |
| Open | `LIMIT` | INFO + bonus — good practice |
| Open | `DENY` but port is still open | CRITICAL — likely Docker iptables bypass |
| Open | No rule | WARNING — unknown intention |
| — | ufw inactive | CRITICAL |

**SSHD hardening** — checks `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, `MaxAuthTries`. Awards bonuses for hardened values.

**Sysctl hardening** — checks ASLR, SYN cookies, ICMP redirects, dmesg/kptr restrictions, IP forwarding.

**Sudo NOPASSWD** — flags `NOPASSWD: ALL` (CRITICAL) and scoped NOPASSWD entries (WARNING).

**HTTP auth probe** — attempts unauthenticated requests to exposed HTTP admin services, checks for 401/403 response.

**World-writable** — finds files/directories with `o+w` in `/etc`, `/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `/opt`. Skips symlinks (their `0777` mode is by design) and `/etc/alternatives/`. On WSL2, skips entirely — DrvFs reports all files as `0777` regardless of real permissions.

---

## Scoring

Starts at 100. Each finding carries a penalty (positive = bad, negative = bonus).

**Penalties:**

| Finding | Penalty |
|---|---|
| Admin service exposed, no proxy | −25 |
| ufw inactive | −25 |
| PermitRootLogin yes | −20 |
| ASLR disabled | −20 |
| ufw DENY but port is open (Docker bypass) | −20 |
| World-writable dir in sensitive path | −20 |
| PermitEmptyPasswords yes | −30 |
| NOPASSWD: ALL in sudoers | −25 |

**Bonuses:**

| Finding | Bonus |
|---|---|
| All open ports have explicit ufw rules | +10 |
| PermitRootLogin no | +8 |
| PasswordAuthentication no | +8 |
| ufw LIMIT on a port | +3 per port |
| SSH on non-standard port | +3 |
| Service bound to localhost | +2 per service |

Score is clamped to `[0, 100]`.

---

## Usage

```bash
# Full scan — run as root for complete results
sudo ./secscore

# JSON output (for scripting or CI)
sudo ./secscore --json

# Run a single scanner
sudo ./secscore --only sshd
sudo ./secscore --only ufw
sudo ./secscore --only world-writable

# Custom profiles path
./secscore --profiles /etc/secscore/profiles.yaml

# Version
./secscore --version
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No issues |
| `1` | Warnings present |
| `2` | Critical issues found |

```bash
# Use in CI/CD pipelines
sudo ./secscore --json > report.json
[ $? -lt 2 ] || { echo "Critical security issues — failing build"; exit 1; }
```

---

## Build

```bash
go build -o secscore ./cmd/secscore

# With version baked in
go build -ldflags "-X secscore/internal/version.Version=v0.3.0" -o secscore ./cmd/secscore
```

Requires Go 1.22+. One external dependency: `gopkg.in/yaml.v3` for profile loading.

---

## Configuration

`profiles.yaml` is loaded from the directory next to the binary, or via `--profiles`.

```yaml
services:
  # match   — substring in container name or image (case-insensitive)
  # type    — admin | infra | app
  # http    — true enables HTTP auth probing on this service
  # behind_proxy — true downgrades public binding from CRITICAL to WARNING

  - match: "portainer"
    type: "admin"
    http: true
    behind_proxy: true

  - match: "postgres"
    type: "infra"
    http: false

# Container names that are themselves reverse proxies.
# Matched against container NAME only (not image) to avoid false positives
# e.g. zabbix-web-nginx should not match "nginx".
proxy_names:
  - "tollgate"
  - "nginx"
  - "traefik"
  - "caddy"
  - "haproxy"

# Sysctl keys to skip entirely.
# Add here when a parameter is intentionally non-default.
ignore_sysctl:
  - "net.ipv4.ip_forward"          # expected on VPN gateways and WSL2
  - "net.ipv6.conf.all.forwarding"
```

---

## Architecture

```
cmd/secscore/        entry point, flag parsing, wiring
internal/
  model/             shared types: Snapshot, Finding, Report, profiles
  scanner/           data collectors — read system state, populate Snapshot
  rule/              evaluators — read Snapshot, return []Finding
  engine/            orchestrates: scan → evaluate → deduplicate → score
  printer/           ANSI terminal output, auto-detects color and width
  version/           build-time version string via ldflags
profiles.yaml        service classification, proxy names, sysctl ignore list
```

Scanners only read. Rules only evaluate. Neither writes to disk. The only network activity is the optional HTTP auth probe, directed at localhost services only.

---

## Running tests

```bash
go test ./...

# Verbose output
go test -v ./internal/...

# Single package
go test -v ./internal/scanner/
go test -v ./internal/rule/
go test -v ./internal/engine/
```

Test files (`*_test.go`) are not compiled into the binary.

---

## Known limitations

**WSL2** — `ufw limit` is not supported (missing `xt_recent` kernel module). Use `ufw allow` instead. World-writable scan is automatically skipped.

**Docker + ufw** — Docker manipulates iptables directly and bypasses ufw. If you have a container publishing to `0.0.0.0`, ufw rules won't block it. Fix: bind containers to `127.0.0.1` in `docker-compose.yml`:
```yaml
ports:
  - "127.0.0.1:9000:9000"
```
secscore detects this condition (DENY rule present but port still open) and flags it as CRITICAL.

**Root required** for: `ss -p` process names, `/etc/sudoers` read, full sysctl access. Without root, these scanners return partial results silently.

**HTTP auth probe** is a heuristic — checks for 401/403 on a few common paths. A service that returns 200 on `/` but requires auth on `/api` will be flagged incorrectly.
