# secscore

Local security analyzer for Linux servers. Scans the running system, scores it, and can automatically fix what it finds.

No agents. No cloud. No external dependencies. Single binary.

```
  Score   100/100  ████████████████████████████████████  Excellent
  ✖  0 critical   ▲  0 warning   ●  14 info
```

---

## Install

**From release (recommended):**
```bash
curl -L https://github.com/casablanque-code/secscore/releases/latest/download/secscore-linux-amd64 -o secscore
chmod +x secscore
sudo mv secscore /usr/local/bin/secscore
```

**From source:**
```bash
git clone https://github.com/casablanque-code/secscore
cd secscore
sudo make install       # builds and copies to /usr/local/bin
```

**Via go install:**
```bash
go install github.com/casablanque-code/secscore/cmd/secscore@latest
```

Requires Go 1.22+. Run as root for full results.

---

## Usage

```bash
# Full scan
sudo secscore

# Scan only one subsystem
sudo secscore --only sshd
sudo secscore --only ufw
sudo secscore --only docker
sudo secscore --only sysctl

# JSON output — for scripting or piping
sudo secscore --json
sudo secscore --json | jq '.Score'
sudo secscore --json | jq '[.Findings[] | select(.Severity=="CRITICAL")]'

# Fix mode — interactive, asks before each change
sudo secscore --fix

# Fix mode — preview what would be changed, no writes
sudo secscore --fix --dry-run

# Fix mode — apply everything without prompting
sudo secscore --fix --auto

# Custom profiles
secscore --profiles /etc/secscore/profiles.yaml

# Version
secscore --version
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No issues |
| `1` | Warnings present |
| `2` | Critical issues found |

Useful in CI/CD pipelines:
```bash
sudo secscore --json > report.json
[ $? -lt 2 ] || { echo "Critical issues found"; exit 1; }
```

---

## Fix mode

`--fix` shows each fixable finding and asks what to do:

```
  [1/3] CRITICAL  SSH: PermitRootLogin yes
         Set PermitRootLogin no in sshd_config and reload sshd
         Actions:
           ▸ edit /etc/ssh/sshd_config: set "PermitRootLogin no"
           ▸ systemctl reload sshd

  Apply? [y/N/q]
```

- `y` — apply this fix
- `N` / Enter — skip
- `q` — quit fix mode

`--dry-run` shows the same output but makes no changes — useful to review before committing.

`--auto` applies all fixes without prompting — useful in provisioning scripts.

**What gets fixed automatically:**

| Finding | Fix applied |
|---|---|
| SSH: PermitRootLogin yes | Set to `no` in sshd_config + reload sshd |
| SSH: PasswordAuthentication yes | Set to `no` + reload sshd |
| SSH: PermitEmptyPasswords yes | Set to `no` + reload sshd |
| SSH: MaxAuthTries > 3 | Set to `3` + reload sshd |
| ufw inactive | `ufw --force enable` |
| Port open, no ufw rule | `ufw allow <port>/tcp` |
| sysctl bad values (ASLR, SYN cookies, etc.) | `sysctl -w key=value` + persist to `/etc/sysctl.d/99-secscore.conf` |

**What requires manual action** (not auto-fixed):
- Docker services bound to `0.0.0.0` — requires editing `docker-compose.yml`
- `NOPASSWD` in sudoers — too dangerous to modify automatically
- World-writable files — requires understanding why they're writable

---

## What it checks

| Scanner | Source |
|---|---|
| `docker` | Running containers and host port bindings |
| `ss` | Host-level listeners via `ss -tulnp` |
| `ufw` | Firewall rules via `ufw status numbered` |
| `sshd` | `/etc/ssh/sshd_config` |
| `sysctl` | Kernel security parameters |
| `sudo` | `/etc/sudoers` and `/etc/sudoers.d/*` |
| `world-writable` | Files/dirs with `o+w` in sensitive paths |

### Key design: intention over state

UFW correlation checks whether open ports have **explicit rules**, not just whether they're blocked:

| Port state | ufw rule | Result |
|---|---|---|
| Open | `ALLOW` | INFO — intentional, no noise |
| Open | `LIMIT` | INFO + bonus |
| Open | `DENY` but port still open | CRITICAL — likely Docker iptables bypass |
| Open | No rule | WARNING — unknown intention |
| — | ufw inactive | CRITICAL |

---

## Scoring

Starts at 100. Penalties reduce it, good practices add bonuses.

**Penalties (selected):**

| Issue | Penalty |
|---|---|
| Admin service exposed without proxy | −25 |
| ufw inactive | −25 |
| PermitRootLogin yes | −20 |
| ASLR disabled | −20 |
| PermitEmptyPasswords yes | −30 |
| NOPASSWD: ALL in sudoers | −25 |

**Bonuses (selected):**

| Good practice | Bonus |
|---|---|
| All open ports have explicit ufw rules | +10 |
| PermitRootLogin no | +8 |
| PasswordAuthentication no | +8 |
| ufw LIMIT on a port | +3 per port |
| Service bound to localhost | +2 per service |

---

## Configuration

`profiles.yaml` is loaded from the same directory as the binary, or via `--profiles`.

```yaml
services:
  # match        — substring in container name or image (case-insensitive)
  # type         — admin | infra | app
  # http         — true enables HTTP auth probing on this service
  # behind_proxy — true downgrades public binding CRITICAL → WARNING

  - match: "portainer"
    type: "admin"
    http: true
    behind_proxy: true

  - match: "postgres"
    type: "infra"
    http: false

# Container names that are themselves reverse proxies.
# Matched against container NAME only (not image) to avoid false positives.
proxy_names:
  - "tollgate"
  - "nginx"
  - "traefik"
  - "caddy"

# Sysctl keys to skip — add when a parameter is intentionally non-default.
# Example: ip_forward=1 is expected on VPN gateways and WSL2 hosts.
ignore_sysctl:
  - "net.ipv4.ip_forward"
  - "net.ipv6.conf.all.forwarding"
```

---

## Build from source

```bash
make build                          # build for current platform → ./secscore
make test                           # run tests
sudo make install                   # build + install to /usr/local/bin
make release                        # cross-compile for linux/darwin amd64/arm64
make help                           # list all targets
```

Version is set at build time:
```bash
go build -ldflags "-X github.com/casablanque-code/secscore/internal/version.Version=v0.3.0" \
  -o secscore ./cmd/secscore
```

---

## Architecture

```
cmd/secscore/        entry point, flag parsing, wiring
internal/
  model/             shared types: Snapshot, Finding, Report, Fix, Action
  scanner/           data collectors — read system state, no decisions
  rule/              evaluators — read Snapshot, produce []Finding with optional Fix
  engine/            orchestrates scan → evaluate → deduplicate → score
  fixer/             applies Fix actions, interactive and auto modes
  printer/           ANSI terminal output with progress and category grouping
  version/           build-time version string
profiles.yaml        service classification, proxy names, sysctl ignore list
```

Scanners only read. Rules only evaluate. Fixer only writes when explicitly invoked with `--fix`. No network calls except optional HTTP auth probe directed at localhost.

---

## Tests

```bash
go test ./...
go test -v ./internal/rule/
go test -v ./internal/scanner/
```

Test files are not compiled into the release binary.

---

## Known limitations

**WSL2** — `ufw limit` requires the `xt_recent` kernel module which is missing in WSL2. Use `ufw allow` instead. World-writable scan is automatically skipped on WSL2.

**Docker + ufw** — Docker inserts iptables rules directly and bypasses ufw. Bind containers to `127.0.0.1` in `docker-compose.yml` to prevent this:
```yaml
ports:
  - "127.0.0.1:9000:9000"
```
secscore detects this condition (DENY rule present but port still open) and flags it as CRITICAL.

**Root required** for `ss -p` process names, sudoers read, and full sysctl access. Without root these scanners return partial results.
