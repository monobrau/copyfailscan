# copyfailscan

Bash helper: discover hosts (optional **CIDR** via `nmap`), then **SSH read-only** checks for **CVE-2026-31431** (Copy Fail / `algif_aead`), **CVE-2026-31677 / CVE-2026-43077** (AF_ALG RX heuristics), **CVE-2026-23111** (nftables + user namespaces), **CVE-2026-23102** (arm64 SVE/SME). **Heuristics only** — not an exploit; confirm with your distributor.

**Treat as sensitive:** password file on disk; output lists hosts and kernel posture.

## Requirements

| Component | When |
|-----------|------|
| `bash`, `ssh`, `sshpass` | Always |
| `nmap` | **CIDR targets:** required for `nmap -sn -PS22`. With **`COPYFAIL_PREAUTH_NMAP=1`** (default), also **`nmap -p22 -sV`** per host after the SSH banner — slower, but helps spot macOS/Windows. Set **`COPYFAIL_PREAUTH_NMAP=0`** to skip per-host `nmap` (you still need `nmap` for a CIDR sweep). |

## Credentials

1. `sudo cp copyfail-creds.example /etc/copyfail-creds && sudo nano /etc/copyfail-creds`
2. One `user:password` per line (only the **first** `:` splits user from password).
3. Mode **`600`** required: `sudo chmod 600 /etc/copyfail-creds`  
   If owned by root, run the script with **`sudo`** (or `chown` to your user, still `600`).

## Usage

```text
CREDS_FILE=/path/to/creds ./copyfail_scan.sh [TARGET]
```

**`TARGET`:** CIDR, single IP/hostname, or path to a host list (`#` comments ok). Omitted target uses the script default (see `TARGET=` in `copyfail_scan.sh`).

```bash
chmod +x copyfail_scan.sh
sudo CREDS_FILE=/etc/copyfail-creds ./copyfail_scan.sh
sudo CREDS_FILE=/etc/copyfail-creds ./copyfail_scan.sh 192.168.1.0/24
CREDS_FILE=~/creds ./copyfail_scan.sh ./hosts.txt
```

**Output:** stdout only (no report file). Use `tee` to save. After per-host lines: **`=== Summary report ===`** (unless `COPYFAIL_SUMMARY=0`) — *Confirmed good* vs *Needs review*; **hosts sharing the same summary line are merged** (comma-separated labels).

## Environment

| Variable | Default | Role |
|----------|---------|------|
| `CREDS_FILE` | `/etc/copyfail-creds` | `user:password` file |
| `COPYFAIL_PREAUTH` | `1` | TCP/22 SSH banner; skip obvious non-Linux before login |
| `COPYFAIL_PREAUTH_NMAP` | `1` | Extra `nmap -p22 -sV` when banner inconclusive (slower) |
| `COPYFAIL_PREAUTH_VERBOSE` | `0` | `1` = show truncated banner on pre-auth skips |
| `COPYFAIL_PARALLEL` | `24` | Max concurrent probes (`1` = sequential) |
| `COPYFAIL_ORDERED_OUTPUT` | `1` | When parallel, buffer lines in probe order (`0` = interleaved) |
| `COPYFAIL_PTR_LOOKUP` | `1` | IPv4 reverse DNS via `getent` when nmap/list has no name |
| `COPYFAIL_SUMMARY` | `1` | Print grouped end summary (`0` = skip) |
| `COPYFAIL_BANNER_TIMEOUT` | `3` | Seconds to wait for SSH identification on port 22 |
| `COPYFAIL_SSH_CONNECT_TIMEOUT` | `3` | `ssh ConnectTimeout` (seconds) |
| `COPYFAIL_NO_BANNER_SKIP_SSH` | `1` | If pre-auth sees no banner, skip SSH attempt (`0` if banners are very slow) |

```bash
# Example: no per-host nmap, sequential
COPYFAIL_PREAUTH_NMAP=0 COPYFAIL_PARALLEL=1 sudo ./copyfail_scan.sh 192.168.54.93
```

## Reading results

- Tags like **`31431 PATCHED`**, **`31431 VULN - MITIGATED`**, **`31431 NO algif_aead - VERIFY`**, **`[SKIP]`** / **`[SKIP - PRE-AUTH]`** are script heuristics; **`23111=`** / **`23102=`** tail fields summarize nftables/user-ns and arm64 SVE probes.
- **`*-pve` / vendor kernels:** `uname -r` may not match upstream NVD tuples — use **distro/Proxmox security notices** and installed kernel packages, not this script alone.
- **Mitigation hint (module-based systems):**  
  `echo 'install algif_aead /bin/false' | sudo tee /etc/modprobe.d/disable-algif.conf && sudo rmmod algif_aead 2>/dev/null`  
  Built-in crypto API paths differ — follow vendor docs (e.g. kernel cmdline blacklist).

## References

- [copy.fail](https://copy.fail) — cross-check with your OS vendor and [NVD](https://nvd.nist.gov/).

## License

MIT — see [`LICENSE`](LICENSE).
