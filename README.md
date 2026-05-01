# CVE-2026-31431 (“Copy Fail”) LAN posture scanner

`copyfail_scan.sh` inventories **Linux kernel versions**, **`algif_aead` presence** (loaded / loadable / built-in per probe), and **simple mitigations** on hosts you can reach over **SSH**. It does **not** run an exploit or proof-of-concept code.

**CVE scope:** CVE-2026-31431 is a **local** privilege escalation in the kernel crypto userspace API (`algif_aead`). It is not remote code execution by itself. Treat credentials, the credentials file, and scan output as sensitive.

**Version:** current release **[v1.0.0](https://github.com/monobrau/copyfailscan/releases/tag/v1.0.0)** (GitHub Releases).

## Requirements

| Component | When |
|-----------|------|
| `bash` (4+), `ssh`, `sshpass` | Always |
| `nmap` | Only when **TARGET** is a **CIDR** (e.g. `192.168.54.0/23`). The script exits with an error if you pass a CIDR and `nmap` is missing. |
| Reachable SSH on targets | Always (TCP discovery uses port **22** for CIDR sweeps: `nmap -sn -PS22`) |

Scanning a **single IP or hostname** does not require `nmap`. Scanning a **host list file** does not require `nmap`.

## Credentials file

1. Copy the example and edit secrets **only on the machine that runs the scan**:

   ```bash
   sudo cp copyfail-creds.example /etc/copyfail-creds
   sudo nano /etc/copyfail-creds
   ```

2. **Format:** one `user:password` per line. Only the **first** `:` separates username from password (passwords may contain additional `:` characters).

3. **Permissions:** the script refuses to run unless the file mode is **`600`**:

   ```bash
   sudo chmod 600 /etc/copyfail-creds
   sudo chown root:root /etc/copyfail-creds   # optional
   ```

4. **Who can read it:** if the file is owned by **root** with mode `600`, run the scanner with **`sudo`** so it can read the file. Alternatively, keep the file owned by your user with `600` and run without `sudo`.

5. **Cleanup:** remove `/etc/copyfail-creds` when you no longer need batch password auth.

## Usage

```text
CREDS_FILE=/path/to/creds ./copyfail_scan.sh [TARGET]
```

**TARGET** (optional; default **`192.168.54.0/23`**):

- **CIDR** — requires `nmap`; discovers live hosts with `nmap -sn -PS22`, then SSHs to each.
- **Single IP or hostname** — probes that host only.
- **Path to a host list file** — one host/IP per line; lines beginning with `#` and blank lines are ignored; UTF-8/Windows CRLF line endings are tolerated (`\r` stripped).

```bash
chmod +x copyfail_scan.sh

# Default subnet (see script default)
CREDS_FILE=/etc/copyfail-creds sudo ./copyfail_scan.sh

# Another network
CREDS_FILE=/etc/copyfail-creds sudo ./copyfail_scan.sh 192.168.1.0/24

# Host list (no nmap required)
CREDS_FILE=/etc/copyfail-creds ./copyfail_scan.sh ./hosts.txt

# Single host
CREDS_FILE=/etc/copyfail-creds ./copyfail_scan.sh 192.168.54.93
```

**Environment:**

| Variable | Default | Meaning |
|----------|---------|---------|
| `CREDS_FILE` | `/etc/copyfail-creds` | Path to the `user:password` file |

## Output legend

Strings below match what **v1.0.0** prints (ANSI colors in the terminal).

| Tag | Meaning |
|-----|--------|
| **LIKELY VULNERABLE** | Kernel matches the script’s **heuristic** “affected” branch **and** `algif_aead` appears present (`loaded`, `loadable`, or `builtin`). **Confirm** with your distributor’s security advisory. |
| **VULN - MITIGATED** | Same idea as vulnerable kernel band, but `/etc/modprobe.d` or `initcall_blacklist=algif_aead_init` on the kernel cmdline was detected. |
| **PATCHED / LIKELY OK** | Heuristic says fixed (e.g. **6.18.22+**, **6.19.12+**, **6.20+** within 6.x, or **7.x**). Distro backports may still use unusual `uname -r` strings—verify with your vendor. |
| **PRE-FIX KERNEL RANGE** | Heuristic treats kernel as older than the affected floor used by this script (approx. **4.14** floor in the script’s `classify_kernel` logic). |
| **NO algif_aead - VERIFY** | Probe did not see `algif_aead` via `lsmod`, `modinfo`, or `/boot/config-$(uname -r)`. Could be a minimal image or odd config—**do not** assume “safe” without checking the advisory and kernel package. |
| **UNKNOWN** | Heuristic could not classify the kernel triplet. |
| **SKIP** | No credential line succeeded over SSH, or the remote probe returned nothing useful. |

Remote facts collected per host: `uname -r`, `PRETTY_NAME` from `/etc/os-release`, `hostname`, `algif_aead` signals, mitigation hints.

## Kernel heuristic (v1.0.0)

The script parses **`uname -r`** (e.g. `6.17.13-1-pve`, `7.0.0-14-generic`) and applies a **best-effort** map:

- Treats kernels **before 4.14** (major/minor model used by the script) as **pre-fix range**.
- Treats **6.18.x** with patch **≥ 22** and **6.19.x** with patch **≥ 12** as **patched**; **6.20+** on the 6.x line as **patched**; **7.x** as **patched** for practical scans.
- If **`algif_aead`** is not detected by the probe, status becomes **NO algif_aead - VERIFY** regardless of the kernel branch.

Vendor kernels often **backport** fixes under build strings that do not match upstream numbers—**prefer your OS vendor’s CVE matrix** over this script alone.

## Mitigation hints (high level)

**Module loadable (many Debian/Ubuntu-style systems):**

```bash
echo 'install algif_aead /bin/false' | sudo tee /etc/modprobe.d/disable-algif.conf
sudo rmmod algif_aead 2>/dev/null
```

**Built-in crypto userspace API (common on some Enterprise Linux builds):** module blacklist may be ineffective; follow your vendor for **kernel command line** mitigations (e.g. `initcall_blacklist=algif_aead_init`).

## Operational notes

- **LXC/LXD/Kubernetes nodes:** containers generally share the **host** kernel—prioritize patching and assessment on the **node**.
- **Firewall:** CIDR discovery targets hosts that respond on **TCP 22**; SSH might still fail if policies differ per subnet.

## References

- Advisory site: [copy.fail](https://copy.fail) (always cross-check with your distribution)

## License

MIT — see [`LICENSE`](LICENSE).
