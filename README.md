# Linux kernel LAN posture scanner (multi-CVE heuristics)

`copyfail_scan.sh` inventories **Linux** hosts over **SSH** (read-only probes): **CVE-2026-31431** (Copy Fail / `algif_aead`), **CVE-2026-23111** (nf_tables + user namespaces), and **CVE-2026-23102** (ARM64 SVE/SME). It does **not** run exploits.

**Scope:** these are primarily **local** kernel issues (an attacker usually needs a user account on the host). Treat credentials and output as sensitive.

**Version:** current release **[v1.2.0](https://github.com/monobrau/copyfailscan/releases/tag/v1.2.0)** (GitHub Releases). See **Changes in v1.2.0** below.

### Changes in v1.2.0

- **CVE-2026-23111** ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-23111)): tail shows `23111=…` from `/boot/config-*`, `nf_tables` module state, `CONFIG_USER_NS`, and `kernel.unprivileged_userns_clone`.
- **CVE-2026-23102** ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-23102)): tail shows `23102=…` on **aarch64/arm64** only (otherwise `n/a(not-arm64)`).
- **CVE-2026-31431** ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-31431)): status tags now prefixed with **`31431`** for clarity.

### Changes in v1.1.0

- **Pre-auth:** optional skip of obvious non-Linux targets via SSH **banner** (and optional **`nmap -sV -p22`** with `COPYFAIL_PREAUTH_NMAP=1`) before `sshpass`.
- **Clearer failures:** distinguish **bad credentials** vs **network/DNS/TCP** vs **CREDS not readable**; **no silent exit** if `/etc/copyfail-creds` is root-only and you run without `sudo`.
- **After login:** **`[SKIP - NOT LINUX]`** when `uname -s` ≠ `Linux`.
- **Robustness:** removed leaked **`set -e`** inside SSH loops.

Older releases: [v1.1.0](https://github.com/monobrau/copyfailscan/releases/tag/v1.1.0), [v1.0.0](https://github.com/monobrau/copyfailscan/releases/tag/v1.0.0).

### Note on “CVE-2026-1042” and io_uring

Some **blog posts** label a critical **io_uring** issue as “CVE-2026-1042”. In **NVD**, [CVE-2026-1042](https://nvd.nist.gov/vuln/detail/CVE-2026-1042) is currently a **WordPress plugin** (Hello Bar), **not** the Linux kernel. This repo does **not** scan for that ID. Use **kernel.org / distro advisories** for io_uring issues under the **correct CVE** assigned to the kernel.

## Requirements

| Component | When |
|-----------|------|
| `bash` (4+), `ssh`, `sshpass` | Always |
| `nmap` | Only when **TARGET** is a **CIDR** (e.g. `192.168.54.0/23`), **or** when **`COPYFAIL_PREAUTH_NMAP=1`** (optional per-host service probe). The script exits with an error if you pass a CIDR and `nmap` is missing. |
| Reachable SSH on targets | Always (TCP discovery uses port **22** for CIDR sweeps: `nmap -sn -PS22`) |

Scanning a **single IP or hostname** does not require `nmap` **unless** you enable **`COPYFAIL_PREAUTH_NMAP=1`**. Scanning a **host list file** does not require `nmap` for discovery (same exception applies if `COPYFAIL_PREAUTH_NMAP=1`).

## Pre-auth filtering (before SSH)

These checks apply to **Linux-oriented** scanning, so the script tries to avoid wasting credential attempts on obvious non-Linux SSH servers.

1. **SSH banner (default, fast)** — Opens **TCP/22** and reads the SSH identification string (RFC 4253 first line, no crypto handshake). If it matches common patterns (**Windows** / Microsoft OpenSSH, **Cygwin**, many **network appliances**), the host is reported as **`[SKIP - PRE-AUTH]`** and **never** runs `sshpass`.

2. **Optional `nmap` service probe** — **macOS** and some other systems often present the same generic `SSH-2.0-OpenSSH_…` banner as Linux, so they cannot be separated by banner alone. Set **`COPYFAIL_PREAUTH_NMAP=1`** to run **`nmap -p22 -sV`** per host (slower, requires `nmap`) and skip targets whose fingerprint text suggests **Windows** or **macOS/Apple**.

If no rule matches, the script continues with normal SSH as before.

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

4. **Who can read it:** if the file is owned by **root** with mode `600`, **only root can read it**. Run **`sudo ./copyfail_scan.sh`** (with `CREDS_FILE` set if needed), **or** `sudo chown youruser:yourgroup /etc/copyfail-creds` while keeping **`chmod 600`**.

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
| `COPYFAIL_PREAUTH` | `1` | If `1`, read SSH banner on port 22 and skip obvious non-Linux targets before `sshpass`. Set to `0` to disable. |
| `COPYFAIL_PREAUTH_NMAP` | `0` | If `1` and `nmap` is installed, run `nmap -p22 -sV` when banner did not justify a skip (helps detect **macOS** and some Windows installs). **Slow** on large subnets. |
| `COPYFAIL_PREAUTH_VERBOSE` | `0` | If `1`, append a truncated copy of the SSH banner to `[SKIP - PRE-AUTH]` lines (debugging). |

```bash
# Example: also use nmap to skip macOS / ambiguous OpenSSH banners (needs nmap installed)
COPYFAIL_PREAUTH_NMAP=1 CREDS_FILE=/etc/copyfail-creds sudo ./copyfail_scan.sh 192.168.54.0/23
```

## Output legend

Strings below match what **v1.2.0** prints (ANSI colors in the terminal).

### CVE-2026-31431 (Copy Fail) tags

| Tag | Meaning |
|-----|--------|
| **SKIP - PRE-AUTH** | Host skipped **before** SSH: SSH banner (and optionally `nmap -sV`) matched **non-Linux** / **non-target** patterns. |
| **31431 LIKELY VULNERABLE** | Kernel matches the script’s **heuristic** “affected” branch **and** `algif_aead` appears present. **Confirm** with your distributor. |
| **31431 VULN - MITIGATED** | Same kernel band, but `algif_aead` mitigations were detected. |
| **31431 PATCHED / LIKELY OK** | Heuristic says fixed (upstream-style **6.18.22+**, **6.19.12+**, **6.20+** on 6.x, or **7.x**). **Backports** (e.g. `*-pve`) may still show older `uname` — verify packages. |
| **31431 PRE-FIX KERNEL RANGE** | Heuristic treats kernel as older than the **~4.14** floor used by the script. |
| **31431 NO algif_aead - VERIFY** | Probe did not see `algif_aead` — **do not** assume safe without checking the advisory. |
| **31431 UNKNOWN** | Heuristic could not classify the kernel triplet. |
| **SKIP - NOT LINUX** | SSH login worked but `uname -s` ≠ `Linux`. |
| **SKIP** | No credential succeeded; line explains **auth / TCP / DNS / creds file** when possible. |

### Trailing `23111=` / `23102=` fields (v1.2.0+)

Each Linux result line ends with **`| 23111=… | 23102=…`** (no ANSI inside these tokens):

| Token | Meaning (heuristic) |
|-------|---------------------|
| `23111=ok(kernel-tier)` | Kernel tier looks **patched or pre-affected** for the script’s coarse map — **still** confirm CVE-2026-23111 with your vendor. |
| `23111=low(no-nf_tables)` | No `nf_tables` build or module signal — attack surface for that CVE is **reduced** in this probe’s view. |
| `23111=low(no-CONFIG_USER_NS)` | `CONFIG_USER_NS` not **y** in `/boot/config-*` (if readable). |
| `23111=reduced(unpriv-userns-disabled)` | `kernel.unprivileged_userns_clone=0` — common hardening; **reduces** typical 23111 exploit paths. |
| `23111=CHECK(CVE-2026-23111)` | **nftables + user_ns signals** and kernel tier **not** in the script’s “safe” bucket — **review** [CVE-2026-23111](https://nvd.nist.gov/vuln/detail/CVE-2026-23111) / distro matrix. |
| `23102=n/a(not-arm64)` | CVE-2026-23102 is **ARM64**-specific ([NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-23102)). |
| `23102=ok(kernel-tier)` | On arm64, kernel tier looks patched/pre-range in this script’s map. |
| `23102=CHECK(CVE-2026-23102)` | On arm64, tier suggests **review** SVE/SME fixes with your vendor. |

Remote facts collected (when Linux): `uname -r`, `PRETTY_NAME`, `hostname`, **31431** `algif_aead` + mitigations, **`uname -m`**, `/boot/config-*` snippets for **NF_TABLES** / **USER_NS**, `nf_tables` load state, **`kernel.unprivileged_userns_clone`**.

## Kernel heuristic

The script parses **`uname -r`** (e.g. `6.17.13-1-pve`, `7.0.0-14-generic`) and applies a **best-effort** map:

- Treats kernels **before 4.14** (major/minor model used by the script) as **pre-fix range**.
- Treats **6.18.x** with patch **≥ 22** and **6.19.x** with patch **≥ 12** as **patched**; **6.20+** on the 6.x line as **patched**; **7.x** as **patched** for practical scans.
- If **`algif_aead`** is not detected by the probe, status becomes **NO algif_aead - VERIFY** regardless of the kernel branch.

Vendor kernels often **backport** fixes under build strings that do not match upstream numbers—**prefer your OS vendor’s CVE matrix** over this script alone.

**Proxmox VE (`*-pve` kernels):** `uname -r` may stay on **6.8.x** or **6.17.x** while Debian/Proxmox security updates fix CVE-2026-31431 in the **`pve-kernel-*`** package. Treat **`[LIKELY VULNERABLE]`** on `*-pve` as “**confirm against Proxmox/Debian advisories and `dpkg -l pve-kernel-*`**,” not proof of an exploitable kernel.

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
