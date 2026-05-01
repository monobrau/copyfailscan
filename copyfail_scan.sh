#!/usr/bin/env bash
#
# CVE-2026-31431 ("Copy Fail") - LAN-oriented posture check via SSH.
# Discovers live hosts (TCP/22 probe), then runs a read-only remote probe:
# kernel version, algif_aead presence, optional mitigations. Does NOT run an exploit.
#
# Usage:
#   CREDS_FILE=/path/to/creds ./copyfail_scan.sh [TARGET]
#
# TARGET:
#   - CIDR (e.g. 192.168.54.0/23) - requires nmap
#   - single IP / hostname
#   - path to a host list file (one host/IP per line, # comments ok)
#
set -euo pipefail

TARGET="${1:-192.168.54.0/23}"
CREDS_FILE="${CREDS_FILE:-/etc/copyfail-creds}"

RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYA='\033[0;36m'
NC='\033[0m'

# Remote probe - kept in a variable so `RESULT=$(ssh_try_host "$ip")` does not steal a heredoc.
REMOTE_SCRIPT=$'KVER=$(uname -r)
DISTRO=$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || echo "Unknown")
HNAME=$(hostname 2>/dev/null || echo "unknown")

AEAD_LOADED="no"
if lsmod 2>/dev/null | grep -qw algif_aead; then
    AEAD_LOADED="loaded"
elif modinfo algif_aead >/dev/null 2>&1; then
    AEAD_LOADED="loadable"
elif grep -q "CONFIG_CRYPTO_USER_API_AEAD=y" "/boot/config-${KVER}" 2>/dev/null; then
    AEAD_LOADED="builtin"
fi

MITIGATED="no"
if grep -rq "algif_aead" /etc/modprobe.d/ 2>/dev/null; then
    MITIGATED="modprobe-blocked"
elif grep -q "initcall_blacklist=algif_aead_init" /proc/cmdline 2>/dev/null; then
    MITIGATED="grub-blacklisted"
fi

echo "${KVER}|${DISTRO}|${AEAD_LOADED}|${MITIGATED}|${HNAME}"'

require_file() {
    if [[ ! -f "$CREDS_FILE" ]]; then
        echo "Credentials file not found: $CREDS_FILE" >&2
        exit 1
    fi
    local mode
    mode="$(stat -c '%a' "$CREDS_FILE" 2>/dev/null || stat -f '%OLp' "$CREDS_FILE")"
    if [[ "$mode" != "600" ]]; then
        echo "Credentials file must be chmod 600 (got $mode): $CREDS_FILE" >&2
        exit 1
    fi
}

require_cmds() {
    if ! command -v sshpass >/dev/null 2>&1; then
        echo "sshpass not found (e.g. apt install sshpass / slackpkg install sshpass)." >&2
        exit 1
    fi
    if ! command -v ssh >/dev/null 2>&1; then
        echo "ssh client not found." >&2
        exit 1
    fi
}

# Parse X.Y.Z prefix from uname -r (handles 6.17.13-1-pve, 7.0.0-14-generic, etc.)
parse_kernel() {
    local k="$1"
    local rest="${k%%-*}"
    KMAJOR=$(echo "$rest" | cut -d. -f1)
    KMINOR=$(echo "$rest" | cut -d. -f2)
    local p
    p=$(echo "$rest" | cut -d. -f3)
    KPATCH=$(echo "$p" | grep -o '^[0-9]*' || echo "0")
    [[ "$KMAJOR" =~ ^[0-9]+$ ]] || KMAJOR=0
    [[ "$KMINOR" =~ ^[0-9]+$ ]] || KMINOR=0
    [[ "$KPATCH" =~ ^[0-9]+$ ]] || KPATCH=0
}

# Heuristic: fixed upstream in 6.18.22+, 6.19.12+, and mainline 6.20+; treat 7.x as fixed for practical scans.
classify_kernel() {
    local km="$1" kn="$2" kp="$3"
    if (( km < 4 || (km == 4 && kn < 14) )); then
        echo "pre-vuln"
        return
    fi
    if (( km >= 7 )); then
        echo "patched"
        return
    fi
    if (( km == 6 )); then
        if (( kn > 19 )); then
            echo "patched"
            return
        fi
        if (( kn == 19 && kp >= 12 )); then
            echo "patched"
            return
        fi
        if (( kn == 19 )); then
            echo "vulnerable"
            return
        fi
        if (( kn == 18 && kp >= 22 )); then
            echo "patched"
            return
        fi
        if (( kn == 18 )); then
            echo "vulnerable"
            return
        fi
        if (( kn < 18 )); then
            echo "vulnerable"
            return
        fi
    fi
    if (( km == 5 || km == 4 )); then
        echo "vulnerable"
        return
    fi
    echo "unknown"
}

ssh_try_host() {
    local HOST="$1"
    local line user pass out rc
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "${line//[$'\t\r\n ']}" ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        user="${line%%:*}"
        pass="${line#*:}"
        [[ -z "$user" ]] && continue
        # Disable errexit: failed SSH must not kill the whole scan under `set -e`.
        set +e
        out="$(SSHPASS="$pass" sshpass -e ssh \
            -o ConnectTimeout=5 \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            "${user}@${HOST}" bash <<<"$REMOTE_SCRIPT" 2>/dev/null)"
        rc=$?
        set -e
        if [[ $rc -eq 0 && -n "$out" ]]; then
            printf '%s\n' "$out"
            return 0
        fi
    done <"$CREDS_FILE"
    return 1
}

check_host() {
    local HOST="$1"
    local RESULT KVER DISTRO AEAD_LOADED MITIGATED HNAME VULN

    RESULT=""
    if ! RESULT="$(ssh_try_host "$HOST")"; then
        echo -e "  ${HOST}: ${YEL}[SKIP]${NC} No SSH auth succeeded (or probe failed)"
        return 0
    fi

    IFS='|' read -r KVER DISTRO AEAD_LOADED MITIGATED HNAME <<<"$RESULT"
    parse_kernel "$KVER"
    VULN="$(classify_kernel "$KMAJOR" "$KMINOR" "$KPATCH")"

    if [[ "$AEAD_LOADED" == "no" ]]; then
        VULN="no-aead-module"
    fi

    case "$VULN" in
        vulnerable)
            if [[ "$MITIGATED" != "no" ]]; then
                echo -e "  ${HOST} (${HNAME}): ${YEL}[VULN - MITIGATED]${NC} ${KVER} | aead=${AEAD_LOADED} | ${DISTRO}"
            else
                echo -e "  ${HOST} (${HNAME}): ${RED}[LIKELY VULNERABLE]${NC} ${KVER} | aead=${AEAD_LOADED} | ${DISTRO}"
            fi
            ;;
        patched)
            echo -e "  ${HOST} (${HNAME}): ${GRN}[PATCHED / LIKELY OK]${NC} ${KVER} | aead=${AEAD_LOADED} | ${DISTRO}"
            ;;
        pre-vuln)
            echo -e "  ${HOST} (${HNAME}): ${GRN}[PRE-FIX KERNEL RANGE]${NC} ${KVER} | aead=${AEAD_LOADED} | ${DISTRO}"
            ;;
        no-aead-module)
            echo -e "  ${HOST} (${HNAME}): ${CYA}[NO algif_aead - VERIFY]${NC} ${KVER} | ${DISTRO} (heuristic: module absent; confirm with vendor advisory / patched kernel)"
            ;;
        *)
            echo -e "  ${HOST} (${HNAME}): ${YEL}[UNKNOWN]${NC} ${KVER} | aead=${AEAD_LOADED} | ${DISTRO}"
            ;;
    esac
}

discover_hosts() {
    local t="$1"
    if [[ -f "$t" ]]; then
        mapfile -t HOSTS < <(sed 's/\r$//' "$t" | grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$' || true)
        return
    fi
    if [[ "$t" == */* ]]; then
        if ! command -v nmap >/dev/null 2>&1; then
            echo "nmap is required for CIDR discovery (${t}). Install nmap or pass a host list file." >&2
            exit 1
        fi
        echo "[*] nmap TCP discovery (-PS22) on $t ..."
        mapfile -t HOSTS < <(nmap -sn -PS22 "$t" 2>/dev/null | awk '/Nmap scan report/{print $NF}' | tr -d '()' || true)
        return
    fi
    HOSTS=("$t")
}

require_file
require_cmds

echo "=== CVE-2026-31431 (Copy Fail) posture scan ==="
echo "=== CREDS_FILE=${CREDS_FILE} | TARGET=${TARGET} ==="
echo ""

discover_hosts "$TARGET"
echo "[*] ${#HOSTS[@]} host(s) to probe"
echo ""

for HOST in "${HOSTS[@]}"; do
    [[ -z "${HOST// }" ]] && continue
    check_host "$HOST"
done

echo ""
echo "=== Scan complete ==="
echo "Heuristic only - verify with distro security notices and patched kernels."
echo "Mitigation (module loadable): echo 'install algif_aead /bin/false' | sudo tee /etc/modprobe.d/disable-algif.conf && sudo rmmod algif_aead 2>/dev/null"
echo "Builtin crypto API (common on some EL kernels): use initcall_blacklist=algif_aead_init on the kernel cmdline - see vendor docs."
