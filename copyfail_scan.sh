#!/usr/bin/env bash
#
# Multi-CVE Linux kernel posture helper (SSH read-only probes; no exploits).
# Covers: CVE-2026-31431 (Copy Fail / AF_ALG), CVE-2026-23111 (nf_tables + user_ns),
#         CVE-2026-23102 (ARM64 SVE/SME signal restore) — all heuristics; confirm with vendor.
# Also flags AF_ALG RX-side gaps (CVE-2026-31677, CVE-2026-43077 — verify with kernel.org / your vendor).
#
# Usage:
#   CREDS_FILE=/path/to/creds ./copyfail_scan.sh [TARGET]
# Probes: CVE-2026-31431 (algif_aead), CVE-2026-31677/43077 (AF_ALG RX heuristics), CVE-2026-23111 (nf_tables+userns), CVE-2026-23102 (arm64 SVE) — heuristics only.
#
# TARGET:
#   - CIDR (e.g. 192.168.54.0/23) - requires nmap
#   - single IP / hostname
#   - path to a host list file (one host/IP per line, # comments ok)
#
# Optional environment (defaults suit homelab scans; tighten for shared / unfamiliar networks):
#   COPYFAIL_PREAUTH=1          Pre-scan TCP/22 SSH banner; skip obvious non-Linux (default 1)
#   COPYFAIL_PREAUTH_NMAP=1     If 1 and nmap exists, nmap -sV -p22 for Windows/macOS hints (default 1; slower).
#                               Set 0 to skip nmap and rely on the SSH banner only.
#   COPYFAIL_PREAUTH_VERBOSE=0  If 1, show truncated SSH banner on pre-auth skips
#   COPYFAIL_PARALLEL=24        Max concurrent host probes (default 24). Set 1 for sequential / conservative runs.
#   COPYFAIL_ORDERED_OUTPUT=1   When PARALLEL>1, print results in probe order (default 1). Set 0 for live interleaved output.
#   COPYFAIL_PTR_LOOKUP=1       For IPv4 targets without a name from nmap/list, try reverse DNS via getent (default 1).
#   COPYFAIL_SUMMARY=1          After hosts, print heuristic OK vs needs review/action (default 1). Set 0 to skip.
#   COPYFAIL_BANNER_TIMEOUT=3     Seconds to wait for TCP/22 + first SSH identification line (nc or timeout+read).
#   COPYFAIL_SSH_CONNECT_TIMEOUT=3  ssh ConnectTimeout (seconds); lower = faster skips on dead hosts.
#   COPYFAIL_NO_BANNER_SKIP_SSH=1 When 1 and PREAUTH=1, do not attempt SSH if no banner (offline / filtered / no SSH).
#                               Set 0 if some targets send a very slow SSH banner.
#
set -euo pipefail

TARGET="${1:-192.168.54.0/23}"
CREDS_FILE="${CREDS_FILE:-/etc/copyfail-creds}"
COPYFAIL_PREAUTH="${COPYFAIL_PREAUTH:-1}"
COPYFAIL_PREAUTH_NMAP="${COPYFAIL_PREAUTH_NMAP:-1}"
COPYFAIL_PREAUTH_VERBOSE="${COPYFAIL_PREAUTH_VERBOSE:-0}"
COPYFAIL_PARALLEL_RAW="${COPYFAIL_PARALLEL:-24}"
if ! [[ "$COPYFAIL_PARALLEL_RAW" =~ ^[0-9]+$ ]] || (( COPYFAIL_PARALLEL_RAW < 1 )); then
    COPYFAIL_PARALLEL=1
elif (( COPYFAIL_PARALLEL_RAW > 64 )); then
    COPYFAIL_PARALLEL=64
else
    COPYFAIL_PARALLEL=$COPYFAIL_PARALLEL_RAW
fi
COPYFAIL_BANNER_TIMEOUT_RAW="${COPYFAIL_BANNER_TIMEOUT:-3}"
if ! [[ "$COPYFAIL_BANNER_TIMEOUT_RAW" =~ ^[0-9]+$ ]] || (( COPYFAIL_BANNER_TIMEOUT_RAW < 1 )); then
    COPYFAIL_BANNER_TIMEOUT=3
elif (( COPYFAIL_BANNER_TIMEOUT_RAW > 30 )); then
    COPYFAIL_BANNER_TIMEOUT=30
else
    COPYFAIL_BANNER_TIMEOUT=$COPYFAIL_BANNER_TIMEOUT_RAW
fi
COPYFAIL_SSH_CONNECT_TIMEOUT_RAW="${COPYFAIL_SSH_CONNECT_TIMEOUT:-3}"
if ! [[ "$COPYFAIL_SSH_CONNECT_TIMEOUT_RAW" =~ ^[0-9]+$ ]] || (( COPYFAIL_SSH_CONNECT_TIMEOUT_RAW < 1 )); then
    COPYFAIL_SSH_CONNECT_TIMEOUT=3
elif (( COPYFAIL_SSH_CONNECT_TIMEOUT_RAW > 60 )); then
    COPYFAIL_SSH_CONNECT_TIMEOUT=60
else
    COPYFAIL_SSH_CONNECT_TIMEOUT=$COPYFAIL_SSH_CONNECT_TIMEOUT_RAW
fi
COPYFAIL_NO_BANNER_SKIP_SSH="${COPYFAIL_NO_BANNER_SKIP_SSH:-1}"
COPYFAIL_ORDERED_OUTPUT="${COPYFAIL_ORDERED_OUTPUT:-1}"
COPYFAIL_PTR_LOOKUP="${COPYFAIL_PTR_LOOKUP:-1}"
COPYFAIL_SUMMARY="${COPYFAIL_SUMMARY:-1}"
COPYFAIL_VERSION="1.2.2"

RED='\033[0;31m'
YEL='\033[1;33m'
GRN='\033[0;32m'
CYA='\033[0;36m'
NC='\033[0m'

declare -gA CFS_DISPLAY_NAME

# Optional reverse DNS for IPv4 when nmap/list did not supply a display name.
cfs_enrich_ptr_labels() {
    [[ "${COPYFAIL_PTR_LOOKUP:-1}" == "0" ]] && return 0
    local h nm
    for h in "${HOSTS[@]}"; do
        [[ -z "${h// }" ]] && continue
        [[ -n "${CFS_DISPLAY_NAME[$h]:-}" ]] && continue
        [[ "$h" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || continue
        # getent returns non-zero when no PTR; with pipefail that would abort the whole script under set -e.
        nm="$(getent hosts "$h" 2>/dev/null | awk -v ip="$h" '{
            for (i = 2; i <= NF; i++) if ($i != ip) { print $i; exit }
        }')" || nm=""
        if [[ -n "$nm" && "$nm" != "$h" ]]; then
            CFS_DISPLAY_NAME["$h"]="$nm"
        fi
    done
}

_cfs_tmp_cleanup() {
    rm -rf "${COPYFAIL_RESULT_DIR:-}" "${CFS_SUMMARY_DIR:-}"
    COPYFAIL_RESULT_DIR=""
    CFS_SUMMARY_DIR=""
}

# Pairs file lines: MESSAGE<TAB>LABEL (LABEL = IP or "IP (hostname)"). Groups identical MESSAGE.
cfs_summary_emit_grouped() {
    local pairs="$1"
    [[ -s "$pairs" ]] || return 1
    sort -t $'\t' -k1,1 -k2,2 -u "$pairs" | awk -F '\t' '
    {
        if ($1 != key) {
            if (key != "") print "- " hosts " — " key
            key = $1
            hosts = $2
        } else {
            hosts = hosts ", " $2
        }
    }
    END {
        if (key != "") print "- " hosts " — " key
    }'
}

cfs_render_summary() {
    [[ "${COPYFAIL_SUMMARY:-1}" == "0" ]] && return 0
    [[ -z "${CFS_SUMMARY_DIR:-}" || ! -d "$CFS_SUMMARY_DIR" ]] && return 0
    local good_pairs review_pairs f
    good_pairs="$(mktemp "${TMPDIR:-/tmp}/cfs-goodp.XXXXXX")"
    review_pairs="$(mktemp "${TMPDIR:-/tmp}/cfs-revp.XXXXXX")"
    shopt -s nullglob
    for f in "$CFS_SUMMARY_DIR"/*.sum; do
        [[ -e "$f" ]] || continue
        while IFS=$'\t' read -r kind label msg; do
            [[ -z "$kind" ]] && continue
            if [[ "$kind" == GOOD ]]; then
                printf '%s\t%s\n' "$msg" "$label" >>"$good_pairs"
            else
                printf '%s\t%s\n' "$msg" "$label" >>"$review_pairs"
            fi
        done <"$f"
    done
    shopt -u nullglob
    echo ""
    echo "=== Summary report ==="
    echo ""
    echo "-- Confirmed good (heuristic) --"
    if [[ -s "$good_pairs" ]]; then
        cfs_summary_emit_grouped "$good_pairs"
    else
        echo "(none)"
    fi
    echo ""
    echo "-- Needs review or action --"
    if [[ -s "$review_pairs" ]]; then
        cfs_summary_emit_grouped "$review_pairs"
    else
        echo "(none)"
    fi
    rm -f "$good_pairs" "$review_pairs"
    rm -rf "$CFS_SUMMARY_DIR"
    CFS_SUMMARY_DIR=""
}

check_host() {
    local HOST="$1"
    local DNS_HINT="${2:-}"
    local RESULT KVER DISTRO AEAD_LOADED MITIGATED HNAME VULN PRE_REASON pr rc_ssh _tag NL_US NL_UR NL_HN NL_OS RX_HEUR_PATCHED GAPS

    _hl() {
        local rh="${1:-}"
        if [[ -n "$rh" && "$rh" != "unknown" && "$rh" != "$HOST" ]]; then
            printf '%s (%s)' "$HOST" "$rh"
        elif [[ -n "$DNS_HINT" && "$DNS_HINT" != "$HOST" ]]; then
            printf '%s (%s)' "$HOST" "$DNS_HINT"
        else
            printf '%s' "$HOST"
        fi
    }

    _sum_good() {
        [[ -z "${CFS_SUMMARY_DIR:-}" || -z "${CFS_SUMMARY_SID:-}" ]] && return 0
        printf 'GOOD\t%s\t%s\n' "$(_hl "${1:-}")" "$2" >"$CFS_SUMMARY_DIR/${CFS_SUMMARY_SID}.sum"
    }
    _sum_review() {
        [[ -z "${CFS_SUMMARY_DIR:-}" || -z "${CFS_SUMMARY_SID:-}" ]] && return 0
        printf 'REVIEW\t%s\t%s\n' "$(_hl "${1:-}")" "$2" >"$CFS_SUMMARY_DIR/${CFS_SUMMARY_SID}.sum"
    }

    set +e
    PRE_REASON="$(preauth_skip_message "$HOST")"
    pr=$?
    set -e
    if [[ $pr -eq 0 && -n "$PRE_REASON" ]]; then
        echo -e "  $(_hl ""): ${CYA}[SKIP - PRE-AUTH]${NC} ${PRE_REASON}"
        _sum_review "" "Skipped before SSH: ${PRE_REASON}"
        return 0
    fi

    RESULT=""
    set +e
    ssh_try_host "$HOST"
    rc_ssh=$?
    set -e
    if [[ $rc_ssh -ne 0 ]]; then
        echo -e "  $(_hl ""): ${YEL}[SKIP]${NC} ${SSH_LAST_FAILURE_DETAIL:-SSH failed (no detail)}"
        _sum_review "" "No successful SSH probe: ${SSH_LAST_FAILURE_DETAIL:-SSH failed}"
        return 0
    fi
    RESULT="$SSH_PROBE_RESULT"

    if [[ "$RESULT" == NOTLINUX\|* ]]; then
        IFS='|' read -r _tag NL_US NL_UR NL_HN NL_OS <<<"$RESULT"
        echo -e "  $(_hl "$NL_HN"): ${CYA}[SKIP - NOT LINUX]${NC} login OK; uname -s=${NL_US}, uname -r=${NL_UR} | ${NL_OS}"
        _sum_review "$NL_HN" "Not Linux (${NL_US}); confirm host is in scope for this scan."
        return 0
    fi

    IFS='|' read -r KVER DISTRO AEAD_LOADED MITIGATED HNAME ARCH NFCONF NFTSTAT USERNS USYSCTL <<<"$RESULT"
    parse_kernel "$KVER"
    local KERNEL_TIER
    KERNEL_TIER="$(classify_kernel "$KMAJOR" "$KMINOR" "$KPATCH")"
    local VULN="$KERNEL_TIER"
    local S2311 S2312
    S2311="$(summarize_23111 "$KERNEL_TIER" "$NFCONF" "$NFTSTAT" "$USERNS" "$USYSCTL")"
    S2312="$(summarize_23102 "$KERNEL_TIER" "$ARCH")"
    local CVE_TAIL=" | 23111=${S2311} | 23102=${S2312}"

    RX_HEUR_PATCHED=0
    if af_alg_rx_heuristic_ok "$KMAJOR" "$KMINOR" "$KPATCH" "$KVER"; then
        RX_HEUR_PATCHED=1
    fi

    if [[ "$AEAD_LOADED" == "no" ]]; then
        VULN="no-aead-module"
    fi

    case "$VULN" in
        vulnerable)
            GAPS="CVE-2026-31431"
            [[ "$RX_HEUR_PATCHED" -eq 0 ]] && GAPS="${GAPS}, CVE-2026-31677/CVE-2026-43077"
            if [[ "$MITIGATED" != "no" ]]; then
                echo -e "  $(_hl "$HNAME"): ${YEL}[31431 VULN - MITIGATED]${NC} ${KVER} | aead=${AEAD_LOADED} | ${DISTRO}${CVE_TAIL}${GAPS:+ | gaps: $GAPS}"
                _sum_review "$HNAME" "CVE-2026-31431 tier looks affected but algif_aead is mitigated — confirm vendor matrix; review gaps: ${GAPS}"
            else
                echo -e "  $(_hl "$HNAME"): ${RED}[31431 LIKELY VULNERABLE]${NC} ${KVER} | aead=${AEAD_LOADED} | ${DISTRO}${CVE_TAIL}${GAPS:+ | gaps: $GAPS}"
                _sum_review "$HNAME" "Treat as priority: patch kernel for CVE-2026-31431 (and AF_ALG RX if listed); ${GAPS}"
            fi
            ;;
        patched)
            if [[ "$RX_HEUR_PATCHED" -eq 1 ]]; then
                echo -e "  $(_hl "$HNAME"): ${GRN}[31431 PATCHED / LIKELY OK]${NC} ${KVER} | aead=${AEAD_LOADED} | ${DISTRO}${CVE_TAIL}"
                _sum_good "$HNAME" "Copy Fail heuristic patched; ${DISTRO} — still confirm *-pve / vendor backports."
            else
                echo -e "  $(_hl "$HNAME"): ${RED}[31431 PATCHED — AF_ALG RX GAPS]${NC} ${KVER} | aead=${AEAD_LOADED} | ${DISTRO}${CVE_TAIL} | gaps: CVE-2026-31677/CVE-2026-43077 (upgrade past NVD floors: e.g. 6.18.24+ / 6.19.14+ on those stable lines)"
                _sum_review "$HNAME" "Kernel past Copy Fail floor but AF_ALG RX heuristics still flag CVE-2026-31677/43077 — plan upgrade past distro/NVD floors."
            fi
            ;;
        pre-vuln)
            echo -e "  $(_hl "$HNAME"): ${GRN}[31431 PRE-FIX KERNEL RANGE]${NC} ${KVER} | aead=${AEAD_LOADED} | ${DISTRO}${CVE_TAIL}"
            _sum_good "$HNAME" "Pre-Copy Fail kernel band per heuristic - verify with vendor if this host class matters."
            ;;
        no-aead-module)
            echo -e "  $(_hl "$HNAME"): ${CYA}[31431 NO algif_aead - VERIFY]${NC} ${KVER} | ${DISTRO} (heuristic: module absent; confirm vendor)${CVE_TAIL}"
            _sum_review "$HNAME" "No algif_aead signal — confirm CVE-2026-31431 exposure with vendor (builtin crypto API / EL kernels differ)."
            ;;
        *)
            echo -e "  $(_hl "$HNAME"): ${YEL}[31431 UNKNOWN]${NC} ${KVER} | aead=${AEAD_LOADED} | ${DISTRO}${CVE_TAIL}"
            _sum_review "$HNAME" "Kernel tuple not classified — check uname vs distro security notices."
            ;;
    esac
}

# Read SSH identification string (first line) from TCP/22 - no cryptographic auth.
# Prefer nc -w (bounded wait on connect + read); else timeout+read on /dev/tcp; else legacy /dev/tcp (may hang on filtered hosts).
read_ssh_banner() {
    local host="$1" line=""
    local tt="${COPYFAIL_BANNER_TIMEOUT:-3}"
    set +e
    line=""
    if command -v nc >/dev/null 2>&1; then
        line="$(nc -w"$tt" "$host" 22 </dev/null 2>/dev/null | head -1)"
    elif command -v timeout >/dev/null 2>&1; then
        line="$(timeout "$((tt + 2))" env CFS_HOST="$host" CFS_TT="$tt" bash -c 'exec 3<>/dev/tcp/"$CFS_HOST"/22 2>/dev/null || exit 1
IFS= read -r -t "$CFS_TT" line <&3 || true
printf %s "$line"' 2>/dev/null)"
    else
        exec 3<>/dev/tcp/"$host"/22 2>/dev/null
        if [[ $? -eq 0 ]]; then
            IFS= read -r -t "$tt" line <&3
            exec 3<&-
            exec 3>&-
        fi
    fi
    line="${line//$'\r'/}"
    line="${line//$'\n'/}"
    [[ -z "$line" ]] && return 1
    printf '%s\n' "$line"
    return 0
}

# Echo skip reason to stdout, exit 0 if this banner should skip Linux CVE probe; else exit 1 with no output.
banner_skip_reason() {
    local b="$1" lb
    lb=$(printf '%s' "$b" | tr '[:upper:]' '[:lower:]')
    if [[ "$lb" =~ openssh_for_windows|openssh.*for.windows|_for_windows_|microsoft|windows_ssh ]]; then
        echo "non-Linux (SSH banner: Windows / Microsoft OpenSSH)"
        return 0
    fi
    if [[ "$lb" =~ cygwin ]]; then
        echo "non-Linux (SSH banner: Cygwin)"
        return 0
    fi
    if [[ "$lb" =~ cisco|routeros|mikrotik|fortinet|fortios|palo.alto|arista|junos|huawei|huaweissh|dellnetworkos ]]; then
        echo "non-Linux (SSH banner: network appliance / switch / router)"
        return 0
    fi
    return 1
}

# Optional nmap service fingerprint on port 22 (slow; helps macOS vs generic OpenSSH).
nmap_skip_reason() {
    local host="$1" out
    command -v nmap >/dev/null 2>&1 || return 1
    set +e
    out=$(nmap -p22 -sV -Pn --version-light --host-timeout 8 "$host" 2>/dev/null)
    [[ -z "$out" ]] && return 1
    if grep -qiE 'microsoft|openssh.*for windows|windows[[:space:]]*ssh' <<<"$out"; then
        echo "non-Linux (nmap: Windows / Microsoft SSH)"
        return 0
    fi
    if grep -qiE 'mac os x|macos|apple remote login|os[[:space:]]*:[[:space:]]*mac|running:[[:space:]]*mac|darwin kernel' <<<"$out"; then
        echo "non-Linux (nmap: macOS / Apple)"
        return 0
    fi
    return 1
}

# Returns 0 and prints reason on stdout if we should skip before sshpass; else returns 1.
preauth_skip_message() {
    local host="$1" banner msg
    [[ "$COPYFAIL_PREAUTH" == "1" ]] || return 1
    msg=""
    if banner="$(read_ssh_banner "$host" 2>/dev/null)"; then
        if msg="$(banner_skip_reason "$banner")"; then
            if [[ "$COPYFAIL_PREAUTH_VERBOSE" == "1" ]]; then
                local short="$banner"
                if (( ${#short} > 72 )); then short="${short:0:72}..."; fi
                msg="$msg | banner: $short"
            fi
            printf '%s\n' "$msg"
            return 0
        fi
    else
        if [[ "$COPYFAIL_NO_BANNER_SKIP_SSH" != "0" ]]; then
            printf '%s\n' "port 22: no SSH identification within ${COPYFAIL_BANNER_TIMEOUT}s (offline, filtered, or non-SSH) — skipping login"
            return 0
        fi
    fi
    if [[ "$COPYFAIL_PREAUTH_NMAP" == "1" ]] && msg="$(nmap_skip_reason "$host")"; then
        printf '%s\n' "$msg"
        return 0
    fi
    return 1
}

# Remote probe - kept in a variable so `RESULT=$(ssh_try_host "$ip")` does not steal a heredoc.
REMOTE_SCRIPT=$'US=$(uname -s 2>/dev/null || echo unknown)
if [[ "$US" != "Linux" ]]; then
  UR=$(uname -r 2>/dev/null || echo "?")
  HN=$(hostname 2>/dev/null || echo "unknown")
  PN=$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME" || echo "Unknown")
  PN=${PN//|/ }
  echo "NOTLINUX|${US}|${UR}|${HN}|${PN}"
  exit 0
fi
KVER=$(uname -r)
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

ARCH=$(uname -m 2>/dev/null || echo unknown)
BCFG="/boot/config-${KVER}"
NFCONF="unk"
NFTSTAT="no"
USERNS="unk"
USYSCTL="unk"
if [[ -r "$BCFG" ]]; then
    NFCONF="n"
    grep -q "^CONFIG_NF_TABLES=y" "$BCFG" && NFCONF=y
    [[ "$NFCONF" == "n" ]] && grep -q "^CONFIG_NF_TABLES=m" "$BCFG" && NFCONF=m
    USERNS="n"
    grep -q "^CONFIG_USER_NS=y" "$BCFG" && USERNS=y
fi
if lsmod 2>/dev/null | grep -qE "^nf_tables[[:space:]]"; then
    NFTSTAT="loaded"
elif modinfo nf_tables >/dev/null 2>&1; then
    NFTSTAT="loadable"
fi
if [[ -r /proc/sys/kernel/unprivileged_userns_clone ]]; then
    USYSCTL=$(cat /proc/sys/kernel/unprivileged_userns_clone 2>/dev/null || echo absent)
else
    USYSCTL="absent"
fi

echo "${KVER}|${DISTRO}|${AEAD_LOADED}|${MITIGATED}|${HNAME}|${ARCH}|${NFCONF}|${NFTSTAT}|${USERNS}|${USYSCTL}"'

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
    if [[ ! -r "$CREDS_FILE" ]]; then
        echo "Credentials file is not readable by this user ($(id -un)): $CREDS_FILE" >&2
        echo "  Files owned by root with mode 600 cannot be read without privileges." >&2
        echo "  Options:  sudo $0 ...   OR   sudo chown $(id -un):$(id -gn) $CREDS_FILE   (keep chmod 600)" >&2
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

# CVE-2026-23111 (nf_tables catchall UAF) — NVD: exploitable with user namespaces + nftables on affected kernels.
summarize_23111() {
    local tier="$1" nfconf="$2" nft="$3" uns="$4" uclone="$5"
    if [[ "$tier" == "patched" || "$tier" == "pre-vuln" ]]; then
        echo "ok(kernel-tier)"
        return 0
    fi
    local nft_ok=0
    [[ "$nfconf" == "y" || "$nfconf" == "m" ]] && nft_ok=1
    [[ "$nft" == "loaded" || "$nft" == "loadable" ]] && nft_ok=1
    if [[ $nft_ok -eq 0 ]]; then
        echo "low(no-nf_tables)"
        return 0
    fi
    if [[ "$uns" != "y" ]]; then
        echo "low(no-CONFIG_USER_NS)"
        return 0
    fi
    if [[ "$uclone" == "0" ]]; then
        echo "reduced(unpriv-userns-disabled)"
        return 0
    fi
    echo "CHECK(CVE-2026-23111)"
}

# CVE-2026-23102 (ARM64 SVE/SME signal context) — NVD: arm64 only.
summarize_23102() {
    local tier="$1" arch="$2"
    if [[ "$arch" != "aarch64" && "$arch" != "arm64" ]]; then
        echo "n/a(not-arm64)"
        return 0
    fi
    if [[ "$tier" == "patched" || "$tier" == "pre-vuln" ]]; then
        echo "ok(kernel-tier)"
        return 0
    fi
    echo "CHECK(CVE-2026-23102)"
}

# CVE-2026-31677 (NVD): AF_ALG RX scatterlist vs receive buffer; floors include 6.12.83, 6.18.24, 6.19.14; 7.0-rc* listed affected.
# Returns 0 if heuristic says RX-side fixes are present, 1 if likely still missing (upstream version tuple).
af_alg_rx_heuristic_ok() {
    local km="$1" kn="$2" kp="$3" kver="$4"
    if [[ "$kver" =~ 7\.0\.[0-9]+-rc ]]; then
        return 1
    fi
    if (( km < 4 || (km == 4 && kn < 14) )); then
        return 0
    fi
    if (( km >= 7 )); then
        return 0
    fi
    if (( km == 6 )); then
        if (( kn > 19 )); then
            return 0
        fi
        if (( kn == 19 && kp >= 14 )); then
            return 0
        fi
        if (( kn == 18 && kp >= 24 )); then
            return 0
        fi
        if (( kn == 12 && kp >= 83 )); then
            return 0
        fi
        return 1
    fi
    return 1
}

# Summarize ssh/sshpass stderr for operators (auth vs network vs other).
classify_ssh_failure() {
    local rc="$1"
    local err="$2"
    local host="${3:-}"
    if grep -qi 'connection refused' <<<"$err"; then
        echo "TCP: connection refused on port 22 (service down or nothing listening)"
        return 0
    fi
    if grep -qi 'connection timed out\|operation timed out\|timed out while waiting' <<<"$err"; then
        echo "TCP: connection timed out (host offline, firewall, or filtering)"
        return 0
    fi
    if grep -qi 'no route to host' <<<"$err"; then
        echo "Network: no route to host"
        return 0
    fi
    if grep -qi 'could not resolve\|name or service not known\|temporary failure in name resolution' <<<"$err"; then
        echo "DNS: name resolution failed"
        return 0
    fi
    if grep -qi 'permission denied' <<<"$err"; then
        echo "SSH: authentication failed for every entry in CREDS_FILE (wrong password/user, disabled account, or key-only access)"
        return 0
    fi
    if grep -qi 'too many authentication failures' <<<"$err"; then
        echo "SSH: too many authentication failures (try fewer credential lines or lower MaxAuthTries on server)"
        return 0
    fi
    if grep -qi 'no matching host key\|host key verification failed' <<<"$err"; then
        echo "SSH: host key verification issue (unexpected if StrictHostKeyChecking=no — check man-in-the-middle)"
        return 0
    fi
    if grep -qi 'could not chdir\|no shell\|not interactive' <<<"$err"; then
        echo "SSH: login or shell restriction on server"
        return 0
    fi
    if grep -qi 'bash:.*/bin/bash\|bash: command not found\|No such file or directory.*bash' <<<"$err"; then
        echo "SSH: remote cannot run bash (often non-Linux or minimal appliance — use a Linux host or install bash)"
        return 0
    fi
    local first
    first=$(printf '%s' "$err" | head -1 | tr -d '\r' | cut -c1-120)
    if [[ -n "$first" ]]; then
        echo "SSH failed (exit ${rc}): ${first}"
    else
        echo "SSH failed (exit ${rc}), no stderr captured — try: ssh -vv user@${host:-host}"
    fi
}

# Sets globals SSH_PROBE_RESULT (stdout from remote) and SSH_LAST_FAILURE_DETAIL on failure.
# Do not call via command substitution — subshell would discard globals.
# Note: never run bare `set -e` here — it leaks into the caller and can abort the script mid-loop.
ssh_try_host() {
    local HOST="$1"
    local line user pass out rc err errf credopen
    SSH_PROBE_RESULT=""
    SSH_LAST_FAILURE_DETAIL=""
    # Opening CREDS_FILE must not abort the whole script under errexit (use explicit check).
    set +e
    exec 4<"$CREDS_FILE"
    credopen=$?
    set +e
    if [[ $credopen -ne 0 ]]; then
        SSH_LAST_FAILURE_DETAIL="Cannot read CREDS_FILE: $CREDS_FILE (permission denied). Run: sudo $0   OR   sudo chown $(id -un):$(id -gn) $CREDS_FILE && chmod 600 $CREDS_FILE"
        return 1
    fi
    while IFS= read -r line <&4 || [[ -n "$line" ]]; do
        [[ -z "${line//[$'\t\r\n ']}" ]] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        user="${line%%:*}"
        pass="${line#*:}"
        [[ -z "$user" ]] && continue
        errf="${TMPDIR:-/tmp}/cfs-$$-${RANDOM}.err"
        set +e
        out="$(SSHPASS="$pass" sshpass -e ssh \
            -o "ConnectTimeout=${COPYFAIL_SSH_CONNECT_TIMEOUT}" \
            -o ConnectionAttempts=1 \
            -o ServerAliveInterval=4 \
            -o ServerAliveCountMax=1 \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o LogLevel=ERROR \
            "${user}@${HOST}" bash <<<"$REMOTE_SCRIPT" 2>"$errf")"
        rc=$?
        err="$(cat "$errf" 2>/dev/null || true)"
        rm -f "$errf"
        SSH_LAST_FAILURE_DETAIL="$(classify_ssh_failure "$rc" "$err" "$HOST")"
        if [[ $rc -eq 0 && -n "$out" ]]; then
            SSH_PROBE_RESULT="$out"
            SSH_LAST_FAILURE_DETAIL=""
            exec 4<&-
            return 0
        fi
    done
    exec 4<&-
    if [[ -z "$SSH_LAST_FAILURE_DETAIL" ]]; then
        SSH_LAST_FAILURE_DETAIL="No usable credential lines in CREDS_FILE, or SSH produced no parseable error"
    fi
    return 1
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
        HOSTS=()
        local rest ip nm line
        while IFS= read -r line; do
            line="${line//$'\r'/}"
            [[ "$line" =~ ^Nmap\ scan\ report\ for\ (.+)$ ]] || continue
            rest="${BASH_REMATCH[1]}"
            rest="${rest#"${rest%%[![:space:]]*}"}"
            rest="${rest%"${rest##*[![:space:]]}"}"
            # Avoid '(' ')' in [[ ]] patterns: they interact badly with shopt extglob.
            ip="${rest##*\(}"
            if [[ "$ip" == "$rest" ]]; then
                HOSTS+=("$rest")
                continue
            fi
            ip="${ip%\)}"
            if [[ "$ip" =~ ^[0-9a-fA-F:.]+$ ]]; then
                nm="${rest%\(*}"
                nm="${nm%"${nm##*[![:space:]]}"}"
                nm="${nm#"${nm%%[![:space:]]*}"}"
                HOSTS+=("$ip")
                [[ -n "$nm" && "$nm" != "$ip" ]] && CFS_DISPLAY_NAME["$ip"]="$nm"
            else
                HOSTS+=("$rest")
            fi
        done < <(LANG=C LC_ALL=C nmap -sn -PS22 "$t" 2>/dev/null || true)
        return
    fi
    HOSTS=("$t")
}

require_file
require_cmds

echo "=== Linux kernel CVE posture scan v${COPYFAIL_VERSION} ==="
echo "=== CVEs: 2026-31431 (Copy Fail), 2026-31677/43077 (AF_ALG RX), 2026-23111 (nf_tables), 2026-23102 (arm64 SVE) — heuristics only ==="
echo "=== CREDS_FILE=${CREDS_FILE} | TARGET=${TARGET} ==="
echo "=== PREAUTH=${COPYFAIL_PREAUTH} PREAUTH_NMAP=${COPYFAIL_PREAUTH_NMAP} PARALLEL=${COPYFAIL_PARALLEL} ORDERED_OUT=${COPYFAIL_ORDERED_OUTPUT} SUMMARY=${COPYFAIL_SUMMARY} PTR=${COPYFAIL_PTR_LOOKUP} BANNER_TO=${COPYFAIL_BANNER_TIMEOUT}s SSH_TO=${COPYFAIL_SSH_CONNECT_TIMEOUT}s NO_BANNER_SKIP=${COPYFAIL_NO_BANNER_SKIP_SSH} ==="
echo ""

discover_hosts "$TARGET"
cfs_enrich_ptr_labels
echo "[*] ${#HOSTS[@]} host(s) to probe"
echo ""

COPYFAIL_RESULT_DIR=""
CFS_SUMMARY_DIR=""
if [[ "${COPYFAIL_SUMMARY:-1}" != "0" ]]; then
    CFS_SUMMARY_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cfs-sum.XXXXXX")" || {
        echo "mktemp failed for summary buffer" >&2
        exit 1
    }
fi
if (( COPYFAIL_PARALLEL > 1 )) && [[ "$COPYFAIL_ORDERED_OUTPUT" != "0" ]]; then
    COPYFAIL_RESULT_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cfs-results.XXXXXX")" || {
        echo "mktemp failed for result buffer" >&2
        exit 1
    }
fi
if [[ -n "${COPYFAIL_RESULT_DIR:-}" || -n "${CFS_SUMMARY_DIR:-}" ]]; then
    trap '_cfs_tmp_cleanup' EXIT INT HUP TERM
fi

# Emit buffered lines in probe order as soon as each prefix of jobs has finished.
cfs_emit_next=0
declare -A cfs_done
cfs_mark_done() {
    local fin="$1"
    [[ -n "${COPYFAIL_RESULT_DIR:-}" ]] || return 0
    cfs_done[$fin]=1
    while [[ -n "${cfs_done[$cfs_emit_next]:-}" ]]; do
        [[ -f "$COPYFAIL_RESULT_DIR/$cfs_emit_next.log" ]] && cat "$COPYFAIL_RESULT_DIR/$cfs_emit_next.log"
        rm -f "$COPYFAIL_RESULT_DIR/$cfs_emit_next.log"
        unset "cfs_done[$cfs_emit_next]"
        ((cfs_emit_next++)) || true
    done
}

cfs_drain_one_job() {
    wait "${pids[0]}"
    cfs_mark_done "${job_sid[0]}"
    _qp=() _qs=()
    for ((_qi = 1; _qi < ${#pids[@]}; _qi++)); do
        _qp+=("${pids[_qi]}")
        _qs+=("${job_sid[_qi]}")
    done
    pids=("${_qp[@]}")
    job_sid=("${_qs[@]}")
}

pids=()
job_sid=()
cfs_spawn_id=0
for _idx in "${!HOSTS[@]}"; do
    HOST="${HOSTS[_idx]}"
    [[ -z "${HOST// }" ]] && continue
    while (( ${#pids[@]} >= COPYFAIL_PARALLEL )); do
        cfs_drain_one_job
    done
    _sid=$cfs_spawn_id
    ((cfs_spawn_id++)) || true
    if [[ -n "${COPYFAIL_RESULT_DIR:-}" ]]; then
        CFS_SUMMARY_SID="$_sid" CFS_SUMMARY_DIR="${CFS_SUMMARY_DIR:-}" \
            check_host "$HOST" "${CFS_DISPLAY_NAME[$HOST]:-}" >"$COPYFAIL_RESULT_DIR/$_sid.log" 2>&1 &
    else
        CFS_SUMMARY_SID="$_sid" CFS_SUMMARY_DIR="${CFS_SUMMARY_DIR:-}" check_host "$HOST" "${CFS_DISPLAY_NAME[$HOST]:-}" &
    fi
    pids+=($!)
    job_sid+=("$_sid")
done
while (( ${#pids[@]} > 0 )); do
    cfs_drain_one_job
done

if [[ -n "${COPYFAIL_RESULT_DIR:-}" ]]; then
    rm -rf "$COPYFAIL_RESULT_DIR"
    COPYFAIL_RESULT_DIR=""
fi

echo ""
echo "=== Scan complete ==="
cfs_render_summary
echo ""
echo "Heuristics only — confirm each CVE with your distributor (especially *-pve / backported kernels)."
echo "CVE-2026-31677 NVD floors (upstream tuple): 6.12.83+, 6.18.24+, 6.19.14+; 7.0-rc* may still be affected."
echo "CVE-2026-31431 mitigation (module loadable): echo 'install algif_aead /bin/false' | sudo tee /etc/modprobe.d/disable-algif.conf && sudo rmmod algif_aead 2>/dev/null"
echo "CVE-2026-23111: often mitigated by disabling unprivileged user namespaces (sysctl) and/or patching; see vendor guidance for nftables."
echo "Builtin crypto API (common on some EL kernels): use initcall_blacklist=algif_aead_init on the kernel cmdline - see vendor docs."
echo "Missed live SSH hosts? Try COPYFAIL_NO_BANNER_SKIP_SSH=0 and/or COPYFAIL_BANNER_TIMEOUT=8."
