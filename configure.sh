#!/usr/bin/env bash
# SideSaddle host configuration
# Run once on any Linux/WSL op station to set up session logging.
#
# Usage:  bash configure.sh
#         bash configure.sh --log-root /custom/path

set -euo pipefail

# ── Args ──────────────────────────────────────────────────────────────────────

LOG_ROOT="${HOME}/.local/share/sidesaddle"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --log-root) LOG_ROOT="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

EW_SCRIPTS="${HOME}/.local/share/evil-winrm-scripts"

# ── Directories ───────────────────────────────────────────────────────────────

mkdir -p "${LOG_ROOT}"
mkdir -p "${EW_SCRIPTS}"
echo "[+] Log root:       ${LOG_ROOT}"
echo "[+] EW scripts dir: ${EW_SCRIPTS}"

# ── Evil-WinRM prompt override ────────────────────────────────────────────────

cat > "${EW_SCRIPTS}/prompt.ps1" << 'EOF'
# Override evil-winrm prompt to include target hostname for log attribution
function prompt {
    "*Evil-WinRM* PS [$env:COMPUTERNAME] $PWD> "
}
EOF
echo "[+] Evil-WinRM prompt script → ${EW_SCRIPTS}/prompt.ps1"

# ── Zsh configuration block ───────────────────────────────────────────────────

ZSHRC="${HOME}/.zshrc"
MARKER="# === SideSaddle session logging ==="

if grep -qF "${MARKER}" "${ZSHRC}" 2>/dev/null; then
    echo "[~] Zshrc already configured — skipping (remove ${MARKER} block to re-run)"
else
    cat >> "${ZSHRC}" << ZSHBLOCK

${MARKER}
_SS_ROOT="\${SS_LOG_ROOT:-${LOG_ROOT}}"

_ss_skip() {
    [[ "\$1" == *SideSaddle* || "\$1" == *sidesaddle* || "\$1" == *pdtmj* ]] && return 0
    case "\$(basename "\${1%% *}")" in
        vim|vi|view|nvim|nano|emacs|pico|\\
        less|more|most|man|info|\\
        top|htop|btop|atop|\\
        tmux|screen|fzf|ranger|nnn|mc|\\
        watch|tail) return 0 ;;
    esac
    return 1
}

_ss_preexec() {
    _ss_skip "\$1" && return
    # Write ### marker to stdout — captured by script
    printf '\\n### %s %s\$%s %s\\n' \\
        "\$(date +'%Y-%m-%d %H:%M:%S')" "\${USER}" "\${PWD}" "\$1"
}

autoload -Uz add-zsh-hook
add-zsh-hook preexec _ss_preexec

# ssop — set the active op for this terminal session
# Usage: ssop op1
ssop() {
    [[ -z "\$1" ]] && { echo "Usage: ssop <op_name>"; return 1; }
    export SS_OP="\$1"
    local dir="\${_SS_ROOT}/\${SS_OP}"
    mkdir -p "\${dir}"
    echo "[SideSaddle] Op: \${SS_OP} → \${dir}"
    echo "[SideSaddle] Open a new terminal (or new tmux window) to start logging."
}

# Start script session — only if SS_OP is set and not already in a script session
if [[ -z "\${SCRIPT_LOG_ACTIVE}" && -t 0 ]]; then
    if [[ -n "\${SS_OP:-}" ]]; then
        export SCRIPT_LOG_ACTIVE=1
        _ss_dir="\${_SS_ROOT}/\${SS_OP}"
        mkdir -p "\${_ss_dir}"
        exec script -q -f "\${_ss_dir}/raw_\$(date +%Y%m%d_%H%M%S)_\$\$.log"
    fi
fi
# === end SideSaddle ===
ZSHBLOCK
    echo "[+] Zshrc configured → ${ZSHRC}"
fi

# ── Evil-WinRM alias ──────────────────────────────────────────────────────────

ALIAS_LINE="alias evil-winrm='evil-winrm -s ${EW_SCRIPTS}'"
if grep -qF "alias evil-winrm=" "${ZSHRC}" 2>/dev/null; then
    echo "[~] evil-winrm alias already set — skipping"
else
    echo "" >> "${ZSHRC}"
    echo "# SideSaddle: always load prompt override for target attribution" >> "${ZSHRC}"
    echo "${ALIAS_LINE}" >> "${ZSHRC}"
    echo "[+] evil-winrm alias added"
fi

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "Done. Workflow:"
echo ""
echo "  1. Set your op:        ssop op1"
echo "  2. Open new terminal   (script starts automatically for op1)"
echo "  3. Launch SideSaddle:  python3 SideSaddle.py --op op1"
echo ""
echo "  --op is required. Alternatives:"
echo "    SS_OP=op1 python3 SideSaddle.py   (env var)"
echo "    current_op: op1  in config.yaml   (persistent)"
echo ""
echo "  Logs written to: ${LOG_ROOT}/<op>/raw_*.log"
