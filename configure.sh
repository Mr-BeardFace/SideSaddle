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
MARKER="# === SideSaddle session logging v5 ==="

# Remove any older SideSaddle blocks so we can reinstall cleanly
for OLD in "# === SideSaddle session logging ===" \
           "# === SideSaddle session logging v2 ===" \
           "# === SideSaddle session logging v3 ===" \
           "# === SideSaddle session logging v4 ===" \
           "# === SideSaddle session logging v5 ==="; do
    if grep -qF "${OLD}" "${ZSHRC}" 2>/dev/null; then
        sed -i "/^${OLD}/,/^# === end SideSaddle ===/d" "${ZSHRC}"
        echo "[~] Removed old SideSaddle block (${OLD})"
    fi
done

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
    printf '\\n### %s %s\$%s %s\\n' \\
        "\$(date +'%Y-%m-%d %H:%M:%S')" "\${USER}" "\${PWD}" "\$1"
}

autoload -Uz add-zsh-hook
add-zsh-hook preexec _ss_preexec

# Auto-start script session for every interactive terminal
if [[ -z "\${SCRIPT_LOG_ACTIVE}" && -t 0 ]]; then
    export SCRIPT_LOG_ACTIVE=1
    _ss_op="\$(cat "\${HOME}/.config/sidesaddle/current_op" 2>/dev/null)"
    if [[ -n "\${_ss_op}" ]]; then
        _ss_log_dir="\${_SS_ROOT}/\${_ss_op}"
    else
        _ss_log_dir="\${_SS_ROOT}"
    fi
    mkdir -p "\${_ss_log_dir}"
    export _SS_CURRENT_LOG="\${_ss_log_dir}/raw_\$(date +%Y%m%d_%H%M%S)_\$\$.log"
    exec script -q -f "\${_SS_CURRENT_LOG}"
fi
# === end SideSaddle ===
ZSHBLOCK
echo "[+] Zshrc configured → ${ZSHRC}"

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
