#!/usr/bin/env bash
# SideSaddle install / uninstall
# Usage:
#   bash install.sh          — install hooks, alias, theme
#   bash install.sh --clear  — remove everything install.sh added

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
SADDLE_PY="${REPO_DIR}/saddle.py"
HOOKS_ZSH="${SCRIPT_DIR}/sidesaddle-hooks.zsh"
THEME_SRC="${SCRIPT_DIR}/sidesaddle.zsh-theme"
ZSH_RC="${HOME}/.zshrc"
OMZ_THEMES="${HOME}/.oh-my-zsh/themes"

# Lines bracketed by these markers are managed by this script
MARKER_START="# >>> SideSaddle"
MARKER_END="# <<< SideSaddle"

# ── Helpers ───────────────────────────────────────────────────────────────────

remove_block() {
    # Remove the managed block from $ZSH_RC, if present
    if [[ ! -f "$ZSH_RC" ]]; then return; fi
    local tmp
    tmp=$(mktemp)
    awk "
        /^# >>> SideSaddle$/ { skip=1 }
        skip { if (/^# <<< SideSaddle$/) { skip=0 }; next }
        { print }
    " "$ZSH_RC" > "$tmp"
    mv "$tmp" "$ZSH_RC"
}

block_present() {
    grep -qF "$MARKER_START" "$ZSH_RC" 2>/dev/null
}

# ── --clear ───────────────────────────────────────────────────────────────────

if [[ "$1" == "--clear" ]]; then
    echo "SideSaddle: removing install..."
    remove_block
    if [[ -f "${OMZ_THEMES}/sidesaddle.zsh-theme" ]]; then
        rm -f "${OMZ_THEMES}/sidesaddle.zsh-theme"
        echo "  removed oh-my-zsh theme"
    fi
    echo "  removed .zshrc block"
    echo "SideSaddle: uninstalled. Restart your shell or: source ~/.zshrc"
    exit 0
fi

# ── Install ───────────────────────────────────────────────────────────────────

echo "SideSaddle installer"
echo "  repo:    ${REPO_DIR}"
echo "  saddle:  ${SADDLE_PY}"
echo "  hooks:   ${HOOKS_ZSH}"
echo ""

# 1. oh-my-zsh theme
if [[ -d "$OMZ_THEMES" ]]; then
    if [[ -f "$THEME_SRC" ]]; then
        cp "$THEME_SRC" "${OMZ_THEMES}/sidesaddle.zsh-theme"
        echo "  ✓ theme installed → ${OMZ_THEMES}/sidesaddle.zsh-theme"
    else
        echo "  ⚠ theme file not found: ${THEME_SRC}"
    fi
else
    echo "  ⚠ oh-my-zsh not found — install theme manually from ${THEME_SRC}"
fi

# 2. .zshrc block
if block_present; then
    echo "  ↺ .zshrc block already present — updating"
    remove_block
fi

touch "$ZSH_RC"
cat >> "$ZSH_RC" <<EOF

${MARKER_START}
alias saddle='python3 ${SADDLE_PY}'
source '${HOOKS_ZSH}'
${MARKER_END}
EOF

echo "  ✓ alias + hooks added to ${ZSH_RC}"
echo ""
echo "Restart your shell or run:"
echo "  source ~/.zshrc"
echo ""
echo "Then start an op:"
echo "  saddle start --op <name>"
