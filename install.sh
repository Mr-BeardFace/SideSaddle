#!/usr/bin/env bash
# SideSaddle install script
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_DIR="$HOME/.config/sidesaddle"
CONFIG_FILE="$CONFIG_DIR/config.yaml"

echo "=== SideSaddle Setup ==="

# 1. ZSH theme
if [[ -d "$HOME/.oh-my-zsh/custom/themes" ]]; then
    cp "$SCRIPT_DIR/shell/sidesaddle.zsh-theme" "$HOME/.oh-my-zsh/custom/themes/sidesaddle.zsh-theme"
    echo "✓ Theme installed to ~/.oh-my-zsh/custom/themes/sidesaddle.zsh-theme"
    echo "  → Set ZSH_THEME=\"sidesaddle\" in your ~/.zshrc"
else
    echo "  ⚠ oh-my-zsh not found — install theme manually from $SCRIPT_DIR/shell/sidesaddle.zsh-theme"
fi

# 2. Shell hooks
HOOKS_LINE="source \"$SCRIPT_DIR/shell/sidesaddle-hooks.zsh\""
if grep -qF "sidesaddle-hooks.zsh" "$HOME/.zshrc" 2>/dev/null; then
    echo "✓ Shell hooks already in ~/.zshrc"
else
    echo "" >> "$HOME/.zshrc"
    echo "# SideSaddle shell hooks" >> "$HOME/.zshrc"
    echo "$HOOKS_LINE" >> "$HOME/.zshrc"
    echo "✓ Shell hooks added to ~/.zshrc"
fi

# 3. Config — write to ~/.config/sidesaddle/ (not the project dir)
mkdir -p "$CONFIG_DIR"
if [[ ! -f "$CONFIG_FILE" ]]; then
    cat > "$CONFIG_FILE" <<'EOF'
# SideSaddle config — edit here or use /config inside the tool
# active_provider: anthropic | bedrock | anthropic-sub
active_provider: bedrock

op:
  name: unnamed_op
  # working_directory: ~/ops   # base dir; op subdir created automatically: ~/ops/<name>/
  #                              leave unset to use ~/.local/share/sidesaddle/<name>/

analyst:
  interval: 10
  debounce: 15

bedrock:
  region: us-east-1
  model: us.anthropic.claude-3-5-sonnet-20241022-v2:0
  profile: default

c2:
  enabled: false
  nighthawk:
    url: ""
EOF
    echo "✓ Config created at $CONFIG_FILE"
else
    echo "  → Config already exists at $CONFIG_FILE (not overwritten)"
fi

# 4. Python deps
if command -v pip3 &>/dev/null; then
    echo "Installing Python dependencies..."
    pip3 install -r "$SCRIPT_DIR/requirements.txt" --quiet
    echo "✓ Dependencies installed"
else
    echo "  ⚠ pip3 not found — run: pip install -r requirements.txt"
fi

echo ""
echo "=== Done ==="
echo "Next steps:"
echo "  1. Set ZSH_THEME=\"sidesaddle\" in ~/.zshrc and restart your shell"
echo "  2. Run: python $SCRIPT_DIR/SideSaddle.py run"
echo "  3. Inside the tool: /op new <engagement_name>"
echo "  4. In your shell: ss_op   (starts TTY capture)"
