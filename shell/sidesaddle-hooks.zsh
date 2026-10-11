# SideSaddle shell hooks
# Source this from ~/.zshrc or place in ~/.oh-my-zsh/custom/
#
# SideSaddle writes your active op's log directory to:
#   ~/.local/share/sidesaddle/.active_log_dir
# when it starts and whenever you switch ops (/op new <name>).
# These hooks read that file automatically — no manual setup needed.
#
# Start SideSaddle, set your op, then run ss_op to begin TTY capture.

autoload -Uz add-zsh-hook

_SS_STATE_FILE="${HOME}/.local/share/sidesaddle/.active_log_dir"
# Resolve the hooks directory at source time — ${0:A:h} is wrong when sourced from .zshrc
_SS_HOOKS_DIR="${${(%):-%x}:A:h}"

_ss_log_dir() {
    # Returns the active log dir, or empty if SideSaddle isn't running an op
    [[ -f "$_SS_STATE_FILE" ]] && cat "$_SS_STATE_FILE"
}

# ── Command logging via preexec ───────────────────────────────────────────────

_ss_preexec() {
    local log_dir
    log_dir=$(_ss_log_dir)
    [[ -z "$log_dir" ]] && return
    mkdir -p "$log_dir"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${ts}] ${1}" >> "${log_dir}/cmd_$(date +%Y%m%d).log"
}

add-zsh-hook preexec _ss_preexec

# ── SSH wrapper: capture full interactive session ─────────────────────────────

ssh() {
    local log_dir
    log_dir=$(_ss_log_dir)
    if [[ -z "$log_dir" ]]; then
        command ssh "$@"
        return
    fi
    mkdir -p "$log_dir"
    local host="unknown"
    for arg in "$@"; do
        [[ "$arg" != -* ]] && host="$arg"
    done
    host="${host//[^a-zA-Z0-9._-]/_}"
    local ts=$(date +%Y%m%d_%H%M%S)
    local raw_log="${log_dir}/ssh_${host}_${ts}.raw"
    local ts_log="${log_dir}/ssh_${host}_${ts}.log"
    local proc="${_SS_HOOKS_DIR}/log_processor.py"
    if [[ -f "$proc" ]]; then
        python3 -u "$proc" --watch "$raw_log" --out "$ts_log" &
        local proc_pid=$!
        script -q -f -e -c "command ssh $*" "$raw_log"
        kill $proc_pid 2>/dev/null
    else
        script -q -f -e -c "command ssh $*" "$raw_log"
    fi
    rm -f "$raw_log"
}

# ── evil-winrm wrapper: prepend timestamps to output ─────────────────────────

evil-winrm() {
    local log_dir
    log_dir=$(_ss_log_dir)
    if [[ -z "$log_dir" ]]; then
        command evil-winrm "$@"
        return
    fi
    mkdir -p "$log_dir"
    local logfile="${log_dir}/evilwinrm_$(date +%Y%m%d_%H%M%S).log"
    command evil-winrm "$@" --log "$logfile" 2>&1 | \
        python3 -u "${_SS_HOOKS_DIR}/log_processor.py" --stdin "${logfile}.log"
}

# ── ss_op: start TTY capture for the active op ───────────────────────────────

ss_op() {
    # No arguments needed. Reads the active op from SideSaddle's state file.
    # Start SideSaddle and set your op (/op new <name>) first.
    local log_dir
    log_dir=$(_ss_log_dir)
    if [[ -z "$log_dir" ]]; then
        echo "SideSaddle: no active op found."
        echo "  Start SideSaddle and set an op first (/op new <name>)."
        return 1
    fi
    mkdir -p "$log_dir"
    local ts=$(date +%Y%m%d_%H%M%S)
    local raw_log="${log_dir}/tty_${ts}.raw"
    local ts_log="${log_dir}/tty_${ts}.log"
    local proc="${_SS_HOOKS_DIR}/log_processor.py"
    echo "SideSaddle: capturing TTY to ${ts_log}"
    export _SS_IN_SCRIPT=1
    if [[ -f "$proc" ]]; then
        python3 -u "$proc" --watch "$raw_log" --out "$ts_log" &
        local proc_pid=$!
        script -q -f "$raw_log"
        kill $proc_pid 2>/dev/null
    else
        script -q -f "$raw_log"
    fi
    rm -f "$raw_log"
    unset _SS_IN_SCRIPT
}

# ── Auto-start: begin TTY capture when a terminal opens with an active op ────

if [[ -z "$_SS_IN_SCRIPT" ]]; then
    _ss_auto_log=$(_ss_log_dir)
    if [[ -n "$_ss_auto_log" ]]; then
        ss_op
    fi
    unset _ss_auto_log
fi
