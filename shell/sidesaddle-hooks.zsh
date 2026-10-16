# SideSaddle shell hooks
# Source this from ~/.zshrc or place in ~/.oh-my-zsh/custom/
#
# TUI mode:   SideSaddle writes the active log dir to .active_log_dir on start.
# Daemon mode: `saddle start --op <name>` spawns a headless daemon.
#              RPROMPT shows the current badge (frontier advance / OPSEC / notable lead).
#
# Both modes share command logging and SSH/evil-winrm capture.

autoload -Uz add-zsh-hook

_SS_STATE_FILE="${HOME}/.local/share/sidesaddle/.active_log_dir"
_SS_BASE="${HOME}/.local/share/sidesaddle"
# Resolve the hooks directory at source time; repo root is one level up
_SS_HOOKS_DIR="${${(%):-%x}:A:h}"
_SS_REPO_DIR="${_SS_HOOKS_DIR:h}"

# Auto-detect Python: prefer repo venv, then any active venv, then system python3
_ss_python() {
    if [[ -x "${_SS_REPO_DIR}/.venv/bin/python3" ]]; then
        echo "${_SS_REPO_DIR}/.venv/bin/python3"
    elif [[ -n "$VIRTUAL_ENV" && -x "${VIRTUAL_ENV}/bin/python3" ]]; then
        echo "${VIRTUAL_ENV}/bin/python3"
    else
        echo "python3"
    fi
}
saddle() { "$(_ss_python)" "${_SS_REPO_DIR}/saddle.py" "$@"; }

_ss_log_dir() {
    [[ -f "$_SS_STATE_FILE" ]] && cat "$_SS_STATE_FILE"
}

_ss_op_dir() {
    local log_dir
    log_dir=$(_ss_log_dir)
    [[ -z "$log_dir" ]] && return
    # log_dir = <op_dir>/logs  →  op_dir = parent
    echo "${log_dir%/logs}"
}

# ── Command logging via preexec ───────────────────────────────────────────────

_ss_preexec() {
    local log_dir
    log_dir=$(_ss_log_dir)
    [[ -z "$log_dir" ]] && return
    # Don't log saddle commands — they're operator tooling, not engagement activity
    [[ "$1" == saddle* ]] && return
    mkdir -p "$log_dir"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${ts}] ${1}" >> "${log_dir}/cmd_$(date +%Y%m%d).log"
}

add-zsh-hook preexec _ss_preexec

# ── RPROMPT badge from daemon ─────────────────────────────────────────────────

_ss_precmd() {
    local op_dir badge_file _ss_badge _ss_badge_type
    op_dir=$(_ss_op_dir)
    [[ -z "$op_dir" ]] && return
    badge_file="${op_dir}/.badge"
    if [[ ! -f "$badge_file" ]]; then
        RPROMPT=""
        return
    fi
    # .badge: line 1 = badge text, line 2 = badge_type
    { read -r _ss_badge; read -r _ss_badge_type } < "$badge_file"
    if [[ -n "$_ss_badge" ]]; then
        case "$_ss_badge_type" in
            frontier)     RPROMPT="%F{green}[${_ss_badge}]%f" ;;
            notable_lead) RPROMPT="%F{cyan}[lead]%f" ;;
            opsec)        RPROMPT="%F{red}[${_ss_badge}]%f" ;;
            *)            RPROMPT="%F{yellow}[${_ss_badge}]%f" ;;
        esac
    else
        RPROMPT=""
    fi
}

add-zsh-hook precmd _ss_precmd

# ── Session registration with daemon ─────────────────────────────────────────
# Register this shell if a daemon is already running for the active op.
# `saddle start` registers the calling shell directly; this covers additional
# terminals opened after the daemon is already up.

_ss_auto_register() {
    local op_dir
    op_dir=$(_ss_op_dir)
    [[ -z "$op_dir" ]] && return
    [[ -S "${op_dir}/.daemon.sock" ]] || return
    saddle register $$ 2>/dev/null
}
_ss_auto_register

# Unregister on shell exit
_ss_exit_hook() {
    saddle unregister $$ 2>/dev/null
}
trap '_ss_exit_hook' EXIT

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
    local log_dir
    log_dir=$(_ss_log_dir)
    if [[ -z "$log_dir" ]]; then
        echo "SideSaddle: no active op found."
        echo "  TUI mode: start SideSaddle and set an op (/op new <name>)."
        echo "  Daemon mode: saddle start --op <name>"
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

# ── Auto-start TTY capture (TUI mode only) ───────────────────────────────────
# Skipped when a daemon socket is present — daemon mode doesn't need ss_op auto-start.

if [[ -z "$_SS_IN_SCRIPT" ]]; then
    _ss_auto_log=$(_ss_log_dir)
    _ss_auto_op_dir=$(_ss_op_dir)
    if [[ -n "$_ss_auto_log" && ! -S "${_ss_auto_op_dir}/.daemon.sock" ]]; then
        ss_op
    fi
    unset _ss_auto_log _ss_auto_op_dir
fi
