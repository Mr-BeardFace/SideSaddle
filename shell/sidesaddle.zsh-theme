# SideSaddle ZSH theme
# Based on the operator's existing theme — adds full datetime timestamp, removes RPROMPT date.
# Install: cp sidesaddle.zsh-theme ~/.oh-my-zsh/custom/themes/
#          Set ZSH_THEME="sidesaddle" in ~/.zshrc

function prompt_char {
    if [ $UID -eq 0 ]; then echo "#"; else echo $; fi
}

# Full datetime replaces %T (time-only). Format: [2026-10-09 21:19:06]
PROMPT='$(git_prompt_info)%F{white}[%F{green}%B%D{%Y-%m-%d %H:%M:%S}%b%F{white}][%F{red}%B%n@%m%b%f%F{white}]:%F{cyan}%B%~%b%F{white}$(prompt_char) '

# Date removed from RPROMPT — it's now in the left prompt
RPROMPT=''

ZSH_THEME_GIT_PROMPT_PREFIX="%{$fg_bold[blue]%}git:(%{$fg[red]%}"
ZSH_THEME_GIT_PROMPT_SUFFIX="%{$reset_color%}"
ZSH_THEME_GIT_PROMPT_DIRTY="%{$fg[blue]%}) %{$fg[yellow]%}✗ "
ZSH_THEME_GIT_PROMPT_CLEAN="%{$fg[blue]%}) "
