# bash completion for aptkeyman
_aptkeyman() {
    local cur prev
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    local cmds="download update verify seed scan list show accept deny add fetch export import gui path version help"
    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${cmds}" -- "${cur}") )
        return 0
    fi
    case "${COMP_WORDS[1]}" in
        accept|deny|show|fetch)
            ;;
        export)
            COMPREPLY=( $(compgen -W "-o --output --blobs --db --datadir" -- "${cur}") )
            ;;
        import)
            COMPREPLY=( $(compgen -f -- "${cur}") )
            ;;
        seed)
            COMPREPLY=( $(compgen -W "--apt-update --apt-log --keyrings --db --datadir" -- "${cur}") )
            ;;
        download|update|verify)
            COMPREPLY=( $(compgen -W "--keyrings-dir --sources --dry-run --db --datadir" -- "${cur}") )
            ;;
        *)
            COMPREPLY=( $(compgen -W "--db --datadir --help" -- "${cur}") )
            ;;
    esac
}
complete -F _aptkeyman aptkeyman
