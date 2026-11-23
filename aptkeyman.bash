# bash completion for aptkeyman

_aptkeyman()
{
	local cur prev words cword
	_init_completion || return

	if [[ $cur == -* ]]; then
		COMPREPLY=($(compgen -W '--verbose --quiet --help --version' -- "$cur"))
		return
	fi

	_filedir
}

complete -F _aptkeyman aptkeyman
