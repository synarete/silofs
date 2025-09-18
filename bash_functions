# shellcheck shell=bash

_LINENO_DEPTH=0

inc_lineno_depth() {
	_LINENO_DEPTH=$((_LINENO_DEPTH + 1))
}

dec_lineno_depth() {
	_LINENO_DEPTH=$((_LINENO_DEPTH - 1))
}

_base_source() {
	local idx=$((${#BASH_SOURCE[@]} - 1))
	local src="${BASH_SOURCE[$idx]}"

	echo -n "$(basename "${src}")"
}

_base_lineno() {
	local idx=$((${#BASH_LINENO[@]} - 2 - _LINENO_DEPTH))
	local lno="${BASH_LINENO[$idx]}"

	echo -n "${lno}"
}

_base_tag() {
	echo -n "$(_base_source):$(_base_lineno)"
}

msg() {
	local verbose="${VERBOSE:-1}"

	if [ "${verbose}" == "1" ]; then
		echo "$(_base_tag): $*" >&2
	fi
}

die() {
	msg "$*"
	exit 1
}

run() {
	msg "$*"
	( "$@" ) || die "failed: $*"
}

cdx() {
	msg "cd $*"
	cd "$@" || die "failed: cd $*"
}

commandv() {
	for cmd in "$@"; do
		run command -v "${cmd}"
	done
}
