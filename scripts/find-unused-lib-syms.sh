#!/usr/bin/env bash
# List symbols exported by libsilofs but not consumed by any other program.
set -o errexit
set -o nounset
set -o pipefail
export LC_ALL=C
unset CDPATH

selfdir="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"
rootdir="$(readlink -f "${selfdir}/../")"
builddir="${rootdir}/build"

source "${rootdir}/bash_functions"

_require_cmd() {
	local cmd="$1"
	command -v nm ${cmd} > /dev/null 2>&1 || die "${cmd} is missing"
}

_require_cmds() {
	_require_cmd nm
	_require_cmd comm
	_require_cmd awk
	_require_cmd grep
}

_find_libsilofs_a() {
	find "${builddir}" -name 'libsilofs.a' -type f | head -1
}

_exported_syms() {
	local lib="$1"

	nm --defined-only --extern-only "${lib}" \
		| awk '/^[0-9a-f]/ { print $3 }' \
		| sort -u
}

_find_prog_objs() {
	find "${builddir}" -name '*.o' -not -path '*/lib/*' -print0
}

_find_lib_objs() {
	find "${builddir}" -name '*.o' -path '*/lib/*' -print0
}

_consumed_syms() {
	{ _find_prog_objs | xargs -0 nm --undefined-only;
	  _find_lib_objs  | xargs -0 nm --undefined-only; } \
		| awk '/^ *U / { print $2 }' \
		| sort -u
}

_called_in_src() {
	local sym="$1"
	local count
	count=$(grep -r --include='*.c' -h \
		"${sym}" \
		"${rootdir}/lib" "${rootdir}/cmd" \
		"${rootdir}/mntd" "${rootdir}/test" \
		2>/dev/null | wc -l)
	[[ "${count}" -gt 1 ]]
}

_filter_src_unused() {
	while read -r sym; do
		_called_in_src "${sym}" || echo "${sym}"
	done
}

_unused_syms() {
	local lib="$1"

	comm -23 <(_exported_syms "${lib}") <(_consumed_syms) \
		| _filter_src_unused
}

_locate_lib_archive() {
	local lib
	lib="$(_find_libsilofs_a)"

	[[ -n "${lib}" ]] || die "libsilofs.a not found under ${builddir}"
	echo "${lib}"
}

_report_unused_syms() {
	local lib="$1"
	local unused

	unused="$(_unused_syms "${lib}")"
	echo "${unused}"
}

# main:
_require_cmds
_report_unused_syms "$(_locate_lib_archive)"
