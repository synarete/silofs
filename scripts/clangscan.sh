#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail
export LC_ALL=C
unset CDPATH

selfdir=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
basedir=$(realpath "${selfdir}"/../)
rootdir=${1:-"${basedir}"}
outdir="${rootdir}"/build/html

source "${rootdir}/bash_functions"

_clang_scan_enabled_checkers_args() {
	clang -cc1 -analyzer-checker-help \
		| awk '/^  [A-Za-z0-9_.]+/{print $1}' \
		| grep -Ev '^(osx|fuchsia|cplusplus|optin|strcpy|webkit)' \
		| grep -Ev '^(alpha|experimental|debug)' \
		| grep -Ev 'DeprecatedOrUnsafeBufferHandling' \
		| grep -Ev 'valist\.Uninitialized' \
		| grep -Ev 'security\.VAList' \
		| sed '/^$/d' \
		| awk '{print " -enable-checker "$1""} '
}

_clang_requires() {
	commandv clang clang++ scan-build
}

_clang_scan_env() {
	CCC_CC="$(command -v clang)"
	CCC_CXX="$(command -v clang++)"
	CCC_ANALYZER_CPLUSPLUS=1
	export CCC_CC CCC_CXX CCC_ANALYZER_CPLUSPLUS
}

_clang_scan_build() {
	local topdir="$1"
	local builddir="${topdir}/build"
	local outdir="${builddir}/html"

	cd "${topdir}"
	mkdir -p "${outdir}"

	cd "${builddir}"
	_clang_scan_env

	run scan-build \
		--use-cc="${CCC_CC}" \
		--use-c++="${CCC_CXX}" \
		"${topdir}/configure" \
		--enable-debug=no \
		CFLAGS='-O2 -pthread'

	run scan-build \
		--use-cc="${CCC_CC}" \
		--use-c++="${CCC_CXX}" \
		-maxloop 32 -k -v -o "${outdir}" \
		$(_clang_scan_enabled_checkers_args) \
		make all
}

_rebootstrap() {
	run "${rootdir}"/bootstrap -r
}


# main:
cd "${rootdir}"
_clang_requires
_rebootstrap "${rootdir}"
_clang_scan_build "${rootdir}"

# expect scan-build to remove all outputs
exit_code=$(find "${outdir}" -mindepth 1 -type d | wc -l)
exit "${exit_code}"
