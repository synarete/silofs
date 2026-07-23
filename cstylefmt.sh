#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail
self="${BASH_SOURCE[0]}"
root=$(dirname "$(readlink -f "${self}")")

# require access to project's root-dir
cd "${root}"

# require 'clang-format' utility
command -v clang-format > /dev/null

# define C source/header configuration YAML files
conf="${root}/.clang-format.yaml"
conf_h="${root}/.clang-format-h.yaml"

# find relevant source & header files
mapfile -t c_srcs < <(find "${root}/"{lib,cmd,mntd,test} -type f -name "*.c")
mapfile -t h_srcs < <(find "${root}/"{include,lib,cmd,mntd,test} -type f \
	      -not -name "fuse_abi.h" -not -name "config*.h" -name "*.h")

# do actual code formatting
_do_clang_format() {
	clang-format -i --style=file:"${conf}" "${c_srcs[@]}"
	clang-format -i --style=file:"${conf_h}" "${h_srcs[@]}"
}

# lint-check code style via python helper script
_do_lint_check() {
	cstylelint_py="${root}/scripts/cstylelint.py"
	${cstylelint_py} "${h_srcs[@]}" "${c_srcs[@]}"
}

arg=${1:-}
case "$arg" in
	-h|--help)
		echo "${self} [--all | --format | --lint ]"
		;;
	-a|--all)
		_do_clang_format
		_do_lint_check
		;;
	-l|--lint)
		_do_lint_check
		;;
	-f|--format|*)
		_do_clang_format
		;;
esac
