#!/usr/bin/env bash
self=$(basename "${BASH_SOURCE[0]}")
selfdir=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
basedir=$(realpath "${1:-$selfdir}")
srcdir="${basedir}"

_msg() { echo "$self: $*" >&2; }
_die() { _msg "$*"; exit 1; }
_try() { ( "$@" ) || _die "failed: $*"; }
_run() { if [ "${VERBOSE:-1}" == "1" ]; then _msg "$@" ; fi; _try "$@"; }

export LC_ALL=C
unset CDPATH


_run_command() {
  command -v "$1" > /dev/null && _run "$@"
}

_run_black() {
  _run_command black -q -l 79 "${srcdir}"
}

_run_flake8() {
  _run_command flake8 "${srcdir}"
}

_run_mypy() {
  _run_command mypy --no-color-output "${srcdir}" | grep -v "Success: "
}

_run_pylint() {
  _run_command pylint --rcfile="${basedir}/pylintrc" "${srcdir}"
}

_main() {
  cd "${srcdir}/../" || exit 1
  _run_black
  _run_flake8
  _run_mypy
  _run_pylint
}

_main
exit 0
