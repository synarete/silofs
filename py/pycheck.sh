#!/usr/bin/env bash
self=$(basename "${BASH_SOURCE[0]}")
selfdir=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
basedir=$(realpath "${selfdir}")

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
  local srcdir="${1}"

  cd "${srcdir}" || exit 1
  _run_command black -q -l 79 "${srcdir}"
}

_run_flake8() {
  local srcdir="${1}"

  cd "${srcdir}/../" || exit 1
  _run_command flake8 "${srcdir}"
}

_run_mypy() {
  local srcdir="${1}"

  cd "${srcdir}" || exit 1
  _run_command mypy --no-color-output "${srcdir}" | grep -v "Success: "
}

_run_pylint() {
  local srcdir="${1}"

  cd "${srcdir}" || exit 1
  _run_command pylint --rcfile="${basedir}/pylintrc" "${srcdir}"
}

_run_pychecks() {
  local srcdir

  _run_black "${1}"
  _run_flake8 "${1}"
  _run_mypy "${1}"
  _run_pylint "${1}"
}

_main() {
  local srcdir

  for arg in "$@"; do
    srcdir="$(realpath "$(readlink -f "${arg}")")"

    cd "${basedir}" || exit 1
    _run_pychecks "${srcdir}"
  done
}

_main "$@"
exit 0
