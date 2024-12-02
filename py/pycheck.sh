#!/usr/bin/env bash
set -o nounset
set -o pipefail
export LC_ALL=C
unset CDPATH

self=$(basename "${BASH_SOURCE[0]}")
selfdir=$(realpath "$(dirname "${BASH_SOURCE[0]}")")
basedir=$(realpath "${selfdir}")
verbose="${VERBOSE:-1}"

msg() { echo "$self: $*" >&2; }
die() { msg "$*"; kill -s 2 $$; }
exe() { ( "$@" ) || die "failed: $*"; }
log() { if [ "${verbose}" == "1" ]; then msg "$@" ; fi; }
run() { log "$@" ; exe "$@"; }
cdx() { log "cd $*"; cd "$@" || die "failed: cd $*"; }

run_command() {
  command -v "$1" > /dev/null && run "$@"
}

run_black() {
  local srcdir="${1}"

  cdx "${srcdir}"
  run_command black -q -l 79 "${srcdir}"
}

run_flake8() {
  local srcdir="${1}"

  cdx "${srcdir}/../"
  run_command flake8 "${srcdir}"
}

run_mypy() {
  local srcdir="${1}"

  cdx "${srcdir}"
  run_command mypy --no-color-output "${srcdir}" | grep -v "Success: "
}

run_pylint() {
  local srcdir="${1}"

  cdx "${srcdir}"
  export PYLINTHOME="${basedir}"
  run_command pylint --rcfile="${basedir}/pylintrc" "${srcdir}"
}

run_pychecks() {
  cdx "${basedir}"
  run_black "${1}"
  run_flake8 "${1}"
  run_mypy "${1}"
  run_pylint "${1}"
}

main() {
  local srcdir
  local curdir

  curdir="$(pwd)"
  for arg in "$@"; do
    srcdir="$(realpath "$(readlink -f "${arg}")")"
    run_pychecks "${srcdir}"
    cdx "${curdir}"
  done
}

main "$@"
exit 0
