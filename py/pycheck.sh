#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail
export LC_ALL=C
unset CDPATH

selfdir="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
rootdir="$(realpath "${selfdir}"/../)"
basedir="$(realpath "${selfdir}")"
source "${rootdir}/bash_functions"


run_black() {
  if command -v black &> /dev/null ; then
    cdx "${1}"
    run black -q -l 79 "${1}"
  fi
}

run_flake8() {
  if command -v flake8 &> /dev/null ; then
    cdx "${1}/../"
    run flake8 "${1}"
  fi
}

run_pylint() {
  if command -v pylint &> /dev/null ; then
    cdx "${1}"
    export PYLINTHOME="${basedir}"
    run pylint --rcfile="${basedir}/pylintrc" "${1}"
  fi
}

run_mypy() {
  if command -v mypy &> /dev/null ; then
    cdx "${1}"
    run mypy --no-color-output "${1}"
  fi
}

run_pychecks() {
  local with_mypy="${WITH_MYPY:-1}"

  cdx "${basedir}"
  run_black "${1}"
  run_flake8 "${1}"
  run_pylint "${1}"
  if [ "${with_mypy}" == "1" ]; then
    run_mypy "${1}"
  fi
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
