#!/usr/bin/env bash
export LC_ALL=C
unset CDPATH
PATH=/opt/coverity/bin/:${PATH}

selfdir="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
rootdir="$(realpath "${selfdir}"/../)"
builddir="${rootdir}/build"
covdir="${builddir}/cov"
covhtml="${builddir}/cov/html"
source "${rootdir}/bash_functions"

commandv cov-build cov-analyze cov-format-errors
cdx "${rootdir}"
run ./bootstrap --autoclean
run ./bootstrap --autogen
run mkdir -p "${covhtml}"
cdx "${builddir}"
run ../configure --disable-shared
run cov-build --dir "${covdir}" make
run cov-analyze --dir "${covdir}"
run cov-format-errors --dir "${covdir}" --html-output "${covhtml}"
