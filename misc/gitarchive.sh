#!/bin/bash
self=$(basename ${BASH_SOURCE[0]})
msg() { echo "$self: $*" >&2; }
die() { msg "$*"; exit 1; }
try() { ( "$@" ) || die "failed: $*"; }
run() { echo "$@" >&2; try "$@"; }

basedir=$(realpath $(dirname ${BASH_SOURCE[0]})/../)
version=$(${basedir}/version.sh -v)
name=silofs-${version}
outdir=${basedir}/build
output=${outdir}/${name}.tar.gz

try mkdir -p ${outdir}
try ls ${basedir}/.git > /dev/null
cd ${basedir}
try git status HEAD > /dev/null
run git archive \
  --format=tar.gz \
  --output=${output} \
  --prefix=${name}/ \
  HEAD
