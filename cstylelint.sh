#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

self="${BASH_SOURCE[0]}"
root=$(dirname "$(readlink -f "${self}")")
checkcstyle_py="${root}"/scripts/checkcstyle.py

srcs=$(find "${root}/include" "${root}/lib" \
  "${root}/cmd" "${root}/mntd" "${root}/tests" \
  -type f -not -name "fuse_kernel.h" -not -name "configs.h" -name "*.[ch]")
${checkcstyle_py} ${srcs}
