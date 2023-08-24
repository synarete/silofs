#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

self=$(basename "${BASH_SOURCE[0]}")
root=$(readlink -f "$(dirname "${self}")")
checkcstyle_py="${root}"/scripts/checkcstyle.py

srcs=$(find "${root}/include" "${root}/lib" \
  "${root}/cmd" "${root}/mntd" "${root}/tests" \
  -type f -not -name "fuse_kernel.h" -not -name "configs.h" -name "*.[ch]")
${checkcstyle_py} ${srcs}
