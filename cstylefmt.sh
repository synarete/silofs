#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

self="${BASH_SOURCE[0]}"
root=$(dirname "$(readlink -f "${self}")")
astylefiles_sh="${root}/scripts/astylefiles.sh"
checkcstyle_py="${root}/scripts/checkcstyle.py"

cd "${root}"
srcs=$(find "${root}/include" "${root}/src" \
  -type f -not -name "fuse_kernel.h" -not -name "configs.h" -name "*.[ch]")

${astylefiles_sh} ${srcs}
${checkcstyle_py} ${srcs}


