#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

self="${BASH_SOURCE[0]}"
root=$(dirname "$(readlink -f "${self}")")
astylefile_sh="${root}/scripts/astylefile.sh"
checkcstyle_py="${root}/scripts/checkcstyle.py"

cd "${root}"
srcs=$(find "${root}/include" "${root}/lib" "${root}/src" "${root}/test" \
  -type f -not -name "fuse_kernel.h" -not -name "config*.h" -name "*.[ch]")

${astylefile_sh} ${srcs}
${checkcstyle_py} ${srcs}
