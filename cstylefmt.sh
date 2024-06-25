#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

self="${BASH_SOURCE[0]}"
root=$(dirname "$(readlink -f "${self}")")
astylefile_sh="${root}/scripts/astylefile.sh"
clangformat_sh="${root}/scripts/clangformat.sh"
checkcstyle_py="${root}/scripts/checkcstyle.py"

cd "${root}"
c_srcs=$(find "${root}/lib" "${root}/src" "${root}/test" -name "*.c")
h_srcs=$(find "${root}/include" "${root}/lib" "${root}/src" "${root}/test" \
  -type f -not -name "fuse_kernel.h" -not -name "config*.h" -name "*.h")

${astylefile_sh} ${h_srcs} ${c_srcs}
#${clangformat_sh} ${c_srcs}
${checkcstyle_py} ${h_srcs} ${c_srcs}
