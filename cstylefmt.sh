#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

self="${BASH_SOURCE[0]}"
root=$(dirname "$(readlink -f "${self}")")

cd "${root}"
c_srcs=$(find "${root}/"{lib,cmd,mntd,test} -type f -name "*.c")
h_srcs=$(find "${root}/"{include,lib,cmd,mntd,test} -type f \
  -not -name "fuse_kernel.h" -not -name "config*.h" -name "*.h")

#astylefile_sh="${root}/scripts/astylefile.sh"
#${astylefile_sh} ${h_srcs} ${c_srcs}

clangformat_sh="${root}/scripts/clangformat.sh"
${clangformat_sh} ${c_srcs}

checkcstyle_py="${root}/scripts/checkcstyle.py"
${checkcstyle_py} ${h_srcs} ${c_srcs}
