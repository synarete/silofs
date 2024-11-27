#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail
self="${BASH_SOURCE[0]}"
root=$(dirname "$(readlink -f "${self}")")

# require access to project's root-dir
cd "${root}"

# require 'clang-format' utility
command -v clang-format > /dev/null

# define C source/header configuration files
c_conf="${root}/.clang-format-c"
h_conf="${root}/.clang-format-h"

# find relevant source & header files
c_srcs=$(find "${root}/"{lib,cmd,mntd,test} -type f -name "*.c")
h_srcs=$(find "${root}/"{include,lib,cmd,mntd,test} -type f \
  -not -name "fuse_kernel.h" -not -name "config*.h" -name "*.h")

# do actual code formatting
clang-format -i --style=file:"${c_conf}" ${c_srcs}
clang-format -i --style=file:"${h_conf}" ${h_srcs}

# link-check code style
checkcstyle_py="${root}/scripts/checkcstyle.py"
${checkcstyle_py} ${h_srcs} ${c_srcs}
