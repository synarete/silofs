#!/bin/bash -e
root=$(readlink -f "$(dirname "${BASH_SOURCE[0]}")/..")
srcs=$(find "${root}/include" "${root}/lib" "${root}/src" "${root}/test" \
  -type f -not -name "fuse_kernel.h" -not -name "config*.h" -name "*.[ch]")

cd "${root}"
command -v clang-format > /dev/null
clang-format -i -style=file ${srcs}
