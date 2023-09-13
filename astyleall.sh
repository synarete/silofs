#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

self="${BASH_SOURCE[0]}"
root=$(dirname "$(readlink -f "${self}")")
srcs=$(find "${root}/include" "${root}/lib" \
  "${root}/cmd" "${root}/mntd" "${root}/tests" \
  -type f -not -name "fuse_kernel.h" -not -name "configs.h" -name "*.[ch]")

command -v astyle > /dev/null
for src in ${srcs}; do
  astyle -Q \
    --style=1tbs \
    --suffix=none \
    --indent=tab=8 \
    --convert-tabs \
    --align-pointer=name \
    --pad-oper \
    --pad-header \
    --unpad-paren \
    --min-conditional-indent=0 \
    --indent-preprocessor \
    --add-braces \
    --add-one-line-braces \
    --break-after-logical \
    --max-code-length=79 \
    --indent-col1-comments \
    --lineend=linux \
    "${src}"
done

