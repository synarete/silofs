#!/bin/bash -e
self=$(basename "${BASH_SOURCE[0]}")
root=$(readlink -f "$(dirname "${self}")")

astyle1tbs() {
  command -v astyle > /dev/null
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
    "$@"
    # --indent-switches
}

srcs=$(find "${root}/include" "${root}/lib" \
  "${root}/cmd" "${root}/mntd" "${root}/tests" \
  -type f -not -name "fuse7.h" -not -name "configs.h" -name "*.[ch]")
for src in ${srcs}; do
  astyle1tbs "${src}"
done

