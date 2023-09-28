#!/bin/bash -e

_clang_tidy_check_list() {
  clang-tidy --list-checks -checks='*' | \
    grep -Ev 'Enabled checks' | \
    grep -Ev '(abseil|android|boost|cplusplus|osx|optin)' | \
    grep -Ev '(fuchsia|objc|zircon|security|altera)' | \
    grep -Ev '(magic-numbers|hicpp-signed-bitwise|llvm-include-order)' | \
    grep -Ev '(cppcoreguidelines-init-variables)' | \
    grep -Ev '(lvmlibc-restrict-system-libc-headers)' | \
    grep -Ev '(Uninitialized|DeprecatedOrUnsafeBufferHandling)' | \
    grep -Ev 'readability-identifier-length' | \
    grep -Ev 'bugprone-easily-swappable-parameters' | \
    grep -Ev 'performance-no-int-to-ptr' | \
    grep -Ev 'readability-suspicious-call-argument' | \
    awk '{print $1}' | \
    tr "\n" " "
}

_clang_tidy_check() {
  basedir=$(realpath "$(dirname "${BASH_SOURCE[0]}")/../")
  srcs=$(find "${basedir}" -type f -name '*.c')
  chks=$(_clang_tidy_check_list | tr " " ",")
  idefs="-I${basedir}/include -I${basedir}/lib -I${basedir}/build/include"
  xdefs="-DSILOFS_HAVE_PRIVATE=1 -DSILOFS_UNITEST=1"

  clang-tidy ${srcs} -checks='-*',${chks} -- "${idefs}" "${xdefs}"
}

_clang_tidy_version() {
  type clang-tidy
  clang-tidy -version
}

_clang_tidy_version
_clang_tidy_check


