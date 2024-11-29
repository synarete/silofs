#!/usr/bin/env bash
self=$(basename "${BASH_SOURCE[0]}")
msg() { echo "$self: $*" >&2; }
die() { msg "$*"; exit 1; }
try() { ( "$@" ) || die "failed: $*"; }
run() { echo "$self: $*" >&2; try "$@"; }

export LC_ALL=C
unset CDPATH

arg1dir=${1:-$(pwd)}
cicddir=$(realpath -P "${arg1dir}")
[ -d "${cicddir}" ] || exit

# Kill any catatonic process still using cicddir
catatonit_pids=("$(pgrep -f catatonit)")
for pid in ${catatonit_pids[@]}; do
  catatonit_cwd="$(readlink -e "/proc/${pid}/cwd")"
  if grep -q "${catatonit_cwd}" <<< "${cicddir}"; then
    run sleep 2
    run kill "${pid}"
  fi
done
