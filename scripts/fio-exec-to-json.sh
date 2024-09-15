#!/usr/bin/env bash
#
# usage: RUNTIME=<30|60|90..> fio-exec.sh <test-dir>
#
self=$(basename "${BASH_SOURCE[0]}")
msg() { echo "$self: $*" >&2; }
die() { msg "$*"; exit 1; }
try() { ( "$@" ) || die "failed: $*"; }
run() { echo "$self: $*" >&2; try "$@"; }

export LC_ALL=C
unset CDPATH


KILO=1024
MEGA=$((KILO * KILO))
GIGA=$((MEGA * KILO))
DATASIZE=${GIGA}
RUNTIME=${RUNTIME:-30}
RWMIX=${RWMIX:-50}
RW=${RW:-readwrite}

# TODO: echo 1 > /sys/block/<dev>/queue/iostats

_fio_to_json() {
  local testdir=$1
  local jobs=$2
  local bs=$3
  local base
  local name
  local jout

  base=$(basename "${testdir}")
  name="${base}-${bs}k-${jobs}j"
  jout="${name}.json"

  run fio \
      --name="${name}" \
      --directory="${testdir}" \
      --numjobs="${jobs}" \
      --bs=$((bs * 1024)) \
      --size="${DATASIZE}" \
      --fallocate=none \
      --rw="${RW}" \
      --rwmixwrite="${RWMIX}" \
      --ioengine=pvsync2 \
      --sync=0 \
      --direct=0 \
      --time_based \
      --runtime="${RUNTIME}" \
      --thinktime=0 \
      --norandommap \
      --group_reporting \
      --randrepeat=1 \
      --unlink=1 \
      --fsync_on_close=0 \
      --output-format=json > "${jout}" ;
}

_fio_execat() {
  local testdir="$1"
  local jobs=(1 2 4 8)
  local bss=(64 256)

  for job in "${jobs[@]}"; do
    for bs in "${bss[@]}"; do
      _fio_to_json "${testdir}" "${job}" "${bs}"
    done
  done
}

# main
_fio_exec_main() {
  local testdir

  for td in "$@"; do
    testdir="$(realpath "${td}")"
    if [[ -d "${testdir}" ]]; then
      _fio_execat "${testdir}"
    fi
  done
}

_fio_exec_main "$@"
