#!/bin/bash
self=$(basename "${BASH_SOURCE[0]}")
msg() { echo "$self: $*" >&2; }
die() { msg "$*"; exit 1; }
try() { ( "$@" ) || die "failed: $*"; }
run() { echo "$self: $@" >&2; try "$@"; }

run command -v fsstress
run fsstress -r 32 -p 4 -v -n 10000 -c \
  -f rmdir=1000 \
  -f link=1000 \
  -f creat=1000 \
  -f mkdir=1000 \
  -f rename=1000 \
  -f stat=1000 \
  -f unlink=1000 \
  -f truncate=100 \
  -f readlink=100 \
  -f fallocate=100 \
  -f getattr=100 \
  -f getdents=100 \
  -f write=10000 \
  -f writev=1000 \
  -f read=10000 \
  -f readv=1000 \
  -d "$@"

