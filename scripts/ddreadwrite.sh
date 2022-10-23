#!/bin/bash -e

do_dd() {
  local bs=512K
  local count=1024

  dd if="$1" of="$2" bs=${bs} count=${count} conv=fdatasync 2>&1 \
    | grep copied \
    | sed 's/copied//g' \
    | awk '{print $5 $6 $8 $9 $10 $11}' \
    | tr "\(\)," "   "
}

do_readwrite() {
  local dirpath=$(readlink -f "$1")
  local outfile=${dirpath}/$$
  local tmpfile=/dev/shm/$$

  echo -n ${dirpath}": write-from-zero: "
  do_dd /dev/zero ${outfile}.1
  echo -n ${dirpath}": read-write: "
  do_dd ${outfile}.1 ${outfile}.2
  echo -n ${dirpath}": read-to-null: "
  do_dd ${outfile}.2 /dev/null
  echo -n ${dirpath}": copy-to-tmp: "
  do_dd ${outfile}.2 ${tmpfile}
  echo -n ${dirpath}": copy-from-tmp: "
  do_dd ${tmpfile} ${outfile}.3
  unlink ${outfile}.1
  unlink ${outfile}.2
  unlink ${outfile}.3
  unlink ${tmpfile}
}

for d in "$@"; do do_readwrite $d ; done

