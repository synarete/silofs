#!/bin/sh
for pid_num in $(pidof silofs); do
  echo ${pid_num}
  gdb -p ${pid_num} --quiet --batch -ex "thread apply all bt"
  echo
done
