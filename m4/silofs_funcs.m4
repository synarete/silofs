
AC_DEFUN([AX_SILOFS_CHECK_FUNCS],
[
  AC_CHECK_FUNCS([$1], :,
    AC_MSG_ERROR([Unable to find function $1]))
])

AC_DEFUN([AX_SILOFS_NEED_FUNCS],
[
  AC_FUNC_ERROR_AT_LINE
  AC_FUNC_MALLOC
  AC_FUNC_MMAP
  AC_FUNC_FORK
  AC_FUNC_GETGROUPS
  AC_FUNC_STRERROR_R
  AC_FUNC_MEMCMP
  AC_FUNC_STAT
  AC_FUNC_VPRINTF
])

AC_DEFUN([AX_SILOFS_NEED_FUNCS2],
[
  AX_SILOFS_CHECK_FUNCS([atexit])
  AX_SILOFS_CHECK_FUNCS([canonicalize_file_name])
  AX_SILOFS_CHECK_FUNCS([copy_file_range])
  AX_SILOFS_CHECK_FUNCS([endpwent])
  AX_SILOFS_CHECK_FUNCS([fcntl])
  AX_SILOFS_CHECK_FUNCS([futimens])
  AX_SILOFS_CHECK_FUNCS([getentropy])
  AX_SILOFS_CHECK_FUNCS([getgrent])
  AX_SILOFS_CHECK_FUNCS([getgrnam])
  AX_SILOFS_CHECK_FUNCS([getgrnam_r])
  AX_SILOFS_CHECK_FUNCS([getgrouplist])
  AX_SILOFS_CHECK_FUNCS([getgroups])
  AX_SILOFS_CHECK_FUNCS([getline])
  AX_SILOFS_CHECK_FUNCS([getlogin])
  AX_SILOFS_CHECK_FUNCS([getlogin_r])
  AX_SILOFS_CHECK_FUNCS([get_nprocs_conf])
  AX_SILOFS_CHECK_FUNCS([getpwnam])
  AX_SILOFS_CHECK_FUNCS([getpwnam_r])
  AX_SILOFS_CHECK_FUNCS([getsubopt])
  AX_SILOFS_CHECK_FUNCS([gettimeofday])
  AX_SILOFS_CHECK_FUNCS([ioctl])
  AX_SILOFS_CHECK_FUNCS([isascii])
  AX_SILOFS_CHECK_FUNCS([iswprint])
  AX_SILOFS_CHECK_FUNCS([localtime_r])
  AX_SILOFS_CHECK_FUNCS([lseek64])
  AX_SILOFS_CHECK_FUNCS([memchr])
  AX_SILOFS_CHECK_FUNCS([memfd_create])
  AX_SILOFS_CHECK_FUNCS([memmem])
  AX_SILOFS_CHECK_FUNCS([memmove])
  AX_SILOFS_CHECK_FUNCS([memset])
  AX_SILOFS_CHECK_FUNCS([mount])
  AX_SILOFS_CHECK_FUNCS([munmap])
  AX_SILOFS_CHECK_FUNCS([pathconf])
  AX_SILOFS_CHECK_FUNCS([pipe2])
  AX_SILOFS_CHECK_FUNCS([posix_fallocate])
  AX_SILOFS_CHECK_FUNCS([prctl])
  AX_SILOFS_CHECK_FUNCS([pread])
  AX_SILOFS_CHECK_FUNCS([preadv])
  AX_SILOFS_CHECK_FUNCS([preadv2])
  AX_SILOFS_CHECK_FUNCS([pwrite])
  AX_SILOFS_CHECK_FUNCS([pwritev])
  AX_SILOFS_CHECK_FUNCS([pwritev2])
  AX_SILOFS_CHECK_FUNCS([renameat2])
  AX_SILOFS_CHECK_FUNCS([select])
  AX_SILOFS_CHECK_FUNCS([setpwent])
  AX_SILOFS_CHECK_FUNCS([sigprocmask])
  AX_SILOFS_CHECK_FUNCS([splice])
  AX_SILOFS_CHECK_FUNCS([statx])
  AX_SILOFS_CHECK_FUNCS([strcasecmp])
  AX_SILOFS_CHECK_FUNCS([strdup])
  AX_SILOFS_CHECK_FUNCS([strrchr])
  AX_SILOFS_CHECK_FUNCS([sysconf])
  AX_SILOFS_CHECK_FUNCS([tcgetattr])
  AX_SILOFS_CHECK_FUNCS([umount2])
  AX_SILOFS_CHECK_FUNCS([usleep])
  AX_SILOFS_CHECK_FUNCS([utimensat])
  AX_SILOFS_CHECK_FUNCS([uuid_parse])
  AX_SILOFS_CHECK_FUNCS([vmsplice])
  AX_SILOFS_CHECK_FUNCS([waitpid])
])

AC_DEFUN([AX_SILOFS_NEED_BUILTIN],
[
  AX_GCC_BUILTIN(__builtin_clz)
  AX_GCC_BUILTIN(__builtin_expect)
  AX_GCC_BUILTIN(__builtin_popcount)
])

AC_DEFUN([AX_SILOFS_NEED_FUNC_ATTRIBUTE],
[
  AX_GCC_FUNC_ATTRIBUTE(noreturn)
])




