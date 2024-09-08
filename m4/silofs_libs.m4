AC_DEFUN([AX_SILOFS_NEED_HEADER],
[
  AC_CHECK_HEADERS([$1], :,
    AC_MSG_ERROR([Unable to find header $1]))
])

AC_DEFUN([AX_SILOFS_NEED_HEADERS],
[
  AX_SILOFS_NEED_HEADER([stddef.h])
  AX_SILOFS_NEED_HEADER([stdint.h])
  AX_SILOFS_NEED_HEADER([stdlib.h])
  AX_SILOFS_NEED_HEADER([stdbool.h])
  AX_SILOFS_NEED_HEADER([string.h])
  AX_SILOFS_NEED_HEADER([unistd.h])
  AX_SILOFS_NEED_HEADER([termios.h])
  AX_SILOFS_NEED_HEADER([limits.h])
  AX_SILOFS_NEED_HEADER([math.h])
  AX_SILOFS_NEED_HEADER([ctype.h])
  AX_SILOFS_NEED_HEADER([fcntl.h])
  AX_SILOFS_NEED_HEADER([getopt.h])
  AX_SILOFS_NEED_HEADER([iconv.h])
  AX_SILOFS_NEED_HEADER([endian.h])
  AX_SILOFS_NEED_HEADER([execinfo.h])
  AX_SILOFS_NEED_HEADER([syslog.h])
  AX_SILOFS_NEED_HEADER([pthread.h])
  AX_SILOFS_NEED_HEADER([gcrypt.h])
  AX_SILOFS_NEED_HEADER([xxhash.h])
  AX_SILOFS_NEED_HEADER([zstd.h])
  AX_SILOFS_NEED_HEADER([pwd.h])
  AX_SILOFS_NEED_HEADER([grp.h])
  AX_SILOFS_NEED_HEADER([sched.h])
  AX_SILOFS_NEED_HEADER([uuid/uuid.h])
  AX_SILOFS_NEED_HEADER([attr/attributes.h])
  AX_SILOFS_NEED_HEADER([sys/xattr.h])
  AX_SILOFS_NEED_HEADER([sys/types.h])
  AX_SILOFS_NEED_HEADER([sys/wait.h])
  AX_SILOFS_NEED_HEADER([sys/time.h])
  AX_SILOFS_NEED_HEADER([sys/prctl.h])
  AX_SILOFS_NEED_HEADER([sys/socket.h])
  AX_SILOFS_NEED_HEADER([sys/file.h])
  AX_SILOFS_NEED_HEADER([sys/stat.h])
  AX_SILOFS_NEED_HEADER([sys/statvfs.h])
  AX_SILOFS_NEED_HEADER([sys/vfs.h])
  AX_SILOFS_NEED_HEADER([sys/sysinfo.h])
  AX_SILOFS_NEED_HEADER([sys/resource.h])
  AX_SILOFS_NEED_HEADER([sys/capability.h])
  AX_SILOFS_NEED_HEADER([sys/ioctl.h])
  AX_SILOFS_NEED_HEADER([sys/mman.h])
  AX_SILOFS_NEED_HEADER([sys/mount.h])
  AX_SILOFS_NEED_HEADER([sys/uio.h])
  AX_SILOFS_NEED_HEADER([sys/select.h])
  AX_SILOFS_NEED_HEADER([sys/un.h])
  AX_SILOFS_NEED_HEADER([netinet/in.h])
  AX_SILOFS_NEED_HEADER([netinet/udp.h])
  AX_SILOFS_NEED_HEADER([netinet/tcp.h])
  AX_SILOFS_NEED_HEADER([arpa/inet.h])
  AX_SILOFS_NEED_HEADER([linux/kernel.h])
  AX_SILOFS_NEED_HEADER([linux/types.h])
  AX_SILOFS_NEED_HEADER([linux/stat.h])
  AX_SILOFS_NEED_HEADER([linux/falloc.h])
  AX_SILOFS_NEED_HEADER([linux/fs.h])
  AX_SILOFS_NEED_HEADER([linux/fuse.h])
  AX_SILOFS_NEED_HEADER([linux/fiemap.h])
  AX_SILOFS_NEED_HEADER([linux/limits.h])
  AX_SILOFS_NEED_HEADER([linux/xattr.h])
])

AC_DEFUN([AX_SILOFS_NEED_LIBS],
[
  AX_PTHREAD
  AX_LIB_GCRYPT([yes])

  AM_PATH_LIBGCRYPT(1.8.1, :,
    AC_MSG_ERROR([Unable to find libgcrypt]))

  AC_SEARCH_LIBS([uuid_generate], [uuid], :,
    AC_MSG_ERROR([Unable to find libuuid]))

  AC_SEARCH_LIBS([cap_clear], [cap], :,
    AC_MSG_ERROR([Unable to find libcap]))

  AC_SEARCH_LIBS([XXH32], [xxhash], :,
    AC_MSG_ERROR([Unable to find libxxhash]))

  AC_SEARCH_LIBS([ZSTD_compress], [zstd], :,
    AC_MSG_ERROR([Unable to find libzstd]))
])

AC_DEFUN([AX_SILOFS_WANT_LIBS],
[
  AC_ARG_WITH([libunwind],
    AS_HELP_STRING([--with-libunwind=yes|no],
      [Link with libunwind for call-stack unwinding]),
      [], [with_libunwind=yes])

  AS_IF([test "x$with_libunwind" = "xyes"], [
    AC_SEARCH_LIBS([unw_backtrace], [unwind], :,
      AC_MSG_ERROR([Unable to find libunwind]))
    AX_SILOFS_NEED_HEADER([libunwind.h])
    AC_DEFINE_UNQUOTED([SILOFS_WITH_LIBUNWIND], ["1"])
    AH_TEMPLATE([SILOFS_WITH_LIBUNWIND],
      [Use libunwind for call-stack unwinding])
  ])

  AC_ARG_WITH([tcmalloc],
    AS_HELP_STRING([--with-tcmalloc],
      [Link with tcmalloc for heap memory leak detection]),
      [with_tcmalloc=yes], [with_tcmalloc=no])

  AS_IF([test "x$with_tcmalloc" = "xyes"], [
    AC_SEARCH_LIBS([tc_malloc], [tcmalloc], :,
      AC_MSG_ERROR([Unable to find libtcmalloc]))
    AC_DEFINE_UNQUOTED([SILOFS_WITH_TCMALLOC], ["1"])
    AH_TEMPLATE([SILOFS_WITH_TCMALLOC],
      [Use libtcmalloc for heap memory leak detection])
  ])
])
