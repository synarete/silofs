AC_DEFUN([AX_SILOFS_NEED_CONFIG_H],
[
  AH_TEMPLATE([SILOFS_VERSION_STRING], [Version string])
  AC_DEFINE_UNQUOTED([SILOFS_VERSION_STRING], ["$pkg_version"],
    [Version string])

  AH_TEMPLATE([SILOFS_VERSION_MAJOR], [Version major number])
  AC_DEFINE_UNQUOTED([SILOFS_VERSION_MAJOR], [$pkg_version_major],
    [Version major number])

  AH_TEMPLATE([SILOFS_VERSION_MINOR], [Version minor number])
  AC_DEFINE_UNQUOTED([SILOFS_VERSION_MINOR], [$pkg_version_minor],
    [Version minor number])

  AH_TEMPLATE([SILOFS_VERSION_SUBLEVEL], [Version sublevel number])
  AC_DEFINE_UNQUOTED([SILOFS_VERSION_SUBLEVEL], [$pkg_version_sublevel],
    [Version sublevel number])

  AH_TEMPLATE([SILOFS_RELEASE], [Release number])
  AC_DEFINE_UNQUOTED([SILOFS_RELEASE], ["$pkg_release"],
    [Release number])

  AH_TEMPLATE([SILOFS_REVISION], [Revision id])
  AC_DEFINE_UNQUOTED([SILOFS_REVISION], ["$pkg_revision"],
    [Revision id])
])
