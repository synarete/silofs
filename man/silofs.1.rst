.. SPDX-License-Identifier: GPL-3.0-or-later

========
 silofs
========

--------------------
The Silo File System
--------------------

:Author:         Shachar Sharon
:Date:           Oct 2022
:Copyright:      GPLv3
:Manual section: 1
:Manual group:   Silofs Manual

..


SYNOPSIS
========

  **silofs** <command> [options]


DESCRIPTION
===========

**silofs** *("stored in large objects file-system")* is a user-space
file-system for storing large volumes of data as encrypted blobs.
It allows normal users to create an isolated storage area, with its
own private key, and mount it on local host. Once mounted, the users
may manipulate their data as they would do with any other POSIX
file-system, while the actual data and meta-data are transparently
encrypted and stored within a local repository as opaque blobs. Any
other process or user can not view the content of those blobs, even
though it may access them as regular files. This model allows common
Linux utilities such as  **rsync** and **rclone** to backup or
archive the content of the repository remotely, yet without
compromising the underlying user's data integrity.


OPTIONS
=======

**-v, --version**
  Displays the current version of the locally installed  **silofs**.

**-h, --help**
  Displays list of avilable sub-commands. When using this option with
  command name displays command-specific help information.

..


COMMANDS
========

..

init
----
**silofs init** [--attic] *repodir*


Create an empty **silofs** repository under *repodir*. Input *repodir*
must be a pathname to an empty directory within local host's
file-system, which **silofs** uses as a local blobs storage.

..


mkfs
----

**silofs mkfs** --size=nbytes *repodir/name*

..

Format new silofs file-system and store its boot meta-data config file
at *repodir/name*. Expects *repodir* to be a valid **silofs**
repository. The actual meta-data objects which compose the newly
created file system, as well as any future writes to this file-system
are stored within the special *repodir/.silofs* directory, using object
representations.

Upon formatting a new silofs file-system the user is requested to
provided a password which is used to derive the main key and IV used
for objects' encryption. This password, no longer than 255 characters
in size, is later required for mounting this file system instance.

..

The *-s*, *--size* option defines the volume's size in bytes. Size may
be suffixed with *G* or *T* to denote Giga-bytes or Tera-bytes
respectively. A valid value for file-system size must be within the
range of **[2G..64T]**.

..

|
| *-s*, *--size=SIZE*
|  Size of new volume in bytes
|

..

mount
-----
**silofs mount** [-raiXD] *repodir/name* *mountpoint*

Attach the *silofs* file-system referenced by *repodir/name* into the
file hierarchy of the host machine, at directory *mountpoint*. Creates
a user-space daemon process which mounts the file-system using FUSE
protocol. The actual **mount**\(2) system call is performed by
auxiliary privileged system-service daemon, which must have valid
configuration entry for *mountpoint* and the current user.
See **silofs-mountd**\(8) for more details.

Upon mounting an existing silofs file-system the user is requested to
provided the password which was used upon **silofs mkfs**. Without
providing a valid password, the **silofs mount** command will fail.

..

|
| *-r*, *--rdonly*
|  Read-only mount
|
| *-a*, *--allow-other*
|  Allow other users to access the file-system. By default, only the
|  owner of the file-system may have any access permissions.
|
| *-i*, *--allow-hostids*
|  Use the local-host uid and gid when not present in the IDs-mapping
|  section of *repodir/name*.
|
| *-X*, *--noexec*
| Do not allow programs execution.
|
| *-D*, *--nodaemon*
| Do not run as daemon process. Mostly used in debug mode.
|

..

umount
------
**silofs umount** [--force] *mountpoint*

Detach the *silofs* file-system mounted at *mountpoint* from the host
file hierarchy. The file-system is specified by giving the directory
where it has been mounted. The actual **umount**\(2) system call is
performed by auxiliary privileged system-service daemon, which must
have valid configuration entry for *mountpoint*.
See **silofs-mountd**\(8) for more details.
..

|
| -l, --lazy
|  Lazy unmount. Detach the file-system from the file hierarchy now,
|  and clean up all references to this file-system as soon as it is not
|  busy anymore.
|
| -f, --force
|  Force an unmount.
|

..

lsmnt
-----
**silofs lsmnt** [--long]

List all currently mounted *silofs* file-systems. When executed with
*-l* or *--long* option, display also the repository boot configuration
file for each mounted file-system.
..

|
| -l, --long
|  Detailed output format. Displays boot configuration file.
|

..

show
----
**silofs show** <sub-command> *pathname*

Query and report various internal parameters from a live file-system.
Calls a silofs specific **ioctl**\(2) commands over *pathname* and
reports its output in a human readable format. The *sub-command*
parameter may be one of the following commands:

  - *version*
    Reports the version number of the currently mounted file-system.
  - *boot*
    Reports the back-end repo dirpath and name of the file-system.
  - *proc*
    Show state of active mount daemon.
  - *spstats*
    Show space-allocations stats.
  - *statx*
    Show extended file stats.

..

snap
----
**silofs snap** --name=*snapname* [*pathname*]

**silofs snap** --name=*snapname* --offline *repodir/name*

Create file-system snapshot with the name *snapname*. With the first
form, creates a snapshot for a currently mounted file-system, on which
*pathname* resides. The file-system must be mounted with read-write
mode. If *pathname* is omitted, uses current working directory. All
pending I/Os are flushed to to the underlying blobs before actual
snapshot operation is taking place. With the second form creates a
snapshot to a non-mounted file system using offline mode. In both
cases, a boot config is created under *repodir/snapname* upon
successful completion.

Upon executin **silofs snap** in offline mode, the user is requested to
provided the password which was used upon **silofs mkfs**. Without
providing a valid password, the **silofs snap** command will fail.
..

|
| -n, --name=*snapname*
|  Snapshot name. Used to store resulting boot config file under
|  *repodir/snapname*.
|
| -o, --offline
|  Create snapshot in offline mode for non-mounted file-system.
|

..

rmfs
----
**silofs rmfs** *repodir/name*

Removes the file-system from the repository. The file-system referenced
by *repodir/name* may have been created by either **mkfs** or **snap**,
and it must **not** be active or mounted up **rmfs**. This operation
removes also all blobs which are associated by this file-system and are
not shared with any other file-system.


Upon removing an existing silofs file-system the user is requested to
provided the password which was used upon **silofs mkfs**. Without
providing a valid password, the **silofs rmfs** command will fail.

..


BUGS
====

Still a work-in-progress.



SEE ALSO
========

**silofs-mountd**\(8), **mount**\(8), **rsync**\(1)

..


