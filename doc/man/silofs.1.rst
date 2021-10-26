.. SPDX-License-Identifier: GPL-3.0-or-later

========
 silofs
========

--------------------
The Silo File System
--------------------

:Author:         Shachar Sharon
:Date:           Aug 2021
:Copyright:      GPLv3
:Manual section: 1
:Manual group:   Silofs Manual

..


SYNOPSIS
========

  **silofs** <command> [options]


DESCRIPTION
===========

**silofs** is a user-space file-system that allows you to easily archive and
restore a point-in-time snapshot to/from the cloud.

The layout of the underlying volume is arranged as packed archive, which may be
easily converted to objects representation.


COMMANDS
========

..

mkfs
----

**silofs mkfs** -s <size> *pathname*

..

Format new silofs file-system volume over regular file at *pathname*. The *-s*,
*--size* option defines the volume's size in bytes. Size may be suffixed with
*G* to denote giga-bytes. The minimum volume size is 1G and maximum is 1T.
Upon creation the user is requested to provide secure passphrase which is used
for encryption of file-system's main key. This passphrase is later required for
all other commands which access this volume.

..

|
| *-s*, *--size=SIZE*
|  Size of new volume in bytes
|
| *-P*, *--passphrase-file=FILE*
|  Passphrase file. This option should be considered insecure. Avoid it.
|


mount
-----
**silofs mount** [options] *pathname* *mountpoint*

Start a user-space daemon which mounts *silofs* volume as FUSE file system.
The regular file *pathname* must refer to a previously formatted volume with
**mkfs**, and *mountpoint* must be an empty directory. Upon start, the user
is requested to provide the passphrase which was used upon volume's *mkfs*.

..

|
| *-r*, *--rdonly*
|  Read-only mount
|
| *-x*, *--noexec*
| Do not allow programs execution.
|
| *-A*, *--allow-other*
|  Allow other users to access the file-system. By default, only the owner of
|  the file-system may have any access permissions.
|
| *-D*, *--nodaemon*
| Do not run as daemon process.
|
| *-P*, *--passphrase-file=FILE*
|  Passphrase file. This option should be considered insecure. Avoid it.
|

..

umount
------
**silofs umount** [--force] *mountpoint*

..

snap
----
**silofs snap** --name=NAME [options] *mountpoint* 

..


show
----
**silofs show** *pathname*

Query and report various internal parameters from a live silofs file-system.

..


lsmnt
-----
**silofs lsmnt**

List currently mounted silofs file-systems.

..


BUGS
====

Still a work-in-progress. Do not use in production.



SEE ALSO
========

**silofs-mountd**\(8), **mount**\(8)

..


