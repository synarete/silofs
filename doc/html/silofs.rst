.. SPDX-License-Identifier: GPL-3.0-or-later

======================================
 Silofs -- a File-System to the Cloud
======================================

.. contents:: :depth: 2

.. sectnum::

----------
 Overview
----------


What is Silofs?
~~~~~~~~~~~~~~~
Silofs is a user-space file-system that allows you to easily archive and
restore a point-in-time snapshot to/from the cloud.


What is Silofs not?
~~~~~~~~~~~~~~~~~~~
Silofs can not be used as a root file-system, nor was it designed to serve as
a high performance storage system. While a lot of effort has been made to
minimize the penalty of user-space file-system (especially when not using
inline encryption), its data-packing strategy and usage of regular file as
backing storage implies performance degradation compared to in-kernel
file-systems.



System requirements
~~~~~~~~~~~~~~~~~~~
Silofs is implemented for the GNU/Linux environment.


-------------------
 Build and Install
-------------------

Preparation
~~~~~~~~~~~

Clone silofs's source code:

.. code-block:: sh

  $ git clone https://github.com/synarete/silofs


Depending on your system, you may need to install additional development
packages in order to compile silofs from source.

On rpm-based systems, install the following packages:

.. code-block:: sh

  $ # run as privileged user:
  $ dnf install gcc make automake libtool libuuid-devel libattr-devel
  $ dnf install libcap-devel libunwind-devel libgcrypt-devel kernel-headers
  $ dnf install python3-docutils

On deb-based systems, install the following packages:

.. code-block:: sh

  $ # run as privileged user:
  $ apt-get install gcc make automake libtool uuid-dev attr-dev libcap-dev
  $ apt-get install libunwind-dev libgcrypt-dev kernel-headers
  $ apt-get install python3-docutils


Build with GNU/autotools
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: sh

  $ git clone https://github.com/synarete/silofs
  $ cd silofs
  $ ./bootstrap
  $ cd build
  $ ../configure
  $ make
  $ make install


Build as rpm/deb package
~~~~~~~~~~~~~~~~~~~~~~~~
On rpm/deb system, you may try installtion via package managers. A helper
script is provided to build packages:

.. code-block:: sh

  $ ./pkg/packagize.sh
  ...

When done, packages are located under ``build`` directory, and should be
installed by privileged user.


-------
 Usage
-------

Preparation
~~~~~~~~~~~

Silofs is designed to operate as a non-privileged process. A user can mount
his own isolated file-system, without any need for special resources or
capabilities from the system. However, an appropriate privilege (Linux: the
``CAP_SYS_ADMIN`` capability) is required to mount a silofs filesystem.

Silofs uses a dedicated mounting daemon service, which allows a non-privileged
processes to mount and umount file-systems (similar to ``fusermount3``). As
a security enhancement, only well-known directories, which are listed in
``/etc/silofs/mountd.conf`` configuration file, may be valid as mount point.
Whenever adding new entries to this file, the ``silofs-mountd.service`` must be
restarted for changes to take effect.

Before mounting new file-system, the sysadmin should add new entry to the
local system configuration file:

.. code-block:: sh

  $ echo '/path/to/mount/dir' >> /etc/silofs/mountd.conf
  $ systemctl restart silofs-mountd.service


Creation
~~~~~~~~

Silofs allows users to create both an encrypted and non-encrypted file-system,
where a non-encrypted file-system can be encrypted offline later on, and vise
versa (i.e., an encrypted file-system may be decrypted offline). Upon
creating an encrypted file-system, the user should provide a strong passphrase
which will later be used during the mount process.

The file-system's data resides on a regular file, which the owner of this
volume-file must have read-write access permissions. The maximal file-system
size should be defined upon creation, thou the actual used file-size will be
much smaller.


To format a new encrypted silofs file-system, use the ``mkfs`` sub-command:

.. code-block:: sh

  $ silofs mkfs --encrypted --size=SIZE /path/to/volume/name.silofs
  enter passphrase:
  re-enter passphrase:
  ...


To format a non-encrypted silofs file-system, use the ``mkfs`` sub-command
without the ``--encrypted`` option.


Mounting
~~~~~~~~

Mounting a silofs file-system can be made only when all the following
conditions are met:

1. The target mount directory is empty.
2. User has read-write-execute access to the mount directory.
3. The mount directory is listed in ``/etc/silofs/mountd.conf`` file.
4. System-wide ``silofs-mountd.service`` is active.

To mount a previously formatted silofs file-system, use the ``mount``
sub-command:

.. code-block:: sh

  $ silofs mount /path/to/volume/fsname.silofs /path/to/mount/dir


Depending on volume's size, encryption mode and local system's characteristics,
mount should be active within few seconds:

.. code-block:: sh

  $ df -h /path/to/mount/dir


To unmount a live silofs file-system, use the ``umount`` sub-command (note that
the ``silofs-mountd.service`` must be active):

.. code-block:: sh

  $ systemctl status silofs-mountd.service
  $ silofs umount /path/to/mount/dir


Cloning
~~~~~~~
When the underlying volume file residues within a file-system which supports
the ``copy_file_range(2)`` system call (such as ``XFS`` or ``BTRFS``), a user
my create a writable snapshot of an active file-system:

.. code-block:: sh

  $ silofs clone /path/to/mount/dir /path/to/volume/fsclone.silofs


Note that the target cloned volume file must reside on the file-system as
the original volume.


Offline encryption
~~~~~~~~~~~~~~~~~~
A user choose to run a silofs file-system in non-encryption mode, primarly
when she wants to avoid the run-time performance penalty of copy and encryption
of data. In such cases, it may be desired to encrypt the underlying volume in
offline mode (encryption is done in-place):

.. code-block:: sh

  $ silofs encrypt /path/to/volume/fsname.silofs
  enter passphrase:
  re-enter passphrase:
  ...


The reversed operation is also valid: take an encrypted volume and decrypt it
in-place:

.. code-block:: sh

  $ silofs decrypt /path/to/volume/fsname.silofs
  enter passphrase:


Archiving
~~~~~~~~~
It is often desired to archive large silofs volumes as encrypted objects
represnations, which may be shipped to remote machine or remote cloud. Silofs
provides a mechanism to export and import:

.. code-block:: sh

  $ silofs export /path/to/volume/fsname.silofs /pash/to/repo/dir
  $ silofs import /pash/to/repo/dir/fsname.silofs /path/to/volume/dir


---------
 Design
---------
TODO


---------
 License
---------
Silofs is distributed under **GPL-3.0-or-later** license. It is a free
software: you can redistribute it and/or modify it under the terms of the
GNU General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.

Silofs is distributed in the hope that it will be useful, but without any
warranty; without even the implied warranty of merchantability or fitness
for a particular purpose. You should have received a copy of the GNU General
Public License along with this program. If not, see GPLv3_


.. _GPLv3: https://www.gnu.org/licenses/gpl-3.0.en.html




