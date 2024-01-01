.. SPDX-License-Identifier: GPL-3.0-or-later

.. meta::
   :title: The Silo File-System
   :description: Documentations for silofs
   :language: en-US
   :keywords: restructuredtext
   :copyright: Shachar Sharon, 2022-2024

======================
 The Silo File-System
======================

.. contents:: :depth: 0

.. sectnum::

.. |silofs| replace:: ``silofs``



Silofs *("stored in large objects file-system")* is a user-space
file-system for storing large volumes of data as encrypted blobs.
It allows normal users to create an isolated storage area, with its
own private key, and mount it on local host. When mounted users may
manipulate their data as they would do with any other file-system,
while the actual data (and meta-data) is transparently encrypted and
stored within a local repository as opaque blobs. Other processes,
which have the appropriate UNIX credentials, may access those blobs as
regular files, but they can not view their content. This model allows
common Linux utilities such as rsync_ and rclone_ to backup or archive
the content of the repository into remote location, yet without
compromising the integrity of the underlying data.

Silofs is implemented using Linux's FUSE bridge, and as such it trades
performance with functionality and ease of use. It is designed to serve
those who wish to easily ship media content into external cloud storage
for long-term archiving, but without revealing information on their
private data, and without paying high costs and extra resources due to
re-packing.


Source code: Github_

License: GPLv3_

.. _Github: https://github.com/synarete/silofs

.. _GPLv3: https://www.gnu.org/licenses/gpl-3.0.en.html

.. _rsync: https://rsync.samba.org/

.. _rclone: https://rclone.org/


