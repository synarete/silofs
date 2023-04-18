.. SPDX-License-Identifier: GPL-3.0-or-later

.. meta::
   :title: The Silo File-System
   :description: Documentations for silofs
   :language: en-US
   :keywords: restructuredtext
   :copyright: Shachar Sharon, 2022-2023

======================
 The Silo File-System
======================

.. contents:: :depth: 0

.. sectnum::

.. |silofs| replace:: ``silofs``



Silofs *("stored in large objects file-system")* is a user-space
file-system for storing large volumes of data as encrypted blobs.
It allows normal users to create an isolated storage area, with its
own private key, and mount it on local host. Once mounted, the users
may manipulate their data as they would do with any other POSIX
file-system, while the actual data and meta-data are transparently
encrypted and stored within a local repository as opaque blobs. Any
other process or user can not view the content of those blobs, even
though it may access them as regular files. This model allows common
Linux utilities such as rsync_ and rclone_ to backup or archive the
content of the repository remotely, yet without compromising the
underlying user's data integrity.

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


