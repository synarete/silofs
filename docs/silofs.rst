.. SPDX-License-Identifier: GPL-3.0-or-later

.. meta::
   :title: The Silo File-System
   :description: Documentations for silofs
   :language: en-US
   :keywords: restructuredtext
   :copyright: Shachar Sharon, 2022

======================
 The Silo File-System
======================

.. contents:: :depth: 0

.. sectnum::

.. |silofs| replace:: ``silofs``

.. |Silofs| replace:: ``Silofs``


|Silofs| *("stored in large objects file-system")* is a GNU/Linux
user-space file-system designed for storing large volumes of data over
encrypted blobs. It let normal users create an isolated storage area,
with its own private key, and mount it on a local host machine. Once
mounted, users may manipulate their data as they would normally do with
any other POSIX file-system, plus take full volume snapshots (online or
offline), while the actual data and meta-data is securely stored within
local repository. The repository itself uses regular files as encrypted
blobs, which are opaque to any user other the file-system's owner. This
layered model allows performing an efficient remote backup or archive
using common utilities like rsync_ or rclone_, yet without compromising
the user's data integrity.

|Silofs| is implemented using Linux's FUSE bridge, and as such it
trades performance with functionality and ease of use. It does not
intend to compete with kernel-based file-systems in performance, or
serve as yet another backup solutions. It is mainly designed to serve
those who wish to easily archive their data into external cloud storage

Source code: Github_

License: GPLv3_

.. _Github: https://github.com/synarete/silofs

.. _GPLv3: https://www.gnu.org/licenses/gpl-3.0.en.html

.. _rsync: https://rsync.samba.org/

.. _rclone: https://rclone.org/


