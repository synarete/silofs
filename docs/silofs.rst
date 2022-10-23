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


|Silofs| is a user-space file-system which takes a unique approach to the
problem of archiving large volumes of data as cloud objects. Instead of
traversing an existing namespace, it implements a fully functional file
system on top of binary large objects (*blobs*), which serve both for I/O
operations and data packing. Combined with built-in snapshot capabilities,
users can easily archive their data into cloud friendly format.

Source code: Github_

License: GPLv3_

.. _Github: https://github.com/synarete/silofs

.. _GPLv3: https://www.gnu.org/licenses/gpl-3.0.en.html


