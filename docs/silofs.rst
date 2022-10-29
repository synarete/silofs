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


|Silofs| *("stored in large objects file-system")* is a GNU/Linux utility
with unique approach to the problem of archiving large volumes of data:
it implements a fully functional file-system on top of binary large
objects (*blobs*), which serve both for I/O operations and data
packing. Combined with built-in snapshot capabilities, compression and
encryption, users can incrementally archive their data into cloud
friendly format.

Source code: Github_

License: GPLv3_

.. _Github: https://github.com/synarete/silofs

.. _GPLv3: https://www.gnu.org/licenses/gpl-3.0.en.html


