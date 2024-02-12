/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
 *
 * Silofs is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Silofs is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#ifndef SILOFS_ERRORS_H_
#define SILOFS_ERRORS_H_

#include <errno.h>

#define SILOFS_ERRBASE          (1000)
#define SILOFS_ERRBASE2         (10000)
#define SILOFS_DEFERR(ec)       (SILOFS_ERRBASE + (ec))
#define SILOFS_DEFERR2(ec)      (SILOFS_ERRBASE2 + (ec))

/* error codes derived from standard errno values */
#define SILOFS_EPERM            SILOFS_DEFERR(EPERM)
#define SILOFS_ENOENT           SILOFS_DEFERR(ENOENT)
#define SILOFS_EIO              SILOFS_DEFERR(EIO)
#define SILOFS_ENXIO            SILOFS_DEFERR(ENXIO)
#define SILOFS_EBADF            SILOFS_DEFERR(EBADF)
#define SILOFS_EAGAIN           SILOFS_DEFERR(EAGAIN)
#define SILOFS_ENOMEM           SILOFS_DEFERR(ENOMEM)
#define SILOFS_EACCES           SILOFS_DEFERR(EACCES)
#define SILOFS_EBUSY            SILOFS_DEFERR(EBUSY)
#define SILOFS_EEXIST           SILOFS_DEFERR(EEXIST)
#define SILOFS_ENOTDIR          SILOFS_DEFERR(ENOTDIR)
#define SILOFS_EISDIR           SILOFS_DEFERR(EISDIR)
#define SILOFS_EINVAL           SILOFS_DEFERR(EINVAL)
#define SILOFS_ENFILE           SILOFS_DEFERR(ENFILE)
#define SILOFS_EMFILE           SILOFS_DEFERR(EMFILE)
#define SILOFS_EFBIG            SILOFS_DEFERR(EFBIG)
#define SILOFS_ENOSPC           SILOFS_DEFERR(ENOSPC)
#define SILOFS_EROFS            SILOFS_DEFERR(EROFS)
#define SILOFS_EMLINK           SILOFS_DEFERR(EMLINK)
#define SILOFS_ERANGE           SILOFS_DEFERR(ERANGE)
#define SILOFS_ENAMETOOLONG     SILOFS_DEFERR(ENAMETOOLONG)
#define SILOFS_ENOSYS           SILOFS_DEFERR(ENOSYS)
#define SILOFS_ENOTEMPTY        SILOFS_DEFERR(ENOTEMPTY)
#define SILOFS_EWOULDBLOCK      SILOFS_DEFERR(EWOULDBLOCK)
#define SILOFS_ENODATA          SILOFS_DEFERR(ENODATA)
#define SILOFS_ECOMM            SILOFS_DEFERR(ECOMM)
#define SILOFS_EPROTO           SILOFS_DEFERR(EPROTO)
#define SILOFS_EFSBADCRC        SILOFS_DEFERR(EBADMSG)
#define SILOFS_EOVERFLOW        SILOFS_DEFERR(EOVERFLOW)
#define SILOFS_EOPNOTSUPP       SILOFS_DEFERR(EOPNOTSUPP)
#define SILOFS_EALREADY         SILOFS_DEFERR(EALREADY)
#define SILOFS_EFSCORRUPTED     SILOFS_DEFERR(EUCLEAN)
#define SILOFS_ENOMEDIUM        SILOFS_DEFERR(ENOMEDIUM)
#define SILOFS_EKEYEXPIRED      SILOFS_DEFERR(EKEYEXPIRED)

/* error codes which are silofs specific */
#define SILOFS_ENOREPO          SILOFS_DEFERR2(1)
#define SILOFS_EBADREPO         SILOFS_DEFERR2(2)
#define SILOFS_ENOBOOT          SILOFS_DEFERR2(3)
#define SILOFS_EBADBOOT         SILOFS_DEFERR2(4)
#define SILOFS_EMOUNT           SILOFS_DEFERR2(5)
#define SILOFS_EUMOUNT          SILOFS_DEFERR2(6)
#define SILOFS_ENORX            SILOFS_DEFERR2(7)
#define SILOFS_ENOTX            SILOFS_DEFERR2(8)
#define SILOFS_ECSUM            SILOFS_DEFERR2(9)
#define SILOFS_ERDONLY          SILOFS_DEFERR2(10)
#define SILOFS_ELSEG            SILOFS_DEFERR2(11)
#define SILOFS_ENOTDONE         SILOFS_DEFERR2(12)
#define SILOFS_ECOMPRESS        SILOFS_DEFERR2(13)
#define SILOFS_EDECOMPRESS      SILOFS_DEFERR2(14)
#define SILOFS_EQALLOC          SILOFS_DEFERR2(15)

/* error codes which are purely internal to silofs */
#define SILOFS_EBUG             SILOFS_DEFERR2(1111)

#endif /* SILOFS_ERRORS_H_ */
