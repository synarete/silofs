/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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
#define SILOFS_EFSCORRUPTED     SILOFS_DEFERR(EUCLEAN)
#define SILOFS_ERANGE           SILOFS_DEFERR(ERANGE)
#define SILOFS_EFSBADCRC        SILOFS_DEFERR(EBADMSG)

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
#define SILOFS_EBLOB            SILOFS_DEFERR2(11)

/* internal error */
#define SILOFS_EBUG             SILOFS_DEFERR2(1111)

#endif /* SILOFS_ERRORS_H_ */
