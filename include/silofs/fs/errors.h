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

#define SILOFS_DEFERR(ec)       (1000 + (ec))
#define SILOFS_DEFERR2(ec)      (10000 + (ec))

/* error codes derived from standard errno values */
#define SILOFS_EPERM            SILOFS_DEFERR(EPERM)
#define SILOFS_EFSCORRUPTED     SILOFS_DEFERR(EFSCORRUPTED)

/* error codes which are internal-only */
#define SILOFS_ENORX            SILOFS_DEFERR2(1)
#define SILOFS_ENOTX            SILOFS_DEFERR2(2)
#define SILOFS_ECSUM            SILOFS_DEFERR2(3)

/* insternal-bug error */
#define SILOFS_EBUG             SILOFS_DEFERR2(1111)

#endif /* SILOFS_ERRORS_H_ */
