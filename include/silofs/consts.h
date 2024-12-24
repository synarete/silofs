/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#ifndef SILOFS_CONSTS_H_
#define SILOFS_CONSTS_H_

/* common power-of-2 sizes */
#define SILOFS_KILO  (1L << 10)
#define SILOFS_MEGA  (1L << 20)
#define SILOFS_GIGA  (1L << 30)
#define SILOFS_TERA  (1L << 40)
#define SILOFS_PETA  (1L << 50)
#define SILOFS_UKILO (1UL << 10)
#define SILOFS_UMEGA (1UL << 20)
#define SILOFS_UGIGA (1UL << 30)
#define SILOFS_UTERA (1UL << 40)
#define SILOFS_UPETA (1UL << 50)

/* memory page size */
#define SILOFS_PAGE_SHIFT_MIN (12)
#define SILOFS_PAGE_SIZE_MIN  (1U << SILOFS_PAGE_SHIFT_MIN)

#define SILOFS_PAGE_SHIFT_MAX (16)
#define SILOFS_PAGE_SIZE_MAX  (1U << SILOFS_PAGE_SHIFT_MAX)

/* valid sizes for system LEVELx_CACHE_LINESIZE */
#define SILOFS_CACHELINE_SIZE_MIN (32)
#define SILOFS_CACHELINE_SIZE_MAX (256)
#define SILOFS_CACHELINE_SIZE_DFL (64)

/* iovec count limit */
#define SILOFS_IOV_MAX (64)

#endif /* SILOFS_CONSTS_H_ */
