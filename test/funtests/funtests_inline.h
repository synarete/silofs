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
#ifndef SILOFS_FUNTESTS_INLINE_H_
#define SILOFS_FUNTESTS_INLINE_H_

#include <stdlib.h>
#include <unistd.h>

static inline loff_t ft_off_end(loff_t off, size_t len)
{
	return off + (long)len;
}

static inline size_t ft_max(size_t a, size_t b)
{
	return (a > b) ? a : b;
}

static inline size_t ft_min(size_t a, size_t b)
{
	return (a < b) ? a : b;
}

static inline long ft_lmax(long a, long b)
{
	return (a > b) ? a : b;
}


#endif /* SILOFS_FUNTESTS_INLINE_H_ */
