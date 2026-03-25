/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#include <silofs/configs.h>
#include <stdio.h>

#include <silofs/ccattr.h>
#include <silofs/infra/snprintf.h>

#define attr_printf silofs_attr_printf(3, 0)

attr_printf static size_t
safe_vsnprintf(char *buf, size_t bsz, const char *fmt, va_list ap)
{
	va_list ap2;
	int ret;

	if ((buf == nullptr) || (bsz == 0)) {
		return 0;
	}

	va_copy(ap2, ap);
	ret = vsnprintf(buf, bsz, fmt, ap2);
	va_end(ap2);

	if (ret < 0) { /* formatting error */
		buf[0] = '\0';
		return 0;
	}

	if ((size_t)ret >= bsz) { /* truncated */
		buf[bsz - 1] = '\0';
		return bsz - 1;
	}

	return (size_t)ret;
}

void silofs_vsnprintf(char *buf, size_t bsz, const char *fmt, va_list ap)
{
	(void)safe_vsnprintf(buf, bsz, fmt, ap);
}
