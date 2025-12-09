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
#ifndef SILOFS_SNPRINTF_H_
#define SILOFS_SNPRINTF_H_

#include <stdlib.h>
#include <stdarg.h>
#include <silofs/ccattr.h>

silofs_attr_printf(3, 0) void silofs_vsnprintf(char *buf, size_t bsz,
                                               const char *fmt, va_list ap);

#endif /* SILOFS_SNPRINTF_H_ */
