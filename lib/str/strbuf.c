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
#include <silofs/configs.h>
#include <silofs/str/strchr.h>
#include <silofs/str/strbuf.h>
#include <silofs/str/strings.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>


void silofs_strbuf_reset(struct silofs_strbuf *sbuf)
{
	memset(sbuf, 0, sizeof(*sbuf));
}

void silofs_strbuf_assign(struct silofs_strbuf *sbuf,
                          const struct silofs_strbuf *other)
{
	memcpy(sbuf, other, sizeof(*sbuf));
}

void silofs_strbuf_setup(struct silofs_strbuf *sbuf,
                         const struct silofs_substr *str)
{
	silofs_strbuf_reset(sbuf);
	silofs_substr_copyto(str, sbuf->str, sizeof(sbuf->str) - 1);
}

void silofs_strbuf_setup_by(struct silofs_strbuf *sbuf, const char *s)
{
	struct silofs_substr ss;

	silofs_substr_init(&ss, s);
	silofs_strbuf_setup(sbuf, &ss);
}

size_t silofs_strbuf_copyto(const struct silofs_strbuf *sbuf,
                            char *str, size_t lim)
{
	const size_t len = strlen(sbuf->str);
	const size_t n = (lim < len) ? lim : len;

	memcpy(str, sbuf->str, n);
	if (lim && (n < lim)) {
		str[n] = '\0';
	}
	return n;
}

size_t silofs_strbuf_sprintf(struct silofs_strbuf *sbuf, const char *fmt, ...)
{
	va_list ap;
	size_t k;
	int n;

	silofs_strbuf_reset(sbuf);
	va_start(ap, fmt);
	k = sizeof(sbuf->str);
	n = vsnprintf(sbuf->str, k - 1, fmt, ap);
	va_end(ap);
	return (n < (int)k) ? (size_t)n : k;
}
