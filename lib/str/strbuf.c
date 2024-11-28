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
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

void silofs_strbuf_init(struct silofs_strbuf *sbuf)
{
	sbuf->str[0] = '\0';
}

void silofs_strbuf_fini(struct silofs_strbuf *sbuf)
{
	sbuf->str[0] = '\0';
}

void silofs_strbuf_as_sv(const struct silofs_strbuf *sbuf,
                         struct silofs_strview *out_sv)
{
	silofs_strview_init(out_sv, sbuf->str);
}

void silofs_strbuf_as_ss(struct silofs_strbuf *sbuf,
                         struct silofs_strspan *out_ss)
{
	const size_t len = silofs_str_length(sbuf->str);

	silofs_strspan_initk(out_ss, sbuf->str, len, sizeof(sbuf->str));
}

void silofs_strbuf_reset(struct silofs_strbuf *sbuf)
{
	silofs_strbuf_bzero(sbuf, sizeof(*sbuf));
}

void silofs_strbuf_bzero(struct silofs_strbuf *sbuf, size_t n)
{
	memset(sbuf, 0, silofs_min(n, sizeof(*sbuf)));
}

void silofs_strbuf_assign(struct silofs_strbuf *sbuf,
                          const struct silofs_strbuf *other)
{
	struct silofs_strview sv;
	struct silofs_strspan ss;

	sbuf->str[0] = '\0';
	silofs_strbuf_as_ss(sbuf, &ss);
	silofs_strbuf_as_sv(other, &sv);
	silofs_strspan_vassign(&ss, &sv);
}

void silofs_strbuf_setup(struct silofs_strbuf *sbuf,
                         const struct silofs_strview *sv)
{
	struct silofs_strspan ss;

	silofs_strbuf_as_ss(sbuf, &ss);
	silofs_strspan_clear(&ss);
	silofs_strspan_vassign(&ss, sv);
}

void silofs_strbuf_setup_by(struct silofs_strbuf *sbuf, const char *s)
{
	struct silofs_strview sv;

	silofs_strbuf_reset(sbuf);
	silofs_strview_init(&sv, s);
	silofs_strbuf_setup(sbuf, &sv);
}

void silofs_strbuf_setup_by2(struct silofs_strbuf *sbuf, const char *s,
                             size_t n)
{
	struct silofs_strview sv;

	silofs_strbuf_reset(sbuf);
	silofs_strview_initn(&sv, s, n);
	silofs_strbuf_setup(sbuf, &sv);
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
