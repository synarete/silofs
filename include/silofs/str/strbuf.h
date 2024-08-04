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
#ifndef SILOFS_STRBUF_H_
#define SILOFS_STRBUF_H_

#include <silofs/infra.h>
#include <silofs/str/strview.h>
#include <silofs/str/strmref.h>


/* fixed-size string-buffer (typically, for names) */
struct silofs_strbuf {
	char str[256];
};


void silofs_strbuf_init(struct silofs_strbuf *sbuf);

void silofs_strbuf_fini(struct silofs_strbuf *sbuf);

void silofs_strbuf_as_sv(const struct silofs_strbuf *sbuf,
                         struct silofs_strview *out_sv);

void silofs_strbuf_as_smr(struct silofs_strbuf *sbuf,
                          struct silofs_strmref *out_smr);

void silofs_strbuf_reset(struct silofs_strbuf *sbuf);

void silofs_strbuf_bzero(struct silofs_strbuf *sbuf, size_t n);

void silofs_strbuf_assign(struct silofs_strbuf *sbuf,
                          const struct silofs_strbuf *other);

void silofs_strbuf_setup(struct silofs_strbuf *sbuf,
                         const struct silofs_strview *sv);

void silofs_strbuf_setup_by(struct silofs_strbuf *sbuf, const char *s);

void silofs_strbuf_setup_by2(struct silofs_strbuf *sbuf,
                             const char *s, size_t n);

size_t silofs_strbuf_sprintf(struct silofs_strbuf *sbuf, const char *fmt, ...);

#endif /* SILOFS_STRBUF_H_ */
