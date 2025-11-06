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
#ifndef SILOFS_UCONV_H_
#define SILOFS_UCONV_H_

#include <stdlib.h>
#include <stdbool.h>
#include <iconv.h>

/* wrapper over iconv for UTF8-to-UTF32LE conversion */
struct silofs_uconv {
	iconv_t iconv;
	bool    iconv_set;
};

int silofs_uconv_init(struct silofs_uconv *uconv);

void silofs_uconv_fini(struct silofs_uconv *uconv);

int silofs_uconv_convert(struct silofs_uconv *uconv, const char *src,
                         size_t slen, char *dst, size_t dlen,
                         size_t *out_conv);

#endif /* SILOFS_UCONV_H_ */
