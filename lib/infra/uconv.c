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
#define _GNU_SOURCE 1
#include "configs.h"
#include <silofs/errors.h>
#include <errno.h>
#include "utility.h"
#include "uconv.h"

int silofs_uconv_init(struct silofs_uconv *uconv)
{
	/* Using UTF32LE to avoid BOM (byte-order-mark) character */
	if (uconv->iconv_set) {
		return -SILOFS_EALREADY;
	}
	uconv->iconv = iconv_open("UTF32LE", "UTF8");
	if (uconv->iconv == (iconv_t)(-1)) { // NOLINT
		return errno ? -errno : -SILOFS_EOPNOTSUPP;
	}
	uconv->iconv_set = true;
	return 0;
}

void silofs_uconv_fini(struct silofs_uconv *uconv)
{
	if (uconv->iconv_set) {
		iconv_close(uconv->iconv);
		uconv->iconv_set = false;
	}
}

int silofs_uconv_convert(const struct silofs_uconv *uconv, const char *src,
                         size_t slen, char *dst, size_t dlen, size_t *out_conv)
{
	char  *in     = silofs_unconst(src);
	char  *out    = dst;
	size_t inlen  = slen;
	size_t outlen = dlen;
	size_t ret;

	errno = 0;
	ret   = iconv(uconv->iconv, &in, &inlen, &out, &outlen);
	if (ret != 0) { // NOLINT
		return errno ? -errno : -SILOFS_EINVAL;
	}
	if (inlen > 0) {
		return errno ? -errno : -SILOFS_EINVAL;
	}
	if ((outlen % 4) != 0) {
		return errno ? -errno : -SILOFS_EINVAL;
	}
	*out_conv = dlen - outlen;
	return 0;
}
