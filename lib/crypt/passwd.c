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
#include "configs.h"
#include <silofs/errors.h>
#include "infra.h"
#include "str.h"
#include "prandom.h"
#include "passwd.h"
#include "ivkey.h"

static void
password_setup_dat(struct silofs_password *pw, const void *pass, size_t len)
{
	memcpy(pw->pass, pass, len);
	pw->passlen = len;
}

static void password_setup_nil(struct silofs_password *pw)
{
	char pass[SILOFS_PASSWORD_MIN];

	memset(pass, 0, sizeof(pass));
	password_setup_dat(pw, pass, sizeof(pass));
}

int silofs_password_setup2(struct silofs_password *pw, const void *pass,
                           size_t len)
{
	int ret = 0;

	SILOFS_STATICASSERT_GT(sizeof(pw->pass), SILOFS_PASSWORD_MAX);

	silofs_password_reset(pw);
	if ((pass == nullptr) && (len == 0)) {
		/* password-less mode */
		password_setup_nil(pw);
	} else if ((pass != nullptr) && //
	           (len >= SILOFS_PASSWORD_MIN) &&
	           (len <= SILOFS_PASSWORD_MAX)) {
		password_setup_dat(pw, pass, len);
	} else {
		ret = -SILOFS_EILLPASS;
	}
	return ret;
}

int silofs_password_setup(struct silofs_password *pw, const char *pass)
{
	return silofs_password_setup2(pw, pass, silofs_str_length(pass));
}

void silofs_password_reset(struct silofs_password *pw)
{
	silofs_memzero(pw, sizeof(*pw));
	pw->passlen = 0;
}

void silofs_password_mkrand(struct silofs_password *pw)
{
	char str[128] = "";
	uint8_t d[60] = {};
	size_t cnt = 0;

	silofs_prandom(d, sizeof(d));
	silofs_mem_to_ascii(d, sizeof(d), str, sizeof(str) - 1, &cnt);
	str[cnt] = '\0';

	silofs_password_setup(pw, str);
}
