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
#include <ctype.h>

#include <silofs/macros.h>
#include <silofs/errors.h>
#include <silofs/infra.h>
#include <silofs/str.h>
#include "passwd.h"

static int check_password_len(size_t len)
{
	return ((len < SILOFS_PASSWORD_MIN) || //
		(len > SILOFS_PASSWORD_MAX)) ?
		       -SILOFS_EILLPASS :
		       0;
}

static int check_password_char(int ch)
{
	return (!isascii(ch) || //
		iscntrl(ch) ||  //
		isspace(ch) ||  //
		!isprint(ch) || //
		!(isalnum(ch) || ispunct(ch))) ?
		       -SILOFS_EILLPASS :
		       0;
}

static int check_password_dat(const void *d, size_t n)
{
	const char *p = d;
	int err       = 0;

	for (size_t i = 0; i < n; ++i) {
		err = check_password_char(p[i]);
		if (err) {
			break;
		}
	}
	return err;
}

void silofs_password_reset(struct silofs_password *pw)
{
	silofs_memzero(pw, sizeof(*pw));
	pw->passlen = 0;
}

static void
password_setup_dat(struct silofs_password *pw, const void *pass, size_t len)
{
	SILOFS_STATICASSERT_LT(sizeof(pw->pass), UINT8_MAX);
	silofs_assert_le(len, sizeof(pw->pass));

	memcpy(pw->pass, pass, len);
	pw->passlen = (uint8_t)len;
}

static void password_setup_nil(struct silofs_password *pw)
{
	char pass[SILOFS_PASSWORD_MIN];

	memset(pass, 0, sizeof(pass));
	password_setup_dat(pw, pass, sizeof(pass));
}

int silofs_password_setup(struct silofs_password *pw, const char *pass)
{
	size_t len;
	int err;

	silofs_password_reset(pw);
	if (pass == nullptr) {
		/* password-less mode */
		password_setup_nil(pw);
		return 0;
	}
	len = silofs_str_length(pass);
	err = check_password_len(len);
	if (err) {
		return err;
	}
	err = check_password_dat(pass, len);
	if (err) {
		return err;
	}
	password_setup_dat(pw, pass, len);
	return 0;
}

int silofs_password_assign(struct silofs_password *pw,
			   const struct silofs_password *other)
{
	int err;

	err = silofs_password_recheck(other);
	if (err) {
		return err;
	}
	password_setup_dat(pw, other->pass, other->passlen);
	return 0;
}

int silofs_password_recheck(const struct silofs_password *pw)
{
	int err;

	err = check_password_len(pw->passlen);
	if (err) {
		return err;
	}
	err = check_password_dat(pw->pass, pw->passlen);
	if (err) {
		return err;
	}
	return 0;
}
