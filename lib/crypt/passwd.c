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
#include <silofs/configs.h>
#include <silofs/errors.h>
#include <silofs/infra.h>
#include <silofs/str.h>
#include <silofs/crypt/passwd.h>
#include <silofs/crypt/ivkey.h>
#include <sys/sysinfo.h>

int silofs_password_setup(struct silofs_password *pw, const char *pass)
{
	struct silofs_strview sv;

	silofs_password_reset(pw);
	silofs_strview_init(&sv, pass);
	if (sv.len >= sizeof(pw->pass)) {
		return -SILOFS_EINVAL;
	}
	silofs_strview_copyto(&sv, pw->pass, sizeof(pw->pass));
	pw->passlen = sv.len;
	return 0;
}

int silofs_password_setup2(struct silofs_password *pw, const void *pass,
                           size_t len)
{
	silofs_password_reset(pw);
	if (len >= sizeof(pw->pass)) {
		return -SILOFS_EINVAL;
	}
	memcpy(pw->pass, pass, len);
	pw->passlen = len;
	return 0;
}

void silofs_password_reset(struct silofs_password *pw)
{
	silofs_memzero(pw, sizeof(*pw));
	pw->passlen = 0;
}

int silofs_password_check(const struct silofs_password *pw)
{
	if (!pw->passlen || (pw->passlen > sizeof(pw->pass))) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

void silofs_password_mkrand(struct silofs_password *pw)
{
	union {
		uint8_t d[128];
		struct {
			struct sysinfo si;
			pid_t pid;
			uid_t uid;
		} s;
	} u;

	STATICASSERT_LT(sizeof(u), sizeof(pw->pass));

	silofs_memzero(&u, sizeof(u));
	sysinfo(&u.s.si);
	u.s.pid = getpid();
	u.s.uid = getuid();

	silofs_prandomize_with(&u, sizeof(u));
	silofs_password_setup2(pw, &u, sizeof(u));
}
