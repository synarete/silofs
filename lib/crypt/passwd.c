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
#include <sys/sysinfo.h>
#include <silofs/errors.h>
#include "infra.h"
#include "str.h"
#include "passwd.h"
#include "ivkey.h"

int silofs_password_setup(struct silofs_password *pw, const char *pass)
{
	const size_t len = silofs_str_length(pass);

	return silofs_password_setup2(pw, pass, len);
}

int silofs_password_setup2(struct silofs_password *pw, const void *pass,
                           size_t len)
{
	SILOFS_STATICASSERT_GT(sizeof(pw->pass), SILOFS_PASSWORD_MAX);

	silofs_password_reset(pw);
	if (len < SILOFS_PASSWORD_MIN) {
		return -SILOFS_EILLPASS;
	}
	if (len > SILOFS_PASSWORD_MAX) {
		return -SILOFS_EILLPASS;
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

	silofs_prandomize_with(&u, sizeof(u), (uint64_t)silofs_time_now());
	silofs_password_setup2(pw, &u, sizeof(u));
}
