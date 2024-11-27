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
#ifndef SILOFS_PASSWD_H_
#define SILOFS_PASSWD_H_

#include <silofs/defs.h>
#include <stdlib.h>

/* password octets-buffers */
struct silofs_password {
	uint8_t pass[SILOFS_PASSWORD_MAX + 1];
	size_t  passlen;
};

int silofs_password_setup(struct silofs_password *pw, const char *pass);

int silofs_password_setup2(struct silofs_password *pw, const void *pass,
			   size_t len);

void silofs_password_mkrand(struct silofs_password *pw);

void silofs_password_reset(struct silofs_password *pw);

int silofs_password_check(const struct silofs_password *pw);

#endif /* SILOFS_PASSWD_H_ */
