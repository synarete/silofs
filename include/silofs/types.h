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
#ifndef SILOFS_TYPES_H_
#define SILOFS_TYPES_H_

#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <silofs/defs.h>
#include <silofs/infra.h>
#include <silofs/str.h>

/* name-string: a pair of string-view and (optional) 64-bits hash */
struct silofs_namestr {
	struct silofs_strview sv;
	uint64_t              hash;
};

/* user-credentials */
struct silofs_cred {
	uid_t  uid;
	gid_t  gid;
	mode_t umask;
};

/* external-internal credentials + time */
struct silofs_creds {
	struct silofs_cred host_cred;
	struct silofs_cred fs_cred;
	struct timespec    ts;
};

/* credentials with time-stamp */
struct silofs_tcreds {
	struct timespec     ts;
	struct silofs_creds cs;
};

#endif /* SILOFS_TYPES_H_ */
