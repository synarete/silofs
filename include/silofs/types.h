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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <gcrypt.h>
#include <iconv.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <silofs/defs.h>
#include <silofs/infra.h>
#include <silofs/str.h>

/* common control flags */
enum silofs_ctlf {
	SILOFS_CTLF_NOW     = SILOFS_BIT(0),
	SILOFS_CTLF_FSYNC   = SILOFS_BIT(1),
	SILOFS_CTLF_RELEASE = SILOFS_BIT(2),
	SILOFS_CTLF_BRINGUP = SILOFS_BIT(4),
	SILOFS_CTLF_OPSTART = SILOFS_BIT(5),
	SILOFS_CTLF_INTERN  = SILOFS_BIT(6),
	SILOFS_CTLF_IDLE    = SILOFS_BIT(7),
};

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

/* inode's time-stamps (birth, access, modify, change) */
struct silofs_itimes {
	struct timespec btime;
	struct timespec atime;
	struct timespec mtime;
	struct timespec ctime;
};

#endif /* SILOFS_TYPES_H_ */
