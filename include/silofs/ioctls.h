/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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
#ifndef SILOFS_IOCTLS_H_
#define SILOFS_IOCTLS_H_

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/stat.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <silofs/fsdef.h>


enum silofs_query_type {
	SILOFS_QUERY_NONE       = 0,
	SILOFS_QUERY_VERSION    = 1,
	SILOFS_QUERY_BOOTSEC    = 2,
	SILOFS_QUERY_PRSTATS    = 3,
	SILOFS_QUERY_SPSTATS    = 4,
	SILOFS_QUERY_STATX      = 5,
};

enum silofs_tweak_type {
	SILOFS_TWEAK_NONE       = 0,
	SILOFS_TWEAK_IFLAGS     = 1,
	SILOFS_TWEAK_DIRFLAGS   = 2,
};


struct silofs_query_version {
	char     string[SILOFS_NAME_MAX + 1];
	uint32_t major;
	uint32_t minor;
	uint32_t sublevel;
};

struct silofs_query_bootsec {
	char    repo[SILOFS_REPOPATH_MAX];
	char    name[SILOFS_NAME_MAX + 1];
};

struct silofs_query_fsname {
	char    name[SILOFS_NAME_MAX + 1];
};

struct silofs_query_prstats {
	int64_t  uptime;      /* current up-time in seconds */
	uint64_t msflags;     /* mount flags */
	uint64_t memsz_max;
	uint64_t memsz_cur;
	uint64_t bopen_cur;
	uint64_t iopen_max;
	uint64_t iopen_cur;
	uint64_t pad[9];
};

struct silofs_query_spstats {
	struct silofs_space_stats spst;
};

struct silofs_query_statx {
	struct statx stx;
	uint32_t iflags;
	uint32_t dirflags;
};

union silofs_query_u {
	struct silofs_query_version     version;
	struct silofs_query_bootsec     bootsec;
	struct silofs_query_fsname      fsname;
	struct silofs_query_prstats     prstats;
	struct silofs_query_spstats     spstats;
	struct silofs_query_statx       statx;
	uint8_t pad[1984];
};

struct silofs_ioc_query {
	int32_t  qtype;
	uint32_t reserved[15];
	union silofs_query_u u;
};

struct silofs_tweak_flags {
	int32_t  flags;
};

union silofs_tweak_u {
	struct silofs_tweak_flags       iflags;
	struct silofs_tweak_flags       dirflags;
};

struct silofs_ioc_tweak {
	int32_t  ttype;
	uint32_t reserved;
	union silofs_tweak_u u;
};

struct silofs_ioc_clone {
	struct silofs_uuid uuid_new;
	struct silofs_uuid uuid_alt;
};


#define SILOFS_FS_IOC_QUERY     _IOWR('S', 1, struct silofs_ioc_query)
#define SILOFS_FS_IOC_TWEAK     _IOWR('S', 2, struct silofs_ioc_tweak)
#define SILOFS_FS_IOC_CLONE     _IOWR('S', 3, struct silofs_ioc_clone)

#endif /* SILOFS_IOCTLS_H_ */
