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
#include <silofs/defs.h>

/* maximal size of ioctl input argument */
#define SILOFS_IOC_SIZE_MAX     (2048)

/* supported ioctl commands */
#define SILOFS_IOC_QUERY        _IOWR('S', 1, struct silofs_ioc_query)
#define SILOFS_IOC_CLONE        _IOWR('S', 2, struct silofs_ioc_clone)
#define SILOFS_IOC_SYNCFS       _IOW('S', 3, struct silofs_ioc_syncfs)
#define SILOFS_IOC_TUNE         _IOW('S', 4, struct silofs_ioc_tune)


enum silofs_query_type {
	SILOFS_QUERY_NONE       = 0,
	SILOFS_QUERY_VERSION    = 1,
	SILOFS_QUERY_REPO       = 2,
	SILOFS_QUERY_BOOT       = 3,
	SILOFS_QUERY_PROC       = 4,
	SILOFS_QUERY_SPSTATS    = 5,
	SILOFS_QUERY_STATX      = 6,
};

struct silofs_query_version {
	char     string[SILOFS_NAME_MAX + 1];
	uint32_t major;
	uint32_t minor;
	uint32_t sublevel;
};

struct silofs_query_repo {
	char    path[SILOFS_REPOPATH_MAX];
};

struct silofs_query_boot {
	char    name[SILOFS_NAME_MAX + 1];
	char    fsid[SILOFS_NAME_MAX + 1];
};

struct silofs_query_proc {
	int64_t  pid;
	uint32_t uid;
	uint32_t gid;
	int64_t  uptime;      /* current up-time in seconds */
	uint64_t msflags;     /* mount flags */
	uint64_t memsz_max;
	uint64_t memsz_cur;
	uint64_t bopen_cur;
	uint64_t iopen_max;
	uint64_t iopen_cur;
	uint64_t pad[23];
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
	struct silofs_query_repo        repo;
	struct silofs_query_boot        boot;
	struct silofs_query_proc        proc;
	struct silofs_query_spstats     spstats;
	struct silofs_query_statx       statx;
	uint8_t pad[1984];
};

struct silofs_ioc_query {
	int32_t  qtype;
	uint32_t reserved[15];
	union silofs_query_u u;
};

struct silofs_ioc_clone {
	struct silofs_lvid lvid_new;
	struct silofs_lvid lvid_alt;
};

struct silofs_ioc_syncfs {
	uint32_t flags;
	uint32_t pad[7];
};

struct silofs_ioc_tune {
	uint32_t iflags_want;
	uint32_t iflags_dont;
	uint32_t pad[60];
};

union silofs_ioc_u {
	uint8_t buf[SILOFS_IOC_SIZE_MAX];
	struct silofs_ioc_query         query;
	struct silofs_ioc_clone         clone;
	struct silofs_ioc_syncfs        syncfs;
	struct silofs_ioc_tune          tune;
};

#endif /* SILOFS_IOCTLS_H_ */
