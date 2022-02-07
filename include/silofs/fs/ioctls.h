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
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <silofs/fs/defs.h>


enum silofs_query_type {
	SILOFS_QUERY_NONE       = 0,
	SILOFS_QUERY_VERSION    = 1,
	SILOFS_QUERY_REPO       = 2,
	SILOFS_QUERY_FSNAME     = 3,
	SILOFS_QUERY_STATFSX    = 4,
	SILOFS_QUERY_STATX      = 5,
};

enum silofs_tweak_type {
	SILOFS_TWEAK_NONE       = 0,
	SILOFS_TWEAK_IFLAGS     = 1,
	SILOFS_TWEAK_DIRFLAGS   = 2,
};


struct silofs_query_version {
	char     v_str[SILOFS_NAME_MAX + 1];
	uint32_t v_major;
	uint32_t v_minor;
	uint32_t v_sublevel;
};

struct silofs_query_repo {
	char    r_path[SILOFS_REPOPATH_MAX];
};

struct silofs_query_fsname {
	char    f_name[SILOFS_NAME_MAX + 1];
};

struct silofs_query_statfsx {
	uint64_t f_msflags;     /* mount flags */
	int64_t  f_uptime;      /* current up-time in seconds */
	uint64_t f_bsize;       /* size of fs in bytes */
	uint64_t f_bused;       /* number of used bytes */
	uint64_t f_ilimit;      /* max number of inodes */
	uint64_t f_icurr;       /* currently used inodes */
	uint64_t f_umeta;       /* uspace used meta bytes */
	uint64_t f_vmeta;       /* vspace used meta bytes */
	uint64_t f_vdata;       /* vspace used data bytes */
};

struct silofs_query_statx {
	struct statx stx;
	uint32_t stx_iflags;
	uint32_t stx_dirflags;
};

union silofs_query_u {
	struct silofs_query_version     version;
	struct silofs_query_repo        repo;
	struct silofs_query_fsname      fsname;
	struct silofs_query_statfsx     statfsx;
	struct silofs_query_statx       statx;
	uint8_t pad[2040];
};

struct silofs_ioc_query {
	int32_t  qtype;
	uint32_t reserved;
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
	char     name[SILOFS_NAME_MAX + 1];
	uint32_t flags;
	uint8_t  reserved[252];
};


#define SILOFS_FS_IOC_QUERY     _IOWR('S', 1, struct silofs_ioc_query)
#define SILOFS_FS_IOC_TWEAK     _IOWR('S', 2, struct silofs_ioc_tweak)
#define SILOFS_FS_IOC_CLONE     _IOWR('S', 3, struct silofs_ioc_clone)

#endif /* SILOFS_IOCTLS_H_ */
