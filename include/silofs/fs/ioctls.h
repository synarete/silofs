/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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

#include <sys/ioctl.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <silofs/fs/defs.h>


enum silofs_query_type {
	SILOFS_QUERY_NONE = 0,
	SILOFS_QUERY_VERSION = 1,
	SILOFS_QUERY_VOLUME = 2,
	SILOFS_QUERY_FSINFO = 3,
	SILOFS_QUERY_INODE = 4,
};

struct silofs_query_version {
	char string[SILOFS_NAME_MAX + 1];
	uint32_t major;
	uint32_t minor;
	uint32_t sublevel;
};

struct silofs_query_volume {
	uint64_t size;
	char     path[SILOFS_REPOPATH_MAX];
};

struct silofs_query_fsinfo {
	int64_t uptime;
	uint64_t msflags;
};

struct silofs_query_inode {
	uint32_t iflags;
	uint32_t dirflags;
};

union silofs_query_u {
	struct silofs_query_version     version;
	struct silofs_query_volume      volume;
	struct silofs_query_fsinfo      fsinfo;
	struct silofs_query_inode       inode;
	uint8_t pad[2040];
};

struct silofs_ioc_query {
	int32_t  qtype;
	uint32_t reserved;
	union silofs_query_u u;
};

enum silofs_tweak_type {
	SILOFS_TWEAK_NONE = 0,
	SILOFS_TWEAK_IFLAGS = 1,
	SILOFS_TWEAK_DIRFLAGS = 2,
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
	uint32_t flags;
	uint32_t reserved[3];
	char     name[SILOFS_NAME_MAX + 1];
	uint8_t  reserved3[240];
};


#define SILOFS_FS_IOC_QUERY     _IOWR('V', 1, struct silofs_ioc_query)
#define SILOFS_FS_IOC_TWEAK     _IOWR('V', 2, struct silofs_ioc_tweak)
#define SILOFS_FS_IOC_CLONE     _IOWR('V', 3, struct silofs_ioc_clone)

#endif /* SILOFS_IOCTLS_H_ */
