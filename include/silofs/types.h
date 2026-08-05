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
#ifndef SILOFS_TYPES_H_
#define SILOFS_TYPES_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include <silofs/macros.h>
#include <silofs/ondisk.h>

/* file-system's top-level control flags */
enum silofs_flags {
	SILOFS_F_PEDANTIC      = SILOFS_BIT(0),
	SILOFS_F_RDONLY        = SILOFS_BIT(1),
	SILOFS_F_ALLOW_EXEC    = SILOFS_BIT(2),
	SILOFS_F_ALLOW_SUID    = SILOFS_BIT(3),
	SILOFS_F_ALLOW_DEV     = SILOFS_BIT(4),
	SILOFS_F_ALLOW_OTHER   = SILOFS_BIT(5),
	SILOFS_F_ALLOW_ADMIN   = SILOFS_BIT(6),
	SILOFS_F_ALLOW_XACL    = SILOFS_BIT(7),
	SILOFS_F_ALLOW_HOSTIDS = SILOFS_BIT(8),
	SILOFS_F_ALLOW_ISOCK   = SILOFS_BIT(9),
	SILOFS_F_ALLOW_IFIFO   = SILOFS_BIT(10),
	SILOFS_F_WITH_FUSE     = SILOFS_BIT(11),
	SILOFS_F_NLOOKUP       = SILOFS_BIT(12),
	SILOFS_F_NO_WRITEBACK  = SILOFS_BIT(13),
	SILOFS_F_AUTOINVAL     = SILOFS_BIT(14),
	SILOFS_F_MAY_SPLICE    = SILOFS_BIT(15),
	SILOFS_F_ASYNCWR       = SILOFS_BIT(16),
	SILOFS_F_LAZYTIME      = SILOFS_BIT(17),
	SILOFS_F_STDALLOC      = SILOFS_BIT(18),
	SILOFS_F_NOPASSWD      = SILOFS_BIT(19),
	SILOFS_F_UTF8NAMES     = SILOFS_BIT(20),
};

/* password as octets-buffers with explicit length */
struct silofs_password {
	uint8_t pass[SILOFS_PASSWORD_MAX];
	uint8_t passlen;
};

/* a pair of repo-directory and reference name */
struct silofs_baseref {
	const char *repodir;
	const char *refname;
};

/* global meta-info */
struct silofs_fsmeta {
	char     version[64];
	uint32_t fmtvers;
	uint32_t reserved;
	uint64_t timestamp;
	uint8_t  reserved2[48];
};

/* user-credentials */
struct silofs_cred {
	uid_t  uid;
	gid_t  gid;
	mode_t umask;
};

/* credential mapping (host to fs-internal) */
struct silofs_creds {
	struct silofs_cred host_cred;
	struct silofs_cred fs_cred;
};

/* user-id host-to-fs bidirectional-mapping */
struct silofs_uids {
	uid_t host_uid;
	uid_t fs_uid;
};

/* group-id host-to-fs bidirectional-mapping */
struct silofs_gids {
	gid_t host_gid;
	gid_t fs_gid;
};

/* file-system's input user-ids list */
struct silofs_users_ids {
	struct silofs_uids *uids;
	size_t              nuids;
};

/* file-system's input group-ids list */
struct silofs_groups_ids {
	struct silofs_gids *gids;
	size_t              ngids;
};

/* file-system's users/groups host-to-internal id-mappings */
struct silofs_fsids {
	struct silofs_users_ids  users;
	struct silofs_groups_ids groups;
};

/* main-boot-record address (ascii-string representation) */
struct silofs_mbaddr {
	char mba[128];
};

/* file-system meta & reference */
struct silofs_fsref {
	struct silofs_fsmeta fsmeta;
	struct silofs_mbaddr mbaddr;
};

/* file-system meta & forks-reference */
struct silofs_fsrefs {
	struct silofs_fsref main;
	struct silofs_fsref base;
	struct silofs_fsref fork;
};

/* file-system's input specification */
struct silofs_spec {
	struct silofs_baseref  bref[2];
	struct silofs_password passwd;
	struct silofs_fsref    fsref;
	struct silofs_fsids    fsids;
	struct silofs_cred     fsowner;
	enum silofs_flags      flags;
	size_t                 fscap;
};

/* in-use versions */
struct silofs_versions {
	const char *silofs_version;
	const char *gcrypt_version;
	const char *zstd_version;
};

/* inode's time-stamps (birth, access, modify, change) */
struct silofs_itimes {
	struct timespec btime;
	struct timespec atime;
	struct timespec mtime;
	struct timespec ctime;
};

#endif /* SILOFS_TYPES_H_ */
