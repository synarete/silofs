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
	SILOFS_F_PEDANTIC     = SILOFS_BIT(0),
	SILOFS_F_RDONLY       = SILOFS_BIT(1),
	SILOFS_F_NOEXEC       = SILOFS_BIT(2),
	SILOFS_F_NOSUID       = SILOFS_BIT(3),
	SILOFS_F_NODEV        = SILOFS_BIT(4),
	SILOFS_F_WITHFUSE     = SILOFS_BIT(5),
	SILOFS_F_NLOOKUP      = SILOFS_BIT(6),
	SILOFS_F_NOWRITEBACK  = SILOFS_BIT(7),
	SILOFS_F_AUTOINVAL    = SILOFS_BIT(8),
	SILOFS_F_MAYSPLICE    = SILOFS_BIT(9),
	SILOFS_F_ALLOWOTHER   = SILOFS_BIT(10),
	SILOFS_F_ALLOWADMIN   = SILOFS_BIT(11),
	SILOFS_F_ALLOWXACL    = SILOFS_BIT(12),
	SILOFS_F_ALLOWHOSTIDS = SILOFS_BIT(13),
	SILOFS_F_ASYNCWR      = SILOFS_BIT(14),
	SILOFS_F_LAZYTIME     = SILOFS_BIT(15),
	SILOFS_F_STDALLOC     = SILOFS_BIT(16),
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
	struct silofs_fsmeta     fsmeta;
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

/* fs root specification */
struct silofs_spec {
	struct silofs_fsref fsref;
	struct silofs_fsids fsids;
};

/* input arguments */
struct silofs_args {
	struct silofs_fsids   fsids;
	struct silofs_baseref bref[2];
	const char           *mntdir;
	const char           *passwd;
	enum silofs_flags     flags;
	uid_t                 uid;
	gid_t                 gid;
	pid_t                 pid;
	mode_t                umask;
	size_t                capacity;
	size_t                memwant;
	bool                  no_ispecial;
	bool                  no_utf8_names;
};

/* in-use versions */
struct silofs_versions {
	const char *silofs_version;
	const char *gcrypt_version;
	const char *zstd_version;
};

/* space accounting per sub-type */
struct silofs_space_gauges {
	ssize_t nsuper;
	ssize_t nspnode;
	ssize_t nspleaf;
	ssize_t nlsmap;
	ssize_t ninode;
	ssize_t nxanode;
	ssize_t ndtnode;
	ssize_t nsymval;
	ssize_t nftnode;
	ssize_t ndata1k;
	ssize_t ndata4k;
	ssize_t ndatabk;
};

/* space accounting per sub-kind + sub-type */
struct silofs_space_stats {
	time_t                     btime;
	time_t                     ctime;
	size_t                     capacity;
	size_t                     vspacesize;
	uint64_t                   generation;
	struct silofs_space_gauges lsegs;
	struct silofs_space_gauges bks;
	struct silofs_space_gauges objs;
};

/* file-system' internal cache stats */
struct silofs_cache_stats {
	size_t nalloc_bytes;
	size_t ncache_nodes;
};

/* inode's time-stamps (birth, access, modify, change) */
struct silofs_itimes {
	struct timespec btime;
	struct timespec atime;
	struct timespec mtime;
	struct timespec ctime;
};

#endif /* SILOFS_TYPES_H_ */
