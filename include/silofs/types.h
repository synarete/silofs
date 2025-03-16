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

#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <silofs/macros.h>
#include <silofs/defs.h>

/* file-system's top-level control flags */
enum silofs_flags {
	SILOFS_F_PEDANTIC     = SILOFS_BIT(0),
	SILOFS_F_RDONLY       = SILOFS_BIT(1),
	SILOFS_F_NOEXEC       = SILOFS_BIT(2),
	SILOFS_F_NOSUID       = SILOFS_BIT(3),
	SILOFS_F_NODEV        = SILOFS_BIT(4),
	SILOFS_F_WITHFUSE     = SILOFS_BIT(5),
	SILOFS_F_NLOOKUP      = SILOFS_BIT(6),
	SILOFS_F_WRITEBACK    = SILOFS_BIT(7),
	SILOFS_F_MAYSPLICE    = SILOFS_BIT(8),
	SILOFS_F_ALLOWOTHER   = SILOFS_BIT(9),
	SILOFS_F_ALLOWADMIN   = SILOFS_BIT(10),
	SILOFS_F_ALLOWXACL    = SILOFS_BIT(11),
	SILOFS_F_ALLOWHOSTIDS = SILOFS_BIT(12),
	SILOFS_F_ASYNCWR      = SILOFS_BIT(13),
	SILOFS_F_LAZYTIME     = SILOFS_BIT(14),
	SILOFS_F_STDALLOC     = SILOFS_BIT(15),
};

/* exported-reference address string */
struct silofs_xref {
	char s[SILOFS_XREFLEN_MAX + 1];
};

/* file-system's boot arguments */
struct silofs_boot_args {
	struct silofs_xref xref;
	const char        *repodir;
	const char        *fsname;
	const char        *arname;
	const char        *passwd;
	const char        *mntdir;
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

/* users & groups id-mappings */
struct silofs_ugids {
	struct silofs_users_ids  users;
	struct silofs_groups_ids groups;
};

/* input arguments */
struct silofs_args {
	struct silofs_boot_args boot;
	struct silofs_ugids     ugids;
	enum silofs_flags       flags;
	uid_t                   uid;
	gid_t                   gid;
	pid_t                   pid;
	mode_t                  umask;
	size_t                  capacity;
	size_t                  memwant;
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
	size_t ncache_unodes;
	size_t ncache_vnodes;
};

#endif /* SILOFS_TYPES_H_ */
