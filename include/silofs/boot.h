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
#ifndef SILOFS_BOOT_H_
#define SILOFS_BOOT_H_

#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/types.h>

struct silofs_env;
struct silofs_task;

/* boot pathname: a pair of repo-directory & boot-record name (optional) */
struct silofs_bootpath {
	struct silofs_strview repodir;
	struct silofs_strview name;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* file-system's control flags (as explicit booleans) */
struct silofs_fs_cflags {
	bool pedantic;
	bool rdonly;
	bool noexec;
	bool nosuid;
	bool nodev;
	bool with_fuse;
	bool asyncwr;
	bool allow_admin;
	bool allow_other;
	bool allow_hostids;
	bool allow_xattr_acl;
	bool writeback_cache;
	bool may_splice;
	bool lazytime;
	bool stdalloc;
};

/* file-system's boot reference */
struct silofs_fs_bref {
	struct silofs_caddr caddr;
	const char         *repodir;
	const char         *name;
	const char         *passwd;
};

/* file-system's arguments */
struct silofs_fs_args {
	struct silofs_fs_bref   bref;
	struct silofs_fs_ids    ids;
	struct silofs_fs_cflags cflags;
	const char             *mntdir;
	uid_t                   uid;
	gid_t                   gid;
	pid_t                   pid;
	mode_t                  umask;
	size_t                  capacity;
	size_t                  memwant;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bootpath_setup(struct silofs_bootpath *bp, const char *repodir,
                          const char *name);

void silofs_bootref_init(struct silofs_fs_bref *bref);

void silofs_bootref_fini(struct silofs_fs_bref *bref);

void silofs_bootref_assign(struct silofs_fs_bref       *bref,
                           const struct silofs_fs_bref *other);

void silofs_bootref_update(struct silofs_fs_bref     *bref,
                           const struct silofs_caddr *caddr, const char *name);

int silofs_bootref_import(struct silofs_fs_bref       *bref,
                          const struct silofs_strview *sv);

void silofs_bootref_export(const struct silofs_fs_bref *bref,
                           struct silofs_strbuf        *sbuf);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_reload_vspace(struct silofs_task *task);

int silofs_reload_rootd(struct silofs_task *task);

#endif /* SILOFS_BOOT_H_ */
