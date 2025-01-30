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
#ifndef SILOFS_APPEXEC_H_
#define SILOFS_APPEXEC_H_

#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/boot.h>
#include <silofs/walk.h>

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
	struct silofs_bootref bref;
	struct silofs_ugids   ids;
	enum silofs_flags     flags;
	uid_t                 uid;
	gid_t                 gid;
	pid_t                 pid;
	mode_t                umask;
	size_t                capacity;
	size_t                memwant;
};

/* in-use versions */
struct silofs_versions {
	const char *silofs_version;
	const char *gcrypt_version;
	const char *zstd_version;
};

/* space accounting per sub-type */
struct silofs_spacegauges {
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
struct silofs_spacestats {
	time_t                    btime;
	time_t                    ctime;
	size_t                    capacity;
	size_t                    vspacesize;
	uint64_t                  generation;
	struct silofs_spacegauges lsegs;
	struct silofs_spacegauges bks;
	struct silofs_spacegauges objs;
};

/* file-system' internal cache stats */
struct silofs_cachestats {
	size_t nalloc_bytes;
	size_t ncache_unodes;
	size_t ncache_vnodes;
};

/* file-system's main control object */
struct silofs_env;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_init_once(void);

int silofs_create_env(const struct silofs_args *args,
                      struct silofs_env       **out_env);

void silofs_destroy_env(struct silofs_env *env);

int silofs_format_repo(struct silofs_env *env);

int silofs_open_repo(struct silofs_env *env);

int silofs_close_repo(struct silofs_env *env);

int silofs_format_fs(struct silofs_env *env, struct silofs_caddr *out_caddr);

int silofs_poke_fs(struct silofs_env *env, const struct silofs_caddr *caddr);

int silofs_open_fs(struct silofs_env *env, const struct silofs_caddr *caddr);

int silofs_close_fs(struct silofs_env *env);

int silofs_run_fs(struct silofs_env *env);

int silofs_post_exec_fs(struct silofs_env *env);

int silofs_fork_fs(struct silofs_env *env, struct silofs_caddr *out_boot_new,
                   struct silofs_caddr *out_boot_alt);

int silofs_unref_fs(struct silofs_env *env, const struct silofs_caddr *caddr);

void silofs_halt_fs(struct silofs_env *env);

int silofs_sync_fs(struct silofs_env *env, bool drop);

void silofs_stat_fs(const struct silofs_env  *env,
                    struct silofs_cachestats *cst);

int silofs_inspect_fs(struct silofs_env *env, silofs_visit_laddr_fn cb,
                      void *user_ctx);

int silofs_archive_fs(struct silofs_env *env, struct silofs_caddr *out_caddr);

int silofs_restore_fs(struct silofs_env *env, struct silofs_caddr *out_caddr);

int silofs_poke_archive(struct silofs_env         *env,
                        const struct silofs_caddr *caddr);

void silofs_getargs(const struct silofs_env *env,
                    struct silofs_args      *out_args);

int silofs_remap_status_code(int status);

int silofs_check_fsname(const char *s);

void silofs_getversions(struct silofs_versions *out_vers);

#endif /* SILOFS_APPEXEC_H_ */
