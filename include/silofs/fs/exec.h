/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#ifndef SILOFS_EXEC_H_
#define SILOFS_EXEC_H_

/* initialization configurations */
struct silofs_iconf {
	struct silofs_namebuf   name;
	struct silofs_uuid      uuid;
	struct silofs_ids       ids;
};

/* file-system input arguments */
struct silofs_fs_args {
	struct silofs_iconf     iconf;
	const char             *repodir;
	const char             *name;
	const char             *mntdir;
	const char             *passwd;
	uid_t                   uid;
	gid_t                   gid;
	pid_t                   pid;
	mode_t                  umask;
	size_t                  capacity;
	size_t                  memwant;
	bool                    withfuse;
	bool                    pedantic;
	bool                    allowother;
	bool                    allowhostids;
	bool                    allowadmin;
	bool                    writeback_cache;
	bool                    lazytime;
	bool                    noexec;
	bool                    nosuid;
	bool                    nodev;
	bool                    rdonly;
	bool                    asyncwr;
	bool                    stdalloc;
};

/* file-system top-level context */
struct silofs_fs_ctx {
	struct silofs_fs_args   fs_args;
	struct silofs_bootpath  bootpath;
	struct silofs_ivkey     ivkey_boot;
	struct silofs_ivkey     ivkey_main;
	struct silofs_alloc    *alloc;
	struct silofs_cache    *cache;
	struct silofs_repo     *repo;
	struct silofs_submitq  *submitq;
	struct silofs_flusher  *flusher;
	struct silofs_idsmap   *idsmap;
	struct silofs_fsenv    *fsenv;
	struct silofs_fuseq    *fuseq;
	struct silofs_password *password;
	struct silofs_uaddr     sb_addr;
	int                     signum;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_new_fs_ctx(const struct silofs_fs_args *args,
                      struct silofs_fs_ctx **out_fs_ctx);

void silofs_del_fs_ctx(struct silofs_fs_ctx *fs_ctx);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_format_repo(struct silofs_fs_ctx *fs_ctx);

int silofs_open_repo(struct silofs_fs_ctx *fs_ctx);

int silofs_close_repo(struct silofs_fs_ctx *fs_ctx);

int silofs_format_fs(struct silofs_fs_ctx *fs_ctx,
                     struct silofs_lvid *out_lvid);

int silofs_boot_fs(struct silofs_fs_ctx *fs_ctx,
                   const struct silofs_lvid *lvid);

int silofs_open_fs(struct silofs_fs_ctx *fs_ctx);

int silofs_poke_fs(struct silofs_fs_ctx *fs_ctx,
                   const struct silofs_lvid *out_lvid,
                   struct silofs_bootrec *out_brec);

int silofs_close_fs(struct silofs_fs_ctx *fs_ctx);

int silofs_exec_fs(struct silofs_fs_ctx *fs_ctx);

int silofs_post_exec_fs(const struct silofs_fs_ctx *fs_ctx);

int silofs_fork_fs(struct silofs_fs_ctx *fs_ctx,
                   struct silofs_lvid *out_new,
                   struct silofs_lvid *out_alt);

int silofs_inspect_fs(struct silofs_fs_ctx *fs_ctx, silofs_visit_laddr_fn cb);

int silofs_unref_fs(struct silofs_fs_ctx *fs_ctx,
                    const struct silofs_lvid *lvid);

void silofs_halt_fs(struct silofs_fs_ctx *fs_ctx, int signum);

int silofs_sync_fs(struct silofs_fs_ctx *fs_ctx, bool drop);

void silofs_stat_fs(const struct silofs_fs_ctx *fs_ctx,
                    struct silofs_cachestats *cst);

#endif /* SILOFS_EXEC_H_ */
