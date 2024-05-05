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
#ifndef SILOFS_EXECLIB_H_
#define SILOFS_EXECLIB_H_

/* file-system top-level context */
struct silofs_fs_ctx {
	struct silofs_fs_args   fs_args;
	struct silofs_bootpath  bootpath;
	struct silofs_ivkey     boot_ivkey;
	struct silofs_ivkey     main_ivkey;
	struct silofs_alloc    *alloc;
	struct silofs_lcache   *lcache;
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

int silofs_init_lib(void);

int silofs_new_ctx(const struct silofs_fs_args *args,
                   struct silofs_fs_ctx **out_fs_ctx);

void silofs_del_ctx(struct silofs_fs_ctx *fs_ctx);

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

int silofs_unref_fs(struct silofs_fs_ctx *fs_ctx,
                    const struct silofs_lvid *lvid);

void silofs_halt_fs(struct silofs_fs_ctx *fs_ctx, int signum);

int silofs_sync_fs(struct silofs_fs_ctx *fs_ctx, bool drop);

void silofs_stat_fs(const struct silofs_fs_ctx *fs_ctx,
                    struct silofs_cachestats *cst);

int silofs_inspect_fs(struct silofs_fs_ctx *fs_ctx,
                      silofs_visit_laddr_fn cb, void *user_ctx);

int silofs_export_fs(struct silofs_fs_ctx *fs_ctx, const char *remotedir,
                     struct silofs_hash256 *out_cat_hash);

#endif /* SILOFS_EXECLIB_H_ */
