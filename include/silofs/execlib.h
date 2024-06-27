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

#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/fs/boot.h>
#include <silofs/fs/stats.h>

/* file-system top-level context */
struct silofs_fs_ctx {
	struct silofs_fs_args   args;
	struct silofs_alloc    *alloc;
	struct silofs_lcache   *lcache;
	struct silofs_repo     *repo;
	struct silofs_submitq  *submitq;
	struct silofs_flusher  *flusher;
	struct silofs_idsmap   *idsmap;
	struct silofs_fsenv    *fsenv;
	struct silofs_fuseq    *fuseq;
	struct silofs_password *password;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_init_lib(void);

int silofs_new_ctx(const struct silofs_fs_args *args,
                   struct silofs_fs_ctx **out_fs_ctx);

void silofs_del_ctx(struct silofs_fs_ctx *fs_ctx);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_format_repo(struct silofs_fsenv *fsenv);

int silofs_open_repo(struct silofs_fsenv *fsenv);

int silofs_close_repo(struct silofs_fsenv *fsenv);

int silofs_format_fs(struct silofs_fsenv *fsenv,
                     struct silofs_caddr *out_caddr);

int silofs_boot_fs(struct silofs_fsenv *fsenv,
                   const struct silofs_caddr *boot_ref);

int silofs_open_fs(struct silofs_fsenv *fsenv);

int silofs_poke_fs(struct silofs_fsenv *fsenv,
                   const struct silofs_caddr *caddr,
                   struct silofs_bootrec *out_brec);

int silofs_close_fs(struct silofs_fsenv *fsenv);

int silofs_exec_fs(struct silofs_fsenv *fsenv);

int silofs_post_exec_fs(struct silofs_fsenv *fsenv);

int silofs_fork_fs(struct silofs_fsenv *fsenv,
                   struct silofs_caddr *out_boot_new,
                   struct silofs_caddr *out_boot_alt);

int silofs_unref_fs(struct silofs_fsenv *fsenv,
                    const struct silofs_caddr *caddr);

void silofs_halt_fs(struct silofs_fsenv *fsenv);

int silofs_sync_fs(struct silofs_fsenv *fsenv, bool drop);

void silofs_stat_fs(const struct silofs_fsenv *fsenv,
                    struct silofs_cachestats *cst);

int silofs_inspect_fs(struct silofs_fsenv *fsenv,
                      silofs_visit_laddr_fn cb, void *user_ctx);

int silofs_pack_fs(struct silofs_fsenv *fsenv,
                   struct silofs_caddr *out_caddr);

int silofs_unpack_fs(struct silofs_fsenv *fsenv,
                     const struct silofs_caddr *caddr);

#endif /* SILOFS_EXECLIB_H_ */
