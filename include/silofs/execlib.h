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
#include <silofs/boot.h>
#include <silofs/stats.h>
#include <silofs/walk.h>

int silofs_init_lib(void);

int silofs_new_fsenv(const struct silofs_fs_args *args,
                     struct silofs_fsenv        **out_fsenv);

void silofs_del_fsenv(struct silofs_fsenv *fsenv);

int silofs_format_repo(struct silofs_fsenv *fsenv);

int silofs_open_repo(struct silofs_fsenv *fsenv);

int silofs_close_repo(struct silofs_fsenv *fsenv);

int silofs_format_fs(struct silofs_fsenv *fsenv,
                     struct silofs_caddr *out_caddr);

int silofs_poke_fs(struct silofs_fsenv       *fsenv,
                   const struct silofs_caddr *caddr);

int silofs_open_fs(struct silofs_fsenv       *fsenv,
                   const struct silofs_caddr *caddr);

int silofs_close_fs(struct silofs_fsenv *fsenv);

int silofs_exec_fs(struct silofs_fsenv *fsenv);

int silofs_post_exec_fs(struct silofs_fsenv *fsenv);

int silofs_fork_fs(struct silofs_fsenv *fsenv,
                   struct silofs_caddr *out_boot_new,
                   struct silofs_caddr *out_boot_alt);

int silofs_unref_fs(struct silofs_fsenv       *fsenv,
                    const struct silofs_caddr *caddr);

void silofs_halt_fs(struct silofs_fsenv *fsenv);

int silofs_sync_fs(struct silofs_fsenv *fsenv, bool drop);

void silofs_stat_fs(const struct silofs_fsenv *fsenv,
                    struct silofs_cachestats  *cst);

int silofs_inspect_fs(struct silofs_fsenv *fsenv, silofs_visit_laddr_fn cb,
                      void *user_ctx);

int silofs_archive_fs(struct silofs_fsenv *fsenv,
                      struct silofs_caddr *out_caddr);

int silofs_restore_fs(struct silofs_fsenv *fsenv,
                      struct silofs_caddr *out_caddr);

int silofs_poke_archive(struct silofs_fsenv       *fsenv,
                        const struct silofs_caddr *caddr);

#endif /* SILOFS_EXECLIB_H_ */
