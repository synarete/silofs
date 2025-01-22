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
#ifndef SILOFS_EXECLIB_H_
#define SILOFS_EXECLIB_H_

#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/boot.h>
#include <silofs/stats.h>
#include <silofs/walk.h>

int silofs_initlib_once(void);

void silofs_require_proper_defs(void);

int silofs_new_env(const struct silofs_env_args *args,
                   struct silofs_env           **out_env);

void silofs_del_env(struct silofs_env *env);

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

#endif /* SILOFS_EXECLIB_H_ */
