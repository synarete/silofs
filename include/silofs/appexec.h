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
#include <silofs/boot.h>
#include <silofs/types.h>
#include <silofs/walk.h>

/* file-system's main control object */
struct silofs_env;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_init_once(void);

void silofs_getversions(struct silofs_versions *out_vers);

int silofs_remap_status_code(int status);

int silofs_check_fsname(const char *s);

int silofs_check_fs_xref(const struct silofs_xref *xref);

int silofs_check_ar_xref(const struct silofs_xref *xref);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_create_env(const struct silofs_args *args,
                      struct silofs_env       **out_env);

void silofs_destroy_env(struct silofs_env *env);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_format_repo(struct silofs_env *env);

int silofs_open_repo(struct silofs_env *env);

int silofs_close_repo(struct silofs_env *env);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_get_args(const struct silofs_env *env,
                     struct silofs_args      *out_args);

int silofs_get_fs_xref(struct silofs_env *env, struct silofs_xref *out_xref);

int silofs_set_fs_xref(struct silofs_env *env, const struct silofs_xref *xref);

int silofs_get_ar_xref(struct silofs_env *env, struct silofs_xref *out_xref);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_format_fs(struct silofs_env *env);

int silofs_poke_fs(struct silofs_env *env);

int silofs_open_fs(struct silofs_env *env);

int silofs_close_fs(struct silofs_env *env);

int silofs_run_fs(struct silofs_env *env);

int silofs_post_exec_fs(struct silofs_env *env);

int silofs_fork_fs(struct silofs_env *env, struct silofs_xrefs *out_bas);

int silofs_unref_fs(struct silofs_env *env);

void silofs_halt_fs(struct silofs_env *env);

int silofs_sync_fs(struct silofs_env *env, bool drop);

void silofs_stat_fs(const struct silofs_env   *env,
                    struct silofs_cache_stats *cst);

int silofs_inspect_fs(struct silofs_env *env, silofs_visit_laddr_fn cb,
                      void *user_ctx);

int silofs_archive_fs(struct silofs_env *env);

int silofs_restore_fs(struct silofs_env *env);

int silofs_poke_ar(struct silofs_env *env, const struct silofs_xref *ba);

#endif /* SILOFS_APPEXEC_H_ */
