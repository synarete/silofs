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
#ifndef SILOFS_APPEXEC_H_
#define SILOFS_APPEXEC_H_

#include <silofs/types.h>

struct silofs_alloc;
struct silofs_env;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_init_once(void);

void silofs_getversions(struct silofs_versions *out_vers);

void silofs_getfsmeta(struct silofs_fsmeta *out_fsmeta);

int silofs_remap_status_code(int status);

int silofs_mkpasswd(struct silofs_password *pw, const char *s);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_create_env(const struct silofs_inargs *inargs,
                      const struct silofs_args   *args,
                      struct silofs_env         **out_env);

void silofs_destroy_env(struct silofs_env *env);

int silofs_open_env(struct silofs_env *env, const struct silofs_args *args);

void silofs_get_baseref(const struct silofs_env *env,
                        struct silofs_baseref   *out);

void silofs_collect_stats(const struct silofs_env   *env,
                          struct silofs_cache_stats *out);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_format_repo(struct silofs_env *env);

int silofs_open_repo(struct silofs_env *env);

int silofs_close_repo(struct silofs_env *env);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_format_fs(struct silofs_env *env, struct silofs_fsref *out_fsref);

int silofs_sense_fs(struct silofs_env *env, const struct silofs_fsref *fsref);

int silofs_reload_fs(struct silofs_env *env, const struct silofs_fsref *fsref);

int silofs_unload_fs(struct silofs_env *env);

int silofs_exec_fs(struct silofs_env *env);

void silofs_halt_fs(struct silofs_env *env);

int silofs_post_exec_fs(struct silofs_env *env);

int silofs_fork_fs(struct silofs_env *env, struct silofs_fsrefs *out_fsrefs);

int silofs_sync_fs(struct silofs_env *env, bool drop);

int silofs_inspect_fs(struct silofs_env *env, bool show);

int silofs_archive_fs(struct silofs_env *env, const struct silofs_fsref *fsref,
                      struct silofs_fsref *out_fsref);

int silofs_restore_fs(struct silofs_env *env, const struct silofs_fsref *fsref,
                      struct silofs_fsref *out_fsref);

int silofs_remove_fs(struct silofs_env *env, const struct silofs_fsref *fsref);

#endif /* SILOFS_APPEXEC_H_ */
