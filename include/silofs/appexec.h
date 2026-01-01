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

#include <silofs/types.h>

struct silofs_alloc;
struct silofs_env;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_init_once(void);

void silofs_getversions(struct silofs_versions *out_vers);

int silofs_remap_status_code(int status);

int silofs_check_fsname(const char *s);

int silofs_encode_mbref(const struct silofs_mbref *mbref, char *s, size_t n);

int silofs_decode_mbref(struct silofs_mbref *mbref, const char *s);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_create_env(const struct silofs_env_args *args,
                      struct silofs_env           **out_env);

void silofs_destroy_env(struct silofs_env *env);

void silofs_get_boot_args(const struct silofs_env *env,
                          struct silofs_boot_args *out);

void silofs_collect_stats(const struct silofs_env   *env,
                          struct silofs_cache_stats *out);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_format_repo(struct silofs_env *env);

int silofs_open_repo(struct silofs_env *env);

int silofs_close_repo(struct silofs_env *env);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_format_fs(struct silofs_env *env, struct silofs_mbref *out_mbref);

int silofs_sense_fs(struct silofs_env         *env,
                    const struct silofs_mbref *fs_mbref);

int silofs_sense_ar(struct silofs_env         *env,
                    const struct silofs_mbref *ar_mbref);

int silofs_open_fs(struct silofs_env         *env,
                   const struct silofs_mbref *fs_mbref);

int silofs_close_fs(struct silofs_env *env);

int silofs_exec_fs(struct silofs_env *env);

void silofs_halt_fs(struct silofs_env *env);

int silofs_post_exec_fs(struct silofs_env *env);

int silofs_fork_fs(struct silofs_env *env, struct silofs_mbrefs *out_mbrefs);

int silofs_remove_fs(struct silofs_env *env, const struct silofs_mbref *mbref);

int silofs_sync_fs(struct silofs_env *env, bool drop);

int silofs_inspect_fs(struct silofs_env *env, bool show);

int silofs_archive_fs(struct silofs_env         *env,
                      const struct silofs_mbref *fs_mbref,
                      struct silofs_mbref       *out_ar_mbref);

int silofs_restore_fs(struct silofs_env         *env,
                      const struct silofs_mbref *ar_mbref,
                      struct silofs_mbref       *out_fs_mbref);

#endif /* SILOFS_APPEXEC_H_ */
