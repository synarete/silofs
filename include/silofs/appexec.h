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
struct silofs_ugids;
struct silofs_mntrules;
struct silofs_mntinfos;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_init_once(void);

void silofs_getversions(struct silofs_versions *out_vers);

int silofs_remap_status_code(int status);

int silofs_check_fsname(const char *s);

int silofs_check_blobref(const struct silofs_blobref *blobref);

int silofs_assign_blobref(struct silofs_blobref *blobref, const char *s);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_parse_fsids(struct silofs_ugids *ugids, struct silofs_alloc *alloc,
                       const char *conf);

int silofs_unparse_fsids(const struct silofs_ugids *ugids,
                         struct silofs_alloc *alloc, char *buf, size_t n);

void silofs_release_fsids(struct silofs_ugids *ugids,
                          struct silofs_alloc *alloc);

int silofs_extend_fsids(struct silofs_ugids *ugids, struct silofs_alloc *alloc,
                        const char *user, bool with_sup_groups);

int silofs_parse_mntrules(struct silofs_mntrules *mrules,
                          struct silofs_alloc *alloc, const char *conf);

void silofs_release_mntrules(struct silofs_mntrules *mrules,
                             struct silofs_alloc    *alloc);

int silofs_parse_mntinfos(struct silofs_mntinfos *minfos,
                          struct silofs_alloc *alloc, const char *conf);

void silofs_release_mntinfos(struct silofs_mntinfos *minfos,
                             struct silofs_alloc    *alloc);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_create_env(const struct silofs_env_args *args,
                      struct silofs_env           **out_env);

void silofs_destroy_env(struct silofs_env *env);

const struct silofs_env_args *
silofs_get_env_args(const struct silofs_env *env);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_format_repo(struct silofs_env *env);

int silofs_open_repo(struct silofs_env *env);

int silofs_close_repo(struct silofs_env *env);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_format_fs(struct silofs_env     *env,
                     struct silofs_blobref *out_blobref);

int silofs_sense_fs(struct silofs_env           *env,
                    const struct silofs_blobref *fs_blobref);

int silofs_sense_ar(struct silofs_env           *env,
                    const struct silofs_blobref *ar_blobref);

int silofs_open_fs(struct silofs_env           *env,
                   const struct silofs_blobref *fs_blobref);

int silofs_close_fs(struct silofs_env *env);

int silofs_exec_fs(struct silofs_env *env);

void silofs_halt_fs(struct silofs_env *env);

int silofs_post_exec_fs(struct silofs_env *env);

int silofs_fork_fs(struct silofs_env *env, struct silofs_blobref *out_main,
                   struct silofs_blobref *out_fork);

int silofs_remove_fs(struct silofs_env           *env,
                     const struct silofs_blobref *blobref);

int silofs_sync_fs(struct silofs_env *env, bool drop);

void silofs_stat_fs(const struct silofs_env   *env,
                    struct silofs_cache_stats *cst);

int silofs_inspect_fs(struct silofs_env *env, bool show);

int silofs_archive_fs(struct silofs_env           *env,
                      const struct silofs_blobref *fs_blobref,
                      struct silofs_blobref       *out_ar_blobref);

int silofs_restore_fs(struct silofs_env           *env,
                      const struct silofs_blobref *ar_blobref,
                      struct silofs_blobref       *out_fs_blobref);

#endif /* SILOFS_APPEXEC_H_ */
