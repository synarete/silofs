/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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
#ifndef SILOFS_UBER_H_
#define SILOFS_UBER_H_

#include <silofs/fs/types.h>

int silofs_uber_init(struct silofs_fs_uber *uber,
                     struct silofs_alloc *alloc,
                     struct silofs_kivam *kivam,
                     struct silofs_repo *mrepo,
                     struct silofs_repo *crepo);

void silofs_uber_fini(struct silofs_fs_uber *uber);

void silofs_uber_shut(struct silofs_fs_uber *uber);

void silofs_uber_relax_caches(const struct silofs_fs_uber *uber, int flags);

int silofs_uber_spawn_supers(struct silofs_fs_uber *uber, size_t capacity,
                             struct silofs_sb_info **out_sbi);

int silofs_uber_stage_supers(struct silofs_fs_uber *uber,
                             const struct silofs_uaddr *uaddr,
                             struct silofs_sb_info **out_sbi);

int silofs_uber_format_supers(struct silofs_fs_uber *uber, size_t capacity);

int silofs_uber_reload_supers(struct silofs_fs_uber *uber,
                              const struct silofs_uaddr *sb_uaddr);


int silofs_uber_forkfs(struct silofs_fs_uber *uber,
                       struct silofs_bootsec *out_bsec);

int silofs_uber_flush_dirty(const struct silofs_fs_uber *uber, int flags);

int silofs_exec_kcopy_by(struct silofs_fs_uber *uber,
                         const struct silofs_xiovec *xiov_src,
                         const struct silofs_xiovec *xiov_dst, size_t len);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_spawn_super_at(struct silofs_fs_uber *uber, bool main,
                          const struct silofs_uaddr *uaddr,
                          struct silofs_sb_info **out_sbi);

int silofs_stage_super_at(struct silofs_fs_uber *uber, bool main,
                          const struct silofs_uaddr *uaddr,
                          struct silofs_sb_info **out_sbi);

int silofs_shadow_super_at(struct silofs_fs_uber *uber, bool main,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_sb_info **out_sbi);


int silofs_spawn_stats_at(struct silofs_fs_uber *uber, bool main,
                          const struct silofs_uaddr *uaddr,
                          struct silofs_spstat_info **out_sti);

int silofs_stage_stats_at(struct silofs_fs_uber *uber, bool main,
                          const struct silofs_uaddr *uaddr,
                          struct silofs_spstat_info **out_sti);

int silofs_shadow_stats_at(struct silofs_fs_uber *uber, bool main,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spstat_info **out_sti);


int silofs_spawn_spnode_at(struct silofs_fs_uber *uber, bool main,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spnode_info **out_sni);

int silofs_stage_spnode_at(struct silofs_fs_uber *uber, bool main,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spnode_info **out_sni);

int silofs_shadow_spnode_at(struct silofs_fs_uber *uber, bool main,
                            const struct silofs_uaddr *uaddr,
                            struct silofs_spnode_info **out_sni);


int silofs_spawn_spleaf_at(struct silofs_fs_uber *uber, bool main,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spleaf_info **out_sli);

int silofs_stage_spleaf_at(struct silofs_fs_uber *uber, bool main,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spleaf_info **out_sli);

int silofs_shadow_spleaf_at(struct silofs_fs_uber *uber, bool main,
                            const struct silofs_uaddr *uaddr,
                            struct silofs_spleaf_info **out_sli);

#endif /* SILOFS_UBER_H_ */
