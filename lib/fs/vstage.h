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
#ifndef SILOFS_VSTAGE_H_
#define SILOFS_VSTAGE_H_

#include <silofs/macros.h>
#include "infra.h"
#include "addr.h"

struct silofs_env;
struct silofs_task_ctx;
struct silofs_spnode_info;
struct silofs_spleaf_info;
struct silofs_vnode_info;
struct silofs_inode_info;
struct silofs_inew_params;

/* stage operation control flags */
enum silofs_stg_mode {
	SILOFS_STG_CUR = SILOFS_BIT(0), /* stage current (normal) */
	SILOFS_STG_COW = SILOFS_BIT(1), /* copy-on-write */
	SILOFS_STG_RAW = SILOFS_BIT(2), /* not-set-yet */
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_spawn_super(struct silofs_env         *env,
                       const struct silofs_uaddr *uaddr,
                       struct silofs_sb_info    **out_sbi);

int silofs_stage_super(struct silofs_env         *env,
                       const struct silofs_uaddr *uaddr,
                       struct silofs_sb_info    **out_sbi);

int silofs_spawn_spnode(struct silofs_env          *env,
                        const struct silofs_uaddr  *uaddr,
                        struct silofs_spnode_info **out_sni);

int silofs_stage_spnode(struct silofs_env          *env,
                        const struct silofs_uaddr  *uaddr,
                        struct silofs_spnode_info **out_sni);

int silofs_spawn_spleaf(struct silofs_env          *env,
                        const struct silofs_uaddr  *uaddr,
                        struct silofs_spleaf_info **out_sli);

int silofs_stage_spleaf(struct silofs_env          *env,
                        const struct silofs_uaddr  *uaddr,
                        struct silofs_spleaf_info **out_sli);

int silofs_spawn_lseg(struct silofs_env *env, const struct silofs_lsid *lsid);

int silofs_stage_lseg(struct silofs_env *env, const struct silofs_lsid *lsid);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_require_lsmap_by(struct silofs_task_ctx    *task,
                            const struct silofs_vaddr *vaddr,
                            struct silofs_lsmap_info **out_lsi);

int silofs_claim_vspace(struct silofs_task_ctx *task, enum silofs_mtype mtype,
                        struct silofs_vaddr *out_vaddr);

int silofs_reclaim_vspace(struct silofs_task_ctx    *task,
                          const struct silofs_vaddr *vaddr);

int silofs_claim_ispace(struct silofs_task_ctx *task,
                        struct silofs_vaddr    *out_vaddr);

int silofs_addref_vspace(struct silofs_task_ctx    *task,
                         const struct silofs_vaddr *vaddr);

int silofs_reload_vspace(struct silofs_task_ctx *task);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_stage_spleaf_of(struct silofs_task_ctx     *task,
                           const struct silofs_vaddr  *vaddr,
                           enum silofs_stg_mode        stg_mode,
                           struct silofs_spleaf_info **out_sli);

int silofs_require_spleaf_of(struct silofs_task_ctx     *task,
                             const struct silofs_vaddr  *vaddr,
                             enum silofs_stg_mode        stg_mode,
                             struct silofs_spleaf_info **out_sli);

int silofs_resolve_llink_of(struct silofs_task_ctx    *task,
                            const struct silofs_vaddr *vaddr,
                            enum silofs_stg_mode       stg_mode,
                            struct silofs_llink       *out_llink);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_stage_vnode(struct silofs_task_ctx    *task,
                       struct silofs_inode_info  *pii,
                       const struct silofs_vaddr *vaddr,
                       enum silofs_stg_mode       stg_mode,
                       struct silofs_vnode_info **out_vni);

int silofs_stage_inode(struct silofs_task_ctx *task, ino_t ino,
                       enum silofs_stg_mode       stg_mode,
                       struct silofs_inode_info **out_ii);

int silofs_fetch_cached_vnode(struct silofs_task_ctx    *task,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_vnode_info **out_vni);

int silofs_fetch_cached_inode(struct silofs_task_ctx *task, ino_t ino,
                              struct silofs_inode_info **out_ii);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_spawn_vnode(struct silofs_task_ctx   *task,
                       struct silofs_inode_info *pii, enum silofs_mtype mtype,
                       struct silofs_vnode_info **out_vni);

int silofs_spawn_inode(struct silofs_task_ctx          *task,
                       const struct silofs_inew_params *inp,
                       struct silofs_inode_info       **out_ii);

int silofs_remove_vnode(struct silofs_task_ctx   *task,
                        struct silofs_vnode_info *vni);

int silofs_remove_vnode_at(struct silofs_task_ctx    *task,
                           const struct silofs_vaddr *vaddr);

int silofs_remove_inode(struct silofs_task_ctx   *task,
                        struct silofs_inode_info *ii);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_refresh_llink(struct silofs_task_ctx   *task,
                         struct silofs_vnode_info *vni);

#endif /* SILOFS_VSTAGE_H_ */
