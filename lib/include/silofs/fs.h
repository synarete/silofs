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
#ifndef SILOFS_FS_H_
#define SILOFS_FS_H_

#include <silofs/types.h>
#include <silofs/base.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>
#include <silofs/vfs.h>

/* stage operation control flags */
enum silofs_stg_mode {
	SILOFS_STG_CUR = SILOFS_BIT(0), /* stage current (normal) */
	SILOFS_STG_COW = SILOFS_BIT(1), /* copy-on-write */
	SILOFS_STG_RAW = SILOFS_BIT(2), /* not-set-yet */
};

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* idsmap */

/* bi-directional id-mapping hash-table (external-internal) */
struct silofs_idsmap {
	struct silofs_alloc     *idm_alloc;
	struct silofs_list_head *idm_uhtof;
	struct silofs_list_head *idm_uftoh;
	struct silofs_list_head *idm_ghtof;
	struct silofs_list_head *idm_gftoh;
	size_t                   idm_uhcap;
	size_t                   idm_usize;
	size_t                   idm_ghcap;
	size_t                   idm_gsize;
	bool                     idm_allow_hostids;
};

int silofs_idsmap_init(struct silofs_idsmap *idsm, struct silofs_alloc *alloc);

void silofs_idsmap_fini(struct silofs_idsmap *idsm);

void silofs_idsmap_clear(struct silofs_idsmap *idsm);

int silofs_idsmap_populate(struct silofs_idsmap      *idsm,
                           const struct silofs_fsids *fsids,
                           bool                       allow_hostids);

int silofs_idsmap_mapcreds(const struct silofs_idsmap *idsm, uid_t host_uid,
                           gid_t host_gid, uid_t *out_fs_uid,
                           gid_t *out_fs_gid);

int silofs_idsmap_rmapcreds(const struct silofs_idsmap *idsm, uid_t fs_uid,
                            gid_t fs_gid, uid_t *out_fs_uid,
                            gid_t *out_fs_gid);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* pvglue */

int silofs_stage_xanode(const struct silofs_task_ctx *task,
                        const struct silofs_vaddr    *vaddr,
                        struct silofs_inode_info     *pii,
                        enum silofs_stg_mode          stg_mode,
                        struct silofs_xanode_info   **out_xai);

int silofs_spawn_xanode(struct silofs_task_ctx     *task,
                        struct silofs_inode_info   *pii,
                        struct silofs_xanode_info **out_xai);

int silofs_remove_xanode_at(struct silofs_task_ctx    *task,
                            const struct silofs_vaddr *vaddr);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

#include <silofs/fs/inode.h>
#include <silofs/fs/dir.h>
#include <silofs/fs/file.h>
#include <silofs/fs/symlink.h>
#include <silofs/fs/xattr.h>

#include <silofs/fs/lsmap.h>
#include <silofs/fs/task.h>
#include <silofs/fs/super.h>
#include <silofs/fs/lcache.h>
#include <silofs/fs/namei.h>
#include <silofs/fs/spmaps.h>

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* vstage */

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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_require_lsmap_by(struct silofs_task_ctx    *task,
                            const struct silofs_vaddr *vaddr,
                            struct silofs_lsmap_info **out_lsi);

int silofs_claim_vspace(struct silofs_task_ctx *task, enum silofs_vtype vtype,
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

int silofs_stage_vnode2_new(struct silofs_task_ctx    *task,
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
                       struct silofs_inode_info *pii, enum silofs_vtype vtype,
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

int silofs_refresh_llink(struct silofs_task_ctx   *task,
                         struct silofs_vnode_info *vni);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

/* encdec */

void silofs_resolve_unode_nmeta(const struct silofs_env *env,
                                struct silofs_nmeta     *out_nmeta);

int silofs_encrypt_view(const struct silofs_env   *env,
                        const struct silofs_llink *llink,
                        const struct silofs_lview *view, void *ptr);

int silofs_decrypt_uni_view(const struct silofs_env  *env,
                            struct silofs_unode_info *uni);

int silofs_decrypt_vni_view(const struct silofs_env  *env,
                            struct silofs_vnode_info *vni);

void silofs_llink_of_uni(const struct silofs_unode_info *uni,
                         const struct silofs_nmeta      *nmeta,
                         struct silofs_llink            *out_llink);

void silofs_llink_of_vni(const struct silofs_vnode_info *vni,
                         struct silofs_llink            *out_llink);

void silofs_calc_cas_paddr(const struct silofs_mdigest_hd *md_hd,
                           enum silofs_ptype ptype, enum silofs_vtype vtype,
                           const struct iovec *iov, size_t iov_cnt,
                           struct silofs_paddr *out_paddr);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

#include <silofs/fs/flush.h>

#endif /* SILOFS_FS_H_ */
