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
	SILOFS_STG_NONE = 0,
	SILOFS_STG_CUR  = SILOFS_BIT(0), /* stage current (normal) */
	SILOFS_STG_COW  = SILOFS_BIT(1), /* copy-on-write */
	SILOFS_STG_RAW  = SILOFS_BIT(2), /* not-set-yet */
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
/* pglue */

int silofs_probe_inode2(const struct silofs_task_ctx *task,
                        const struct silofs_vaddr    *vaddr);

int silofs_stage_inode2(const struct silofs_task_ctx *task,
                        const struct silofs_vaddr    *vaddr,
                        enum silofs_stg_mode          stg_mode,
                        struct silofs_inode_info    **out_ii);

int silofs_spawn_inode2(const struct silofs_task_ctx *task,
                        struct silofs_inode_info    **out_ii);

int silofs_remove_inode2(const struct silofs_task_ctx *task,
                         const struct silofs_vaddr    *vaddr);

int silofs_stage_xanode2(const struct silofs_task_ctx *task,
                         const struct silofs_vaddr    *vaddr,
                         struct silofs_inode_info     *pii,
                         enum silofs_stg_mode          stg_mode,
                         struct silofs_xanode_info   **out_xai);

int silofs_spawn_xanode2(const struct silofs_task_ctx *task,
                         struct silofs_inode_info     *pii,
                         struct silofs_xanode_info   **out_xai);

int silofs_remove_xanode2(const struct silofs_task_ctx *task,
                          const struct silofs_vaddr    *vaddr,
                          struct silofs_inode_info     *pii);

int silofs_stage_symval2(const struct silofs_task_ctx *task,
                         const struct silofs_vaddr    *vaddr,
                         struct silofs_inode_info     *pii,
                         enum silofs_stg_mode          stg_mode,
                         struct silofs_symval_info   **out_svi);

int silofs_spawn_symval2(const struct silofs_task_ctx *task,
                         struct silofs_inode_info     *pii,
                         struct silofs_symval_info   **out_svi);

int silofs_remove_symval2(const struct silofs_task_ctx *task,
                          const struct silofs_vaddr    *vaddr,
                          struct silofs_inode_info     *pii);

int silofs_stage_dtnode2(const struct silofs_task_ctx *task,
                         const struct silofs_vaddr    *vaddr,
                         struct silofs_inode_info     *pii,
                         enum silofs_stg_mode          stg_mode,
                         struct silofs_dtnode_info   **out_dti);

int silofs_spawn_dtnode2(const struct silofs_task_ctx *task,
                         struct silofs_inode_info     *pii,
                         struct silofs_dtnode_info   **out_dti);

int silofs_remove_dtnode2(const struct silofs_task_ctx *task,
                          const struct silofs_vaddr    *vaddr,
                          struct silofs_inode_info     *pii);

int silofs_stage_ftnode2(const struct silofs_task_ctx *task,
                         const struct silofs_vaddr    *vaddr,
                         struct silofs_inode_info     *pii,
                         enum silofs_stg_mode          stg_mode,
                         struct silofs_ftnode_info   **out_fti);

int silofs_spawn_ftnode2(const struct silofs_task_ctx *task,
                         struct silofs_inode_info     *pii,
                         struct silofs_ftnode_info   **out_fti);

int silofs_remove_ftnode2(struct silofs_task_ctx    *task,
                          const struct silofs_vaddr *vaddr,
                          struct silofs_inode_info  *pii);

int silofs_claim_fdnode2(const struct silofs_task_ctx *task,
                         enum silofs_vtype             vtype,
                         struct silofs_inode_info     *pii,
                         struct silofs_vaddr          *out_vaddr);

int silofs_stage_fdnode2(const struct silofs_task_ctx *task,
                         const struct silofs_vaddr    *vaddr,
                         struct silofs_inode_info     *pii,
                         enum silofs_stg_mode          stg_mode,
                         struct silofs_fdnode_info   **out_fdi);

int silofs_remove_fdnode2(const struct silofs_task_ctx *task,
                          const struct silofs_vaddr    *vaddr,
                          struct silofs_inode_info     *pii);

int silofs_share_fdnode2(const struct silofs_task_ctx *task,
                         const struct silofs_vaddr    *vaddr,
                         struct silofs_inode_info     *pii);

int silofs_unshare_fdnode2(const struct silofs_task_ctx *task,
                           const struct silofs_vaddr    *vaddr,
                           struct silofs_inode_info     *pii);

int silofs_isshared_fdnode2(const struct silofs_task_ctx *task,
                            const struct silofs_vaddr    *vaddr,
                            struct silofs_inode_info *pii, bool *out_res);

int silofs_mark_unwritten_fdnode2(const struct silofs_task_ctx *task,
                                  const struct silofs_vaddr    *vaddr,
                                  struct silofs_inode_info     *pii);

int silofs_clear_unwritten_fdnode2(const struct silofs_task_ctx *task,
                                   const struct silofs_vaddr    *vaddr,
                                   struct silofs_inode_info     *pii);

int silofs_test_unwritten_fdnode2(const struct silofs_task_ctx *task,
                                  const struct silofs_vaddr    *vaddr,
                                  struct silofs_inode_info     *pii,
                                  bool                         *out_unwritten);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

#include <silofs/fs/inode.h>
#include <silofs/fs/dir.h>
#include <silofs/fs/file.h>
#include <silofs/fs/symlink.h>

#include <silofs/fs/lsmap.h>
#include <silofs/fs/task.h>
#include <silofs/fs/super.h>
#include <silofs/fs/lcache.h>
#include <silofs/fs/namei.h>
#include <silofs/fs/spmaps.h>

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* dir */

/* pair of ino and dir-type */
struct silofs_ino_dt {
	ino_t  ino;
	mode_t dt;
};

enum silofs_dirf silofs_dir_flags(const struct silofs_inode_info *dir_ii);

void silofs_dir_set_flag(struct silofs_inode_info *dir_ii,
                         enum silofs_dirf          flag);

void silofs_dir_unset_flag(struct silofs_inode_info *dir_ii,
                           enum silofs_dirf          flag);

void silofs_ii_setup_dir(struct silofs_inode_info *dir_ii, //
                         nlink_t nlink, uint64_t seed);

int silofs_lookup_dentry(struct silofs_task_ctx      *task,
                         struct silofs_inode_info    *dir_ii,
                         const struct silofs_namestr *name,
                         struct silofs_ino_dt        *out_idt);

int silofs_add_dentry(struct silofs_task_ctx      *task,
                      struct silofs_inode_info    *dir_ii,
                      const struct silofs_namestr *name,
                      struct silofs_inode_info    *ii);

int silofs_remove_dentry(struct silofs_task_ctx      *task,
                         struct silofs_inode_info    *dir_ii,
                         const struct silofs_namestr *name);

int silofs_readdir_normal(struct silofs_task_ctx    *task,
                          struct silofs_inode_info  *dir_ii,
                          struct silofs_readdir_ctx *rd_ctx);

int silofs_readdir_plus(struct silofs_task_ctx    *task,
                        struct silofs_inode_info  *dir_ii,
                        struct silofs_readdir_ctx *rd_ctx);

int silofs_drop_dir(struct silofs_task_ctx   *task,
                    struct silofs_inode_info *dir_ii);

bool silofs_dir_isempty(const struct silofs_inode_info *dir_ii);

bool silofs_dir_may_add(const struct silofs_inode_info *dir_ii);

bool silofs_dir_has_flags(const struct silofs_inode_info *dir_ii,
                          enum silofs_dirf                mask);

void silofs_dir_inherit_parent(struct silofs_inode_info       *dir_ii,
                               const struct silofs_inode_info *parentd_ii);

int silofs_dir_make_hname(const struct silofs_inode_info *dir_ii,
                          const struct silofs_mdigest_hd *md_hd,
                          const struct silofs_namestr    *nstr,
                          struct silofs_namestr          *out_nstr);

int silofs_dir_check_name(const struct silofs_inode_info *dir_ii,
                          const struct silofs_uconv      *uconv,
                          const struct silofs_namestr    *nstr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_verify_dir_inode(const struct silofs_inode *inode);

int silofs_verify_dtree_node(const struct silofs_dtree_node *dtn);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* xattr */

void silofs_ii_setup_xattr(struct silofs_inode_info *ii);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_do_getxattr(struct silofs_task_ctx      *task,
                       struct silofs_inode_info    *ii,
                       const struct silofs_namestr *name, void *buf,
                       size_t size, size_t *out_size);

int silofs_do_setxattr(struct silofs_task_ctx      *task,
                       struct silofs_inode_info    *ii,
                       const struct silofs_namestr *name, const void *value,
                       size_t size, int flags, bool kill_sgid);

int silofs_do_removexattr(struct silofs_task_ctx      *task,
                          struct silofs_inode_info    *ii,
                          const struct silofs_namestr *name);

int silofs_do_listxattr(struct silofs_task_ctx      *task,
                        struct silofs_inode_info    *ii,
                        struct silofs_listxattr_ctx *lxa_ctx);

int silofs_drop_xattr(struct silofs_task_ctx   *task,
                      struct silofs_inode_info *ii);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_verify_inode_xattr(const struct silofs_inode *inode);

int silofs_verify_xattr_node(const struct silofs_xattr_node *xan);

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

int silofs_stage_inode_of(struct silofs_task_ctx *task, ino_t ino,
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

int silofs_spawn_inode_by(struct silofs_task_ctx          *task,
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
