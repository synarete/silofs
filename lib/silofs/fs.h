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

#include <silofs/macros.h>
#include <silofs/ondisk.h>
#include <silofs/types.h>
#include <silofs/infra.h>
#include <silofs/flags.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>
#include <silofs/pstor.h>
#include <silofs/vfs.h>

struct silofs_env;

/* stage operation control flags */
enum silofs_stg_mode {
	SILOFS_STG_NONE = 0,
	SILOFS_STG_CUR  = SILOFS_BIT(0), /* stage current (normal) */
	SILOFS_STG_COW  = SILOFS_BIT(1), /* copy-on-write */
	SILOFS_STG_RAW  = SILOFS_BIT(2), /* not-set-yet */
};

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* idsmap */

#include <silofs/fs/idsmap.h>

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* pglue */

int silofs_probe_super2(const struct silofs_task_ctx *task);

int silofs_stage_super2(const struct silofs_task_ctx *task,
                        enum silofs_stg_mode          stg_mode,
                        struct silofs_sbnode_info   **out_sbi);

int silofs_spawn_super2(const struct silofs_task_ctx *task,
                        struct silofs_sbnode_info   **out_sbi);

int silofs_probe_spnode2(const struct silofs_task_ctx *task,
                         const struct silofs_laddr    *laddr);

int silofs_stage_spnode2_of(const struct silofs_task_ctx *task,
                            const struct silofs_laddr    *ref_laddr,
                            enum silofs_stg_mode          stg_mode,
                            struct silofs_spnode_info   **out_spi);

int silofs_spawn_spnode2_of(const struct silofs_task_ctx *task,
                            const struct silofs_laddr    *ref_laddr,
                            struct silofs_spnode_info   **out_spi);

int silofs_probe_inode2(const struct silofs_task_ctx *task,
                        const struct silofs_laddr    *laddr);

int silofs_stage_inode2(const struct silofs_task_ctx *task,
                        const struct silofs_laddr    *laddr,
                        enum silofs_stg_mode          stg_mode,
                        struct silofs_inode_info    **out_ii);

int silofs_spawn_inode2(const struct silofs_task_ctx *task,
                        struct silofs_inode_info    **out_ii);

int silofs_remove_inode2(const struct silofs_task_ctx *task,
                         const struct silofs_laddr    *laddr);

int silofs_stage_xanode2(const struct silofs_task_ctx *task,
                         const struct silofs_laddr    *laddr,
                         struct silofs_inode_info     *pii,
                         enum silofs_stg_mode          stg_mode,
                         struct silofs_xanode_info   **out_xai);

int silofs_spawn_xanode2(const struct silofs_task_ctx *task,
                         struct silofs_inode_info     *pii,
                         struct silofs_xanode_info   **out_xai);

int silofs_remove_xanode2(const struct silofs_task_ctx *task,
                          const struct silofs_laddr    *laddr,
                          struct silofs_inode_info     *pii);

int silofs_stage_symval2(const struct silofs_task_ctx *task,
                         const struct silofs_laddr    *laddr,
                         struct silofs_inode_info     *pii,
                         enum silofs_stg_mode          stg_mode,
                         struct silofs_symval_info   **out_svi);

int silofs_spawn_symval2(const struct silofs_task_ctx *task,
                         struct silofs_inode_info     *pii,
                         struct silofs_symval_info   **out_svi);

int silofs_remove_symval2(const struct silofs_task_ctx *task,
                          const struct silofs_laddr    *laddr,
                          struct silofs_inode_info     *pii);

int silofs_stage_dtnode2(const struct silofs_task_ctx *task,
                         const struct silofs_laddr    *laddr,
                         struct silofs_inode_info     *pii,
                         enum silofs_stg_mode          stg_mode,
                         struct silofs_dtnode_info   **out_dti);

int silofs_spawn_dtnode2(const struct silofs_task_ctx *task,
                         struct silofs_inode_info     *pii,
                         struct silofs_dtnode_info   **out_dti);

int silofs_remove_dtnode2(const struct silofs_task_ctx *task,
                          const struct silofs_laddr    *laddr,
                          struct silofs_inode_info     *pii);

int silofs_stage_ftnode2(const struct silofs_task_ctx *task,
                         const struct silofs_laddr    *laddr,
                         struct silofs_inode_info     *pii,
                         enum silofs_stg_mode          stg_mode,
                         struct silofs_ftnode_info   **out_fti);

int silofs_spawn_ftnode2(const struct silofs_task_ctx *task,
                         struct silofs_inode_info     *pii,
                         struct silofs_ftnode_info   **out_fti);

int silofs_remove_ftnode2(struct silofs_task_ctx    *task,
                          const struct silofs_laddr *laddr,
                          struct silofs_inode_info  *pii);

int silofs_claim_fdnode2(const struct silofs_task_ctx *task,
                         enum silofs_ltype             ltype,
                         struct silofs_inode_info     *pii,
                         struct silofs_laddr          *out_laddr);

int silofs_stage_fdnode2(const struct silofs_task_ctx *task,
                         const struct silofs_laddr    *laddr,
                         struct silofs_inode_info     *pii,
                         enum silofs_stg_mode          stg_mode,
                         struct silofs_fdnode_info   **out_fdi);

int silofs_remove_fdnode2(const struct silofs_task_ctx *task,
                          const struct silofs_laddr    *laddr,
                          struct silofs_inode_info     *pii);

int silofs_share_fdnode2(const struct silofs_task_ctx *task,
                         const struct silofs_laddr    *laddr,
                         struct silofs_inode_info     *pii);

int silofs_unshare_fdnode2(const struct silofs_task_ctx *task,
                           const struct silofs_laddr    *laddr,
                           struct silofs_inode_info     *pii);

int silofs_isshared_fdnode2(const struct silofs_task_ctx *task,
                            const struct silofs_laddr    *laddr,
                            struct silofs_inode_info *pii, bool *out_res);

int silofs_mark_unwritten_fdnode2(const struct silofs_task_ctx *task,
                                  const struct silofs_laddr    *laddr,
                                  struct silofs_inode_info     *pii);

int silofs_clear_unwritten_fdnode2(const struct silofs_task_ctx *task,
                                   const struct silofs_laddr    *laddr,
                                   struct silofs_inode_info     *pii);

int silofs_test_unwritten_fdnode2(const struct silofs_task_ctx *task,
                                  const struct silofs_laddr    *laddr,
                                  struct silofs_inode_info     *pii,
                                  bool                         *out_unwritten);

#include <silofs/fs/super.h>
#include <silofs/fs/inode.h>
#include <silofs/fs/inops.h>
#include <silofs/fs/namei.h>
#include <silofs/fs/file.h>

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
/* symlnk */

void silofs_ii_setup_symlnk(struct silofs_inode_info *lnk_ii);

int silofs_drop_symlink(struct silofs_task_ctx   *task,
                        struct silofs_inode_info *lnk_ii);

int silofs_do_readlink(struct silofs_task_ctx   *task,
                       struct silofs_inode_info *lnk_ii, void *ptr, size_t lim,
                       size_t *out_len);

int silofs_bind_symval(struct silofs_task_ctx      *task,
                       struct silofs_inode_info    *lnk_ii,
                       const struct silofs_strview *symval);

int silofs_verify_symval_node(const struct silofs_symval_node *svn);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* xattr */

void silofs_ii_setup_xattr(struct silofs_inode_info *ii);

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
/* flush */

int silofs_flush_dirty(struct silofs_task_ctx   *task,
                       struct silofs_inode_info *ii, int flags);

int silofs_flush_dirty_now(struct silofs_task_ctx *task);

int silofs_destage_dirty_by(struct silofs_task_ctx *task);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* format */

int silofs_format(struct silofs_task_ctx *task, size_t fs_capacity,
                  struct silofs_pnptr *out_pnptr);

int silofs_reload(struct silofs_task_ctx    *task,
                  const struct silofs_pnptr *pnptr);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* task */
#include <silofs/fs/task.h>

#endif /* SILOFS_FS_H_ */
