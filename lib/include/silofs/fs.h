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
/* inode */

/* inode's attributes masks */
enum silofs_iattr_flags {
	SILOFS_IATTR_NONE         = 0,
	SILOFS_IATTR_PARENT       = SILOFS_BIT(0),
	SILOFS_IATTR_LAZY         = SILOFS_BIT(1),
	SILOFS_IATTR_SIZE         = SILOFS_BIT(2),
	SILOFS_IATTR_SPAN         = SILOFS_BIT(3),
	SILOFS_IATTR_NLINK        = SILOFS_BIT(4),
	SILOFS_IATTR_BLOCKS       = SILOFS_BIT(5),
	SILOFS_IATTR_MODE         = SILOFS_BIT(6),
	SILOFS_IATTR_UID          = SILOFS_BIT(7),
	SILOFS_IATTR_GID          = SILOFS_BIT(8),
	SILOFS_IATTR_KILL_SUID    = SILOFS_BIT(9),
	SILOFS_IATTR_KILL_SGID    = SILOFS_BIT(10),
	SILOFS_IATTR_BTIME        = SILOFS_BIT(11),
	SILOFS_IATTR_ATIME        = SILOFS_BIT(12),
	SILOFS_IATTR_MTIME        = SILOFS_BIT(13),
	SILOFS_IATTR_CTIME        = SILOFS_BIT(14),
	SILOFS_IATTR_NOW          = SILOFS_BIT(15),
	SILOFS_IATTR_KILL_SUIDGID = SILOFS_IATTR_KILL_SUID |
	                            SILOFS_IATTR_KILL_SGID,
	SILOFS_IATTR_MCTIME       = SILOFS_IATTR_MTIME | SILOFS_IATTR_CTIME,
	SILOFS_IATTR_AMCTIME      = SILOFS_IATTR_ATIME | SILOFS_IATTR_MTIME |
	                            SILOFS_IATTR_CTIME,
	SILOFS_IATTR_TIMES        = SILOFS_IATTR_BTIME | SILOFS_IATTR_AMCTIME,
};

/* inode's attributes */
struct silofs_iattr {
	enum silofs_iattr_flags ia_flags;
	mode_t                  ia_mode;
	ino_t                   ia_ino;
	ino_t                   ia_parent;
	nlink_t                 ia_nlink;
	uid_t                   ia_uid;
	gid_t                   ia_gid;
	dev_t                   ia_rdev;
	ssize_t                 ia_size;
	ssize_t                 ia_span;
	blkcnt_t                ia_blocks;
	struct silofs_itimes    ia_t;
};

/* new-inode's create parameters */
struct silofs_inew_params {
	struct silofs_creds creds;
	struct timespec     ts;
	mode_t              mode;
	dev_t               rdev;
	ino_t               parent_ino;
	mode_t              parent_mode;
	enum silofs_inodef  flags;
	uint64_t            generation;
	uint64_t            seed;
};

bool silofs_ino_isnull(ino_t ino);

bool silofs_user_cap_fowner(const struct silofs_cred *cred);

bool silofs_user_cap_sys_admin(const struct silofs_cred *cred);

struct silofs_inode_info *
silofs_ii_unconst(const struct silofs_inode_info *ii);

struct silofs_vnode_info *silofs_ii_to_vni(const struct silofs_inode_info *ii);

const struct silofs_vaddr *silofs_ii_vaddr(const struct silofs_inode_info *ii);

ino_t silofs_ii_parent(const struct silofs_inode_info *ii);

void silofs_ii_set_loose(struct silofs_inode_info *ii);

uid_t silofs_ii_uid(const struct silofs_inode_info *ii);

gid_t silofs_ii_gid(const struct silofs_inode_info *ii);

mode_t silofs_ii_mode(const struct silofs_inode_info *ii);

nlink_t silofs_ii_nlink(const struct silofs_inode_info *ii);

off_t silofs_ii_size(const struct silofs_inode_info *ii);

off_t silofs_ii_span(const struct silofs_inode_info *ii);

blkcnt_t silofs_ii_blocks(const struct silofs_inode_info *ii);

uint64_t silofs_ii_generation(const struct silofs_inode_info *ii);

bool silofs_ii_isdir(const struct silofs_inode_info *ii);

bool silofs_ii_isreg(const struct silofs_inode_info *ii);

bool silofs_ii_isfifo(const struct silofs_inode_info *ii);

bool silofs_ii_issock(const struct silofs_inode_info *ii);

bool silofs_ii_islnk(const struct silofs_inode_info *ii);

bool silofs_ii_isrootd(const struct silofs_inode_info *ii);

bool silofs_is_rootdir(const struct silofs_inode_info *ii);

bool silofs_ii_isevictable(const struct silofs_inode_info *ii);

void silofs_ii_fixup_as_rootdir(struct silofs_inode_info *ii);

void silofs_ii_update_iflags(struct silofs_inode_info *ii, int iflags_want,
                             int iflags_dont);

void silofs_ii_update_iattrs(struct silofs_inode_info  *ii,
                             const struct silofs_iattr *iattr);

void silofs_ii_kill_suidgid(struct silofs_inode_info *ii);

void silofs_ii_refresh_atime(struct silofs_inode_info *ii, bool to_volatile);

void silofs_ii_update_spawned(struct silofs_inode_info        *ii,
                              const struct silofs_inew_params *inp);

void silofs_ii_update_staged(struct silofs_inode_info *ii);

void silofs_ii_stat_of(const struct silofs_inode_info *ii,
                       uint32_t sx_want_mask, struct silofs_stat *st);

void silofs_make_iattr_of(const struct silofs_inode_info *ii,
                          struct silofs_iattr            *out_iattr);

void silofs_ii_cleardirty_vnis(struct silofs_inode_info *ii);

bool silofs_ii_isloose(const struct silofs_inode_info *ii);

enum silofs_inodef silofs_ii_flags(const struct silofs_inode_info *ii);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ii_incref(struct silofs_inode_info *ii);

void silofs_ii_decref(struct silofs_inode_info *ii);

void silofs_ii_setdirty(struct silofs_inode_info *ii);

void silofs_ii_cleardirty(struct silofs_inode_info *ii);

bool silofs_ii_isdirty(const struct silofs_inode_info *ii);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_do_getattr(struct silofs_task_ctx   *task,
                      struct silofs_inode_info *ii,
                      struct silofs_stat       *out_st);

int silofs_do_statx(struct silofs_task_ctx *task, struct silofs_inode_info *ii,
                    uint32_t sx_want_mask, struct silofs_stat *out_st);

int silofs_do_chmod(struct silofs_task_ctx *task, struct silofs_inode_info *ii,
                    mode_t mode, const struct silofs_itimes *itimes);

int silofs_do_chown(const struct silofs_task_ctx *task,
                    struct silofs_inode_info *ii, uid_t uid, gid_t gid,
                    bool kill_suidgid, const struct silofs_itimes *itimes);

int silofs_do_utimens(const struct silofs_task_ctx *task,
                      struct silofs_inode_info     *ii,
                      const struct silofs_itimes   *itimes);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_update_itimes_of(const struct silofs_task_ctx *task,
                             struct silofs_inode_info     *ii,
                             enum silofs_iattr_flags       attr_flags);

void silofs_update_iblocks_of(const struct silofs_task_ctx *task,
                              struct silofs_inode_info     *ii,
                              enum silofs_vtype vtype, long dif);

void silofs_update_iattrs_of(const struct silofs_task_ctx *task,
                             struct silofs_inode_info     *ii,
                             const struct silofs_iattr    *iattr);

void silofs_update_isize_of(const struct silofs_task_ctx *task,
                            struct silofs_inode_info *ii, ssize_t size);

int silofs_spawn_inode_by(struct silofs_task_ctx          *task,
                          const struct silofs_inew_params *inp,
                          struct silofs_inode_info       **out_ii);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_verify_inode(const struct silofs_inode *inode);

int silofs_verify_ino(ino_t ino);

ino_t silofs_inode_ino(const struct silofs_inode *inode);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

#include <silofs/fs/lsmap.h>
#include <silofs/fs/task.h>
#include <silofs/fs/super.h>
#include <silofs/fs/lcache.h>
#include <silofs/fs/spmaps.h>

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* namei */

struct silofs_laddr_visitor;

int silofs_make_xattrname(struct silofs_task_ctx         *task,
                          const struct silofs_inode_info *ii, const char *s,
                          struct silofs_namestr *out_nstr);

int silofs_make_linkname(struct silofs_task_ctx         *task,
                         const struct silofs_inode_info *dir_ii, const char *s,
                         struct silofs_namestr *out_nstr);

void silofs_inew_params_of(const struct silofs_task_ctx   *task,
                           const struct silofs_inode_info *parent_dii,
                           mode_t mode, dev_t rdev,
                           struct silofs_inew_params *out_inp);

int silofs_do_forget(struct silofs_task_ctx   *task,
                     struct silofs_inode_info *ii, size_t nlookup);

int silofs_do_statvfs(const struct silofs_task_ctx *task,
                      struct silofs_inode_info *ii, struct statvfs *out_stvfs);

int silofs_do_access(const struct silofs_task_ctx *task,
                     struct silofs_inode_info *ii, int mode);

int silofs_do_open(struct silofs_task_ctx *task, struct silofs_inode_info *ii,
                   int o_flags, bool kill_suidgid);

int silofs_do_release(struct silofs_task_ctx   *task,
                      struct silofs_inode_info *ii, bool flush);

int silofs_do_mkdir(struct silofs_task_ctx      *task,
                    struct silofs_inode_info    *dir_ii,
                    const struct silofs_namestr *name, mode_t mode,
                    struct silofs_inode_info **out_ii);

int silofs_do_rmdir(struct silofs_task_ctx      *task,
                    struct silofs_inode_info    *dir_ii,
                    const struct silofs_namestr *name);

int silofs_do_rename(struct silofs_task_ctx      *task,
                     struct silofs_inode_info    *dir_ii,
                     const struct silofs_namestr *name,
                     struct silofs_inode_info    *newdir_ii,
                     const struct silofs_namestr *newname, int flags);

int silofs_do_symlink(struct silofs_task_ctx      *task,
                      struct silofs_inode_info    *dir_ii,
                      const struct silofs_namestr *name,
                      const struct silofs_strview *symval,
                      struct silofs_inode_info   **out_ii);

int silofs_do_link(struct silofs_task_ctx      *task,
                   struct silofs_inode_info    *dir_ii,
                   const struct silofs_namestr *name,
                   struct silofs_inode_info    *ii);

int silofs_do_unlink(struct silofs_task_ctx      *task,
                     struct silofs_inode_info    *dir_ii,
                     const struct silofs_namestr *name);

int silofs_do_create(struct silofs_task_ctx      *task,
                     struct silofs_inode_info    *dir_ii,
                     const struct silofs_namestr *name, mode_t mode,
                     bool kill_suidgid, struct silofs_inode_info **out_ii);

int silofs_do_mknod(struct silofs_task_ctx      *task,
                    struct silofs_inode_info    *dir_ii,
                    const struct silofs_namestr *name, mode_t mode, dev_t dev,
                    struct silofs_inode_info **out_ii);

int silofs_do_lookup(struct silofs_task_ctx      *task,
                     struct silofs_inode_info    *dir_ii,
                     const struct silofs_namestr *name,
                     struct silofs_inode_info   **out_ii);

int silofs_do_opendir(struct silofs_task_ctx   *task,
                      struct silofs_inode_info *dir_ii, int o_flags);

int silofs_do_readdir(struct silofs_task_ctx    *task,
                      struct silofs_inode_info  *dir_ii,
                      struct silofs_readdir_ctx *rd_ctx);

int silofs_do_readdirplus(struct silofs_task_ctx    *task,
                          struct silofs_inode_info  *dir_ii,
                          struct silofs_readdir_ctx *rd_ctx);

int silofs_do_releasedir(struct silofs_task_ctx   *task,
                         struct silofs_inode_info *dir_ii, int o_flags,
                         bool flush);

int silofs_do_fsyncdir(struct silofs_task_ctx   *task,
                       struct silofs_inode_info *dir_ii, bool dsync);

int silofs_do_fsync(struct silofs_task_ctx *task, struct silofs_inode_info *ii,
                    bool datasync);

int silofs_do_flush(struct silofs_task_ctx *task, struct silofs_inode_info *ii,
                    bool now);

int silofs_do_query(struct silofs_task_ctx *task, struct silofs_inode_info *ii,
                    enum silofs_query_type   qtype,
                    struct silofs_ioc_query *out_qry);

int silofs_do_forkfs(struct silofs_task_ctx   *task,
                     struct silofs_inode_info *dir_ii, int flags,
                     struct silofs_mbrefs *out_paddrs);

int silofs_do_tune(struct silofs_task_ctx   *task,
                   struct silofs_inode_info *dir_ii, int iflags_want,
                   int iflags_dont);

int silofs_do_syncfs(struct silofs_task_ctx   *task,
                     struct silofs_inode_info *ii, int flags);

int silofs_do_maintain(struct silofs_task_ctx *task, int flags);

int silofs_do_walkfs(struct silofs_task_ctx            *task,
                     const struct silofs_laddr_visitor *lvis);

int silofs_do_unrefs(struct silofs_task_ctx *task);

int silofs_forget_loose_ii(struct silofs_task_ctx   *task,
                           struct silofs_inode_info *ii);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* file */

/* regual-file sub-types */
enum silofs_file_type {
	SILOFS_FILE_TYPE_NONE = 0,
	SILOFS_FILE_TYPE1     = 1,
	SILOFS_FILE_TYPE2     = 2,
};

void silofs_ii_setup_reg(struct silofs_inode_info *ii);

int silofs_drop_reg(struct silofs_task_ctx   *task,
                    struct silofs_inode_info *ii);

int silofs_do_write(struct silofs_task_ctx *task, struct silofs_inode_info *ii,
                    const void *buf, size_t len, off_t off, int o_flags,
                    bool kill_suidgid, size_t *out_len);

int silofs_do_write_iter(struct silofs_task_ctx   *task,
                         struct silofs_inode_info *ii, int o_flags,
                         bool kill_suidgid, struct silofs_rwiter_ctx *rwi_ctx);

int silofs_do_read(struct silofs_task_ctx *task, struct silofs_inode_info *ii,
                   void *buf, size_t len, off_t off, int o_flags,
                   size_t *out_len);

int silofs_do_read_iter(struct silofs_task_ctx   *task,
                        struct silofs_inode_info *ii, int o_flags,
                        struct silofs_rwiter_ctx *rwi_ctx);

int silofs_do_lseek(struct silofs_task_ctx *task, struct silofs_inode_info *ii,
                    off_t off, int whence, off_t *out_off);

int silofs_do_fallocate(struct silofs_task_ctx   *task,
                        struct silofs_inode_info *ii, int mode, off_t off,
                        off_t length);

int silofs_do_truncate(struct silofs_task_ctx   *task,
                       struct silofs_inode_info *ii, off_t off,
                       bool kill_suidgid);

int silofs_do_fiemap(struct silofs_task_ctx   *task,
                     struct silofs_inode_info *ii, struct fiemap *fm);

int silofs_do_copy_file_range(struct silofs_task_ctx   *task,
                              struct silofs_inode_info *ii_in,
                              struct silofs_inode_info *ii_out, off_t off_in,
                              off_t off_out, size_t len, int flags,
                              size_t *out_ncp);

int silofs_do_rdwr_post(const struct silofs_task_ctx *task, int wr_mode,
                        const struct silofs_iovec *iov, size_t cnt);

int silofs_verify_ftree_node(const struct silofs_ftree_node *ftn);

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
/* vstage */

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

int silofs_require_spleaf_of(struct silofs_task_ctx     *task,
                             const struct silofs_vaddr  *vaddr,
                             enum silofs_stg_mode        stg_mode,
                             struct silofs_spleaf_info **out_sli);

int silofs_resolve_llink_of(struct silofs_task_ctx    *task,
                            const struct silofs_vaddr *vaddr,
                            enum silofs_stg_mode       stg_mode,
                            struct silofs_llink       *out_llink);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_stage_inode_of(struct silofs_task_ctx *task, ino_t ino,
                          enum silofs_stg_mode       stg_mode,
                          struct silofs_inode_info **out_ii);

int silofs_fetch_cached_vnode(struct silofs_task_ctx    *task,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_vnode_info **out_vni);

int silofs_fetch_cached_inode(struct silofs_task_ctx *task, ino_t ino,
                              struct silofs_inode_info **out_ii);

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
