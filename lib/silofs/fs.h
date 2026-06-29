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
#include <silofs/flags.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>
#include <silofs/pv.h>
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
                        struct silofs_sbnode_info2  **out_sbi);

int silofs_spawn_super2(const struct silofs_task_ctx *task,
                        struct silofs_sbnode_info2  **out_sbi);

int silofs_probe_spnode2(const struct silofs_task_ctx *task,
                         const struct silofs_vaddr    *vaddr);

int silofs_stage_spnode2_of(const struct silofs_task_ctx *task,
                            const struct silofs_vaddr    *ref_vaddr,
                            enum silofs_stg_mode          stg_mode,
                            struct silofs_spnode_info2  **out_spi);

int silofs_spawn_spnode2_of(const struct silofs_task_ctx *task,
                            const struct silofs_vaddr    *ref_vaddr,
                            struct silofs_spnode_info2  **out_spi);

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

#include <silofs/fs/super.h>
#include <silofs/fs/inode.h>
#include <silofs/fs/inops.h>

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* super */
#if 0
struct silofs_spmap_lmap;

int silofs_sb_check_version(const struct silofs_super_block *sb);

bool silofs_sb_test_flags(const struct silofs_super_block *sb,
			  enum silofs_superf               mask);

int silofs_verify_super_block(const struct silofs_super_block *sb);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_uaddr *silofs_sbi_uaddr(const struct silofs_sb_info *sbi);

const struct silofs_laddr *silofs_sbi_laddr(const struct silofs_sb_info *sbi);

const struct silofs_blobid56b *
silofs_sbi_lvid(const struct silofs_sb_info *sbi);

void silofs_sbi_incref(struct silofs_sb_info *sbi);

void silofs_sbi_decref(struct silofs_sb_info *sbi);

void silofs_sbi_setdirty(struct silofs_sb_info *sbi);

void silofs_sbi_setup_spawned(struct silofs_sb_info *sbi);

int silofs_sbi_sproot_of(const struct silofs_sb_info *sbi,
			 enum silofs_vtype            vtype,
			 struct silofs_uaddr         *out_uaddr);

int silofs_sbi_resolve_child(const struct silofs_sb_info *sbi,
			     enum silofs_vtype            vtype,
			     struct silofs_uaddr         *out_uaddr);

void silofs_sbi_bind_child(struct silofs_sb_info *sbi, enum silofs_vtype vtype,
			   const struct silofs_uaddr *uaddr);

void silofs_sbi_resolve_lmap(const struct silofs_sb_info *sbi,
			     struct silofs_spmap_lmap    *out_lmap);

void silofs_sbi_add_flags(struct silofs_sb_info *sbi,
			  enum silofs_superf     flags);

bool silofs_sbi_is_fossil(const struct silofs_sb_info *sbi);

void silofs_sbi_self_blobid(const struct silofs_sb_info *sbi,
			    struct silofs_blobid        *out_blobid);

void silofs_sbi_self_layerid(const struct silofs_sb_info *sbi,
			     struct silofs_layerid       *out_layerid);

int silofs_sbi_main_lseg(const struct silofs_sb_info *sbi,
			 enum silofs_vtype            vspace,
			 struct silofs_lsid          *out_lsid);

void silofs_sbi_bind_main_lseg(struct silofs_sb_info    *sbi,
			       enum silofs_vtype         vspace,
			       const struct silofs_lsid *lsid);

bool silofs_sbi_has_main_lseg(const struct silofs_sb_info *sbi,
			      enum silofs_vtype            vspace);

void silofs_sbi_resolve_main_at(const struct silofs_sb_info *sbi, off_t voff,
				enum silofs_vtype    vspace,
				struct silofs_uaddr *out_uaddr);

bool silofs_sbi_ismutable_lsid(const struct silofs_sb_info *sbi,
			       const struct silofs_lsid    *lsid);

bool silofs_sbi_ismutable_laddr(const struct silofs_sb_info *sbi,
				const struct silofs_laddr   *laddr);

struct silofs_sb_refs {
	struct silofs_uaddr curr;
	struct silofs_uaddr prev;
};

void silofs_sbi_resolve_refs(const struct silofs_sb_info *sbi,
			     struct silofs_sb_refs       *out_refs);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_sbst_setup_spawned(struct silofs_sb_info *sbi);

void silofs_sbst_setup_forked(struct silofs_sb_info       *sbi,
			      const struct silofs_sb_info *sbi_from);

void silofs_sbst_update_lsegs(struct silofs_sb_info *sbi,
			      enum silofs_vtype vtype, ssize_t take);

void silofs_sbst_fetch_from_sb(struct silofs_sb_info *sbi);

void silofs_sbst_force_into_sb(struct silofs_sb_info *sbi);

int silofs_verify_space_stats(const struct silofs_space_stats1k *sp);

#endif
/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* spmaps */

struct silofs_spnode_info;

struct silofs_spmap_lmap {
	struct silofs_laddr laddr[SILOFS_SPMAP_NCHILDS];
	size_t              len[SILOFS_SPMAP_NCHILDS];
	uint32_t            cnt;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

off_t silofs_sni_base_voff(const struct silofs_spnode_info *sni);

enum silofs_height silofs_sni_height(const struct silofs_spnode_info *sni);

const struct silofs_uaddr *
silofs_sni_uaddr(const struct silofs_spnode_info *sni);

const struct silofs_laddr *
silofs_sni_laddr(const struct silofs_spnode_info *sni);

void silofs_sni_incref(struct silofs_spnode_info *sni);

void silofs_sni_decref(struct silofs_spnode_info *sni);

void silofs_sni_setup_spawned(struct silofs_spnode_info *sni,
                              const struct silofs_uaddr *parent, off_t voff);

void silofs_sni_update_nactive(struct silofs_spnode_info *sni);

void silofs_sni_clone_from(struct silofs_spnode_info       *sni,
                           const struct silofs_spnode_info *sni_other);

void silofs_sni_vspace_range(const struct silofs_spnode_info *sni,
                             struct silofs_lrange            *lrange);

void silofs_sni_active_lrange(const struct silofs_spnode_info *sni,
                              struct silofs_lrange            *out_lrange);

void silofs_sni_main_lseg(const struct silofs_spnode_info *sni,
                          struct silofs_lsid              *out_lsid);

void silofs_sni_bind_main_lseg(struct silofs_spnode_info *sni,
                               const struct silofs_lsid  *lsid);

void silofs_sni_resolve_main(const struct silofs_spnode_info *sni, off_t voff,
                             struct silofs_uaddr *out_uaddr);

void silofs_sni_bind_child(struct silofs_spnode_info *sni, off_t voff,
                           const struct silofs_uaddr *uaddr);

int silofs_sni_resolve_child(const struct silofs_spnode_info *sni, off_t voff,
                             struct silofs_uaddr *out_uaddr);

void silofs_sni_resolve_lmap(const struct silofs_spnode_info *sni,
                             struct silofs_spmap_lmap        *out_lmap);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_laddr *
silofs_sli_laddr(const struct silofs_spleaf_info *sli);

const struct silofs_uaddr *
silofs_sli_uaddr(const struct silofs_spleaf_info *sli);

enum silofs_vtype silofs_sli_refvtype(const struct silofs_spleaf_info *sli);

void silofs_sli_incref(struct silofs_spleaf_info *sli);

void silofs_sli_decref(struct silofs_spleaf_info *sli);

void silofs_sli_setup_spawned(struct silofs_spleaf_info *sli,
                              const struct silofs_uaddr *parent,
                              enum silofs_vtype refvtype, off_t voff);

void silofs_sli_get_lrange(const struct silofs_spleaf_info *sli,
                           struct silofs_lrange            *out_lrange);

off_t silofs_sli_base_voff(const struct silofs_spleaf_info *sli);

void silofs_sli_lbk_vaddrs_at(const struct silofs_spleaf_info *sli,
                              const struct silofs_vaddr       *vaddr,
                              struct silofs_vaddrs            *out_vaddrs);

void silofs_sli_main_lseg(const struct silofs_spleaf_info *sli,
                          struct silofs_lsid              *out_lsid);

void silofs_sli_bind_main_lseg(struct silofs_spleaf_info *sli,
                               const struct silofs_lsid  *lsid);

void silofs_sli_bind_child(struct silofs_spleaf_info *sli, off_t voff,
                           const struct silofs_laddr *laddr);

void silofs_sli_clone_from(struct silofs_spleaf_info       *sli,
                           const struct silofs_spleaf_info *sli_other);

int silofs_sli_resolve_main_lbk(const struct silofs_spleaf_info *sli,
                                off_t voff, struct silofs_laddr *out_laddr);

bool silofs_sli_has_child_lbk_at(const struct silofs_spleaf_info *sli,
                                 const struct silofs_vaddr       *vaddr);

int silofs_sli_resolve_child(const struct silofs_spleaf_info *sli, off_t voff,
                             struct silofs_laddr *out_laddr);

int silofs_sli_require_child(struct silofs_spleaf_info *sli,
                             const struct silofs_vaddr *vaddr, bool *out_new);

void silofs_sli_resolve_lmap(const struct silofs_spleaf_info *sli,
                             struct silofs_spmap_lmap        *out_lmaps);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_verify_spmap_node(const struct silofs_spmap_node *sn);

int silofs_verify_spmap_leaf(const struct silofs_spmap_leaf *sl);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* spxmap */

/* short lifo of previously-allocated now-free space-addresses */
struct silofs_spalifo {
	off_t    sal_lifo[63];
	uint32_t sal_size;
	uint32_t sal_ulen;
};

/* map of previously-allocated now-free space (in-memory only) */
struct silofs_spamap {
	struct silofs_spalifo spa_lifo;
	struct silofs_alloc  *spa_alloc;
	struct silofs_avl     spa_avl;
	off_t                 spa_hint;
	unsigned int          spa_cap_max;
	enum silofs_vtype     spa_vtype;
};

/* map of previously-allocated now-free space-addresses by vtype */
struct silofs_spamaps {
	struct silofs_spamap spa_lsmap;
	struct silofs_spamap spa_inode;
	struct silofs_spamap spa_xanode;
	struct silofs_spamap spa_dtnode;
	struct silofs_spamap spa_symval;
	struct silofs_spamap spa_ftnode;
	struct silofs_spamap spa_data1k;
	struct silofs_spamap spa_data4k;
	struct silofs_spamap spa_data64k;
};

/* key of in-memory uaddress-mapping */
struct silofs_uakey {
	off_t              voff;
	enum silofs_height height;
	enum silofs_vtype  vspace;
};

/* in-memory mapping of uaddr by (voff,height,vspace) */
struct silofs_uamap {
	struct silofs_listq      uam_lru;
	struct silofs_alloc     *uam_alloc;
	struct silofs_list_head *uam_htbl;
	uint32_t                 uam_htbl_cap;
	uint32_t                 uam_htbl_sz;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_spamaps_init(struct silofs_spamaps *spam,
                        struct silofs_alloc   *alloc);

void silofs_spamaps_fini(struct silofs_spamaps *spam);

void silofs_spamaps_drop(struct silofs_spamaps *spam);

int silofs_spamaps_trypop(struct silofs_spamaps *spam, enum silofs_vtype vtype,
                          size_t len, off_t *out_voff);

int silofs_spamaps_store(struct silofs_spamaps *spam, enum silofs_vtype vtype,
                         off_t voff, size_t len);

int silofs_spamaps_baseof(const struct silofs_spamaps *spam,
                          enum silofs_vtype vtype, off_t voff, off_t *out);

off_t silofs_spamaps_get_hint(const struct silofs_spamaps *spam,
                              enum silofs_vtype            vtype);

void silofs_spamaps_set_hint(struct silofs_spamaps *spam,
                             enum silofs_vtype vtype, off_t off);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_uakey_setup_by(struct silofs_uakey       *uakey,
                           const struct silofs_uaddr *uaddr);

void silofs_uakey_setup_by2(struct silofs_uakey        *uakey,
                            const struct silofs_lrange *lrange,
                            enum silofs_vtype           vspace);

int silofs_uamap_init(struct silofs_uamap *uamap, struct silofs_alloc *alloc);

void silofs_uamap_fini(struct silofs_uamap *uamap);

const struct silofs_uaddr *
silofs_uamap_lookup(const struct silofs_uamap *uamap,
                    const struct silofs_uakey *uakey);

void silofs_uamap_remove(struct silofs_uamap       *uamap,
                         const struct silofs_uakey *uakey);

int silofs_uamap_insert(struct silofs_uamap       *uamap,
                        const struct silofs_uaddr *uaddr);

void silofs_uamap_drop_all(struct silofs_uamap *uamap);

bool silofs_uamap_drop_lru(struct silofs_uamap *uamap);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* vcache */

#if 0
/* in-memory caching */
struct silofs_vcache {
	struct silofs_alloc *lc_alloc;
	struct silofs_hmapq  lc_uni_hmapq;
	struct silofs_uamap  lc_uamap;
	struct silofs_dirtyq lc_unis_dq;
	struct silofs_vcache lc_vc;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_vcache_init(struct silofs_vcache *vcache,
		       struct silofs_alloc  *alloc);

void silofs_vcache_fini(struct silofs_vcache *vcache);

void silofs_vcache_relax(struct silofs_vcache *vcache, int flags);

void silofs_vcache_drop(struct silofs_vcache *vcache);

struct silofs_unode_info *
silofs_vcache_lookup_uni(struct silofs_vcache      *vcache,
			 const struct silofs_uaddr *uaddr);

struct silofs_unode_info *
silofs_vcache_create_uni(struct silofs_vcache      *vcache,
			 const struct silofs_uaddr *uaddr);

void silofs_vcache_forget_uni(struct silofs_vcache     *vcache,
			      struct silofs_unode_info *uni);

struct silofs_unode_info *
silofs_vcache_find_uni_by(struct silofs_vcache      *vcache,
			  const struct silofs_uakey *uakey);

void silofs_vcache_drop_uamap(struct silofs_vcache *vcache);

void silofs_vcache_collect_stats(const struct silofs_vcache *vcache,
				 struct silofs_cache_stats  *out_cstats);

#endif

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
                           mode_t mode, dev_t rdev, uint64_t igen,
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

int silofs_do_walkfs(struct silofs_task_ctx *task);

int silofs_do_unrefs(struct silofs_task_ctx *task);

int silofs_forget_loose_ii(struct silofs_task_ctx   *task,
                           struct silofs_inode_info *ii);

int silofs_next_inogen(const struct silofs_task_ctx *task, uint64_t *out_igen);

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
