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
#ifndef SILOFS_LNODES_H_
#define SILOFS_LNODES_H_

#include <silofs/types.h>
#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/nodes/hmapq.h>

enum silofs_lnflags {
	SILOFS_LNF_RECHECK = SILOFS_BIT(0),
	SILOFS_LNF_PINNED  = SILOFS_BIT(1),
	SILOFS_LNF_ACTIVE  = SILOFS_BIT(2),
	SILOFS_LNF_LOOSE   = SILOFS_BIT(3),
};

/* lnode: base object of all logical-nodes */
struct silofs_lnode_info {
	struct silofs_hmapq_elem  ln_hmqe;
	struct silofs_avl_node    ln_ds_avl_node;
	struct silofs_lnode_info *ln_ds_next;
	struct silofs_lview      *ln_view;
	enum silofs_lnflags       ln_flags;
	enum silofs_vtype         ln_vtype;
};

/* unode */
struct silofs_unode_info {
	struct silofs_lnode_info un_lni;
	struct silofs_uaddr      un_uaddr;
	uint64_t                 un_magic;
};

/* space accounting per sub-type */
struct silofs_space_gauges {
	ssize_t nsuper;
	ssize_t nspnode;
	ssize_t nspleaf;
	ssize_t nlsmap;
	ssize_t ninode;
	ssize_t nxanode;
	ssize_t ndtnode;
	ssize_t nsymval;
	ssize_t nftnode;
	ssize_t ndata1k;
	ssize_t ndata4k;
	ssize_t ndata64k;
};

/* space accounting per sub-kind + sub-type */
struct silofs_space_stats {
	time_t                     btime;
	time_t                     ctime;
	size_t                     capacity;
	size_t                     vspacesize;
	uint64_t                   generation;
	struct silofs_space_gauges lsegs;
	struct silofs_space_gauges bks;
	struct silofs_space_gauges objs;
};

/* super-block */
struct silofs_sb_info {
	struct silofs_unode_info   sb_uni;
	struct silofs_space_stats  sb_spst_curr;
	struct silofs_space_stats  sb_spst_prev;
	struct silofs_super_block *sb;
};

/* space-node */
struct silofs_spnode_info {
	struct silofs_unode_info  sn_uni;
	struct silofs_spmap_node *sn;
	size_t                    sn_nactive_subs;
};

/* space-leaf */
struct silofs_spleaf_info {
	struct silofs_unode_info  sl_uni;
	struct silofs_spmap_leaf *sl;
};

/* vnode */
struct silofs_vnode_info {
	struct silofs_lnode_info vn_lni;
	struct silofs_vaddr      vn_vaddr;
	struct silofs_llink      vn_llink;
	uint64_t                 vn_magic;
	int                      vn_asyncwr;

	bool (*isevictable_fn)(const struct silofs_vnode_info *vni);
};

/* logical-space map */
struct silofs_lsmap_info {
	struct silofs_vnode_info ls_vni;
	struct silofs_lsmap     *lsm;
	size_t                   ls_nused_bytes;
	off_t                    ls_off_hint;
};

/* inode */
struct silofs_inode_info {
	struct silofs_vnode_info  i_vni;
	struct silofs_dirtyq      i_dq_vnis;
	struct silofs_inode      *inode;
	struct silofs_inode_info *i_looseq_next;
	struct timespec           i_atime_lazy;
	ino_t                     i_ino;
	long                      i_nopen;
	long                      i_nlookup;
	bool                      i_in_looseq;
};

/* xattr node */
struct silofs_xanode_info {
	struct silofs_vnode_info  xan_vni;
	struct silofs_xattr_node *xan;
};

/* symbolic-link value node */
struct silofs_symval_info {
	struct silofs_vnode_info    syv_vni;
	struct silofs_symlnk_value *syv;
};

/* dir-tree node */
struct silofs_dtnode_info {
	struct silofs_vnode_info  dtn_vni;
	struct silofs_dtree_node *dtn;
};

/* file-tree node */
struct silofs_ftnode_info {
	struct silofs_vnode_info  ftn_vni;
	struct silofs_ftree_node *ftn;
};

/* file-tree leaf */
union silofs_ftleaf_u {
	struct silofs_data_block1  *db1;
	struct silofs_data_block4  *db4;
	struct silofs_data_block64 *db;
};

struct silofs_ftleaf_info {
	struct silofs_vnode_info ftl_vni;
	union silofs_ftleaf_u    ftl;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_lni_refcnt(const struct silofs_lnode_info *lni);

void silofs_lni_incref(struct silofs_lnode_info *lni);

void silofs_lni_decref(struct silofs_lnode_info *lni);

void silofs_lni_dirtify(struct silofs_lnode_info *lni);

void silofs_lni_undirtify(struct silofs_lnode_info *lni);

void silofs_lni_remove_from(struct silofs_lnode_info *lni,
                            struct silofs_hmapq      *hmapq);

bool silofs_lni_isevictable(const struct silofs_lnode_info *lni);

bool silofs_lni_isdirty(const struct silofs_lnode_info *lni);

int silofs_verify_lnode(const struct silofs_lnode_info *lni);

struct silofs_lnode_info *
silofs_lni_from_dqe(const struct silofs_dq_elem *dqe);

struct silofs_lnode_info *
silofs_lni_from_hmqe(const struct silofs_hmapq_elem *hmqe);

struct silofs_hmapq_elem *silofs_lni_to_hmqe(struct silofs_lnode_info *lni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_uni_incref(struct silofs_unode_info *uni);

void silofs_uni_decref(struct silofs_unode_info *uni);

void silofs_uni_dirtify(struct silofs_unode_info *uni);

void silofs_uni_undirtify(struct silofs_unode_info *uni);

bool silofs_uni_isevictable(const struct silofs_unode_info *uni);

bool silofs_uni_isactive(const struct silofs_unode_info *uni);

void silofs_uni_set_active(struct silofs_unode_info *uni);

void silofs_uni_seal_view(struct silofs_unode_info *uni);

void silofs_uni_set_dq(struct silofs_unode_info *uni,
                       struct silofs_dirtyq     *dq);

enum silofs_vtype silofs_uni_vtype(const struct silofs_unode_info *uni);

const struct silofs_uaddr *
silofs_uni_uaddr(const struct silofs_unode_info *uni);

const struct silofs_laddr *
silofs_uni_laddr(const struct silofs_unode_info *uni);

struct silofs_unode_info *
silofs_uni_from_lni(const struct silofs_lnode_info *lni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_vni_refcnt(const struct silofs_vnode_info *vni);

void silofs_vni_incref(struct silofs_vnode_info *vni);

void silofs_vni_decref(struct silofs_vnode_info *vni);

bool silofs_vni_isdirty(const struct silofs_vnode_info *vni);

void silofs_vni_dirtify(struct silofs_vnode_info *vni,
                        struct silofs_inode_info *ii);

void silofs_vni_undirtify(struct silofs_vnode_info *vni);

bool silofs_vni_isevictable(const struct silofs_vnode_info *vni);

void silofs_vni_seal_view(struct silofs_vnode_info *vni);

void silofs_vni_set_dq(struct silofs_vnode_info *vni,
                       struct silofs_dirtyq     *dq);

bool silofs_vni_need_recheck(const struct silofs_vnode_info *vni);

void silofs_vni_set_rechecked(struct silofs_vnode_info *vni);

enum silofs_vtype silofs_vni_vtype(const struct silofs_vnode_info *vni);

const struct silofs_vaddr *
silofs_vni_vaddr(const struct silofs_vnode_info *vni);

struct silofs_vnode_info *silofs_vni_from_dqe(struct silofs_dq_elem *dqe);

struct silofs_vnode_info *
silofs_vni_from_lni(const struct silofs_lnode_info *lni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_sb_info *silofs_sbi_from_uni(struct silofs_unode_info *uni);

struct silofs_spnode_info *silofs_sni_from_uni(struct silofs_unode_info *uni);

struct silofs_spleaf_info *silofs_sli_from_uni(struct silofs_unode_info *uni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_inode_info *
silofs_ii_from_lni(const struct silofs_lnode_info *lni);

struct silofs_inode_info *
silofs_ii_from_vni(const struct silofs_vnode_info *vni);

struct silofs_inode_info *silofs_ii_from_dqe(struct silofs_dq_elem *dqe);

struct silofs_xanode_info *silofs_xai_from_vni(struct silofs_vnode_info *vni);

struct silofs_symval_info *silofs_syi_from_vni(struct silofs_vnode_info *vni);

struct silofs_dtnode_info *silofs_dni_from_vni(struct silofs_vnode_info *vni);

struct silofs_ftnode_info *silofs_fni_from_vni(struct silofs_vnode_info *vni);

struct silofs_ftleaf_info *silofs_fli_from_vni(struct silofs_vnode_info *vni);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_unode_info *
silofs_new_unode(struct silofs_alloc *alloc, const struct silofs_uaddr *uaddr);

void silofs_del_unode(struct silofs_unode_info *uni,
                      struct silofs_alloc *alloc, int flags);

struct silofs_vnode_info *
silofs_new_vnode(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr);

void silofs_del_vnode(struct silofs_vnode_info *vni,
                      struct silofs_alloc *alloc, int flags);

#endif /* SILOFS_LNODES_H_ */
