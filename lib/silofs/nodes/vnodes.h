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
#ifndef SILOFS_VNODES_H_
#define SILOFS_VNODES_H_

#include <silofs/ondisk.h>
#include <silofs/types.h>
#include <silofs/infra.h>
#include <silofs/addr.h>

enum silofs_vni_flags {
	SILOFS_VNF_RECHECK = SILOFS_BIT(0),
	SILOFS_VNF_PINNED  = SILOFS_BIT(1),
	SILOFS_VNF_ACTIVE  = SILOFS_BIT(2),
	SILOFS_VNF_LOOSE   = SILOFS_BIT(3),
};

/* vnode */
struct silofs_vnode_info {
	struct silofs_node_info vn_ni;
	struct silofs_vaddr     vn_vaddr;
	struct silofs_paddr     vn_curr_paddr;
	uint64_t                vn_magic;
	uint32_t                vn_flags;
	int                     vn_asyncwr;
	bool                    vn_use_pn_vnis_dq;

	bool (*isevictable_fn)(const struct silofs_vnode_info *vni);
};

/* super node */
struct silofs_sbnode_info {
	struct silofs_vnode_info   sbn_vni;
	struct silofs_superb_node *sbn;
};

/* space allocation node */
struct silofs_spnode_info2 {
	struct silofs_vnode_info  spn_vni;
	struct silofs_space_node *spn;
	/* in-memory only */
	unsigned spn_nused_ref;
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
	struct silofs_vnode_info   svn_vni;
	struct silofs_symval_node *svn;
};

/* dir tree node */
struct silofs_dtnode_info {
	struct silofs_vnode_info  dtn_vni;
	struct silofs_dtree_node *dtn;
};

/* file tree node */
struct silofs_ftnode_info {
	struct silofs_vnode_info  ftn_vni;
	struct silofs_ftree_node *ftn;
};

/* file data node */
union silofs_fdnode_u {
	struct silofs_data_node1  *dn1;
	struct silofs_data_node4  *dn4;
	struct silofs_data_node64 *dn64;
};

struct silofs_fdnode_info {
	struct silofs_vnode_info fdn_vni;
	union silofs_fdnode_u    fdn;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_lview * //
silofs_vni_lview(const struct silofs_vnode_info *vni);

struct silofs_lview * //
silofs_vni_lviewx(const struct silofs_vnode_info *vni);

size_t silofs_vni_refcnt(const struct silofs_vnode_info *vni);

void silofs_vni_incref(struct silofs_vnode_info *vni);

void silofs_vni_decref(struct silofs_vnode_info *vni);

bool silofs_vni_isdirty(const struct silofs_vnode_info *vni);

void silofs_vni_setdirty(struct silofs_vnode_info *vni,
                         struct silofs_inode_info *ii);

void silofs_vni_cleardirty(struct silofs_vnode_info *vni);

bool silofs_vni_isevictable(const struct silofs_vnode_info *vni);

void silofs_vni_set_dq(struct silofs_vnode_info *vni,
                       struct silofs_dirtyq     *dq);

bool silofs_vni_need_recheck(const struct silofs_vnode_info *vni);

void silofs_vni_set_rechecked(struct silofs_vnode_info *vni);

enum silofs_vtype silofs_vni_vtype(const struct silofs_vnode_info *vni);

const struct silofs_vaddr *
silofs_vni_vaddr(const struct silofs_vnode_info *vni);

struct silofs_vnode_info * //
silofs_vni_from_dqe(const struct silofs_dq_elem *dqe);

struct silofs_vnode_info * //
silofs_vni_from_hmqe(struct silofs_hmapq_elem *hmqe);

void silofs_vni_remove_from(struct silofs_vnode_info *vni,
                            struct silofs_hmapq      *hmapq);

int silofs_verify_lview_of(const struct silofs_vnode_info *vni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_sbnode_info * //
silofs_sbi_from_vni(struct silofs_vnode_info *vni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_inode_info *
silofs_ii_from_vni(const struct silofs_vnode_info *vni);

struct silofs_inode_info *silofs_ii_from_dqe(struct silofs_dq_elem *dqe);

struct silofs_xanode_info *silofs_xai_from_vni(struct silofs_vnode_info *vni);

struct silofs_symval_info *silofs_svi_from_vni(struct silofs_vnode_info *vni);

struct silofs_dtnode_info *silofs_dti_from_vni(struct silofs_vnode_info *vni);

struct silofs_ftnode_info *silofs_fti_from_vni(struct silofs_vnode_info *vni);

struct silofs_fdnode_info *silofs_fdi_from_vni(struct silofs_vnode_info *vni);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_vnode_info *
silofs_new_vnode(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr);

void silofs_del_vnode(struct silofs_vnode_info *vni,
                      struct silofs_alloc      *alloc);

void silofs_seal_vnode(const struct silofs_vnode_info *vni);

#endif /* SILOFS_VNODES_H_ */
