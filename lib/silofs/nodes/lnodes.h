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

#include <silofs/ondisk.h>
#include <silofs/types.h>
#include <silofs/infra.h>
#include <silofs/addr.h>

/* lnode */
struct silofs_lnode_info {
	struct silofs_node_info ln_ni;
	struct silofs_laddr     ln_laddr;
	struct silofs_paddr     ln_curr_paddr;
	uint64_t                ln_magic;
	int                     ln_asyncwr;

	bool (*isevictable_fn)(const struct silofs_lnode_info *lni);
};

/* super node */
struct silofs_sbnode_info {
	struct silofs_lnode_info   sbn_lni;
	struct silofs_superb_node *sbn;
};

/* space allocation node */
struct silofs_spnode_info {
	struct silofs_lnode_info  spn_lni;
	struct silofs_space_node *spn;
	/* in-memory only */
	unsigned spn_nused_ref;
};

/* inode */
struct silofs_inode_info {
	struct silofs_lnode_info  i_lni;
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
	struct silofs_lnode_info  xan_lni;
	struct silofs_xattr_node *xan;
};

/* symbolic-link value node */
struct silofs_symval_info {
	struct silofs_lnode_info   svn_lni;
	struct silofs_symval_node *svn;
};

/* dir tree node */
struct silofs_dtnode_info {
	struct silofs_lnode_info  dtn_lni;
	struct silofs_dtree_node *dtn;
};

/* file tree node */
struct silofs_ftnode_info {
	struct silofs_lnode_info  ftn_lni;
	struct silofs_ftree_node *ftn;
};

/* file leaf (data) node */
union silofs_flnode_u {
	struct silofs_data_node1  *dn1;
	struct silofs_data_node4  *dn4;
	struct silofs_data_node64 *dn64;
};

struct silofs_flnode_info {
	struct silofs_lnode_info fln_lni;
	union silofs_flnode_u    fln;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_lview * //
silofs_lni_lview(const struct silofs_lnode_info *lni);

struct silofs_lview * //
silofs_lni_lviewx(const struct silofs_lnode_info *lni);

size_t silofs_lni_refcnt(const struct silofs_lnode_info *lni);

void silofs_lni_incref(struct silofs_lnode_info *lni);

void silofs_lni_decref(struct silofs_lnode_info *lni);

bool silofs_lni_isdirty(const struct silofs_lnode_info *lni);

void silofs_lni_setdirty(struct silofs_lnode_info *lni,
                         struct silofs_inode_info *ii);

void silofs_lni_cleardirty(struct silofs_lnode_info *lni);

bool silofs_lni_isevictable(const struct silofs_lnode_info *lni);

void silofs_lni_set_dq(struct silofs_lnode_info *lni,
                       struct silofs_dirtyq     *dq);

bool silofs_lni_need_recheck(const struct silofs_lnode_info *lni);

void silofs_lni_set_rechecked(struct silofs_lnode_info *lni);

enum silofs_ltype silofs_lni_ltype(const struct silofs_lnode_info *lni);

const struct silofs_laddr *
silofs_lni_laddr(const struct silofs_lnode_info *lni);

struct silofs_lnode_info * //
silofs_lni_from_dqe(const struct silofs_dq_elem *dqe);

struct silofs_lnode_info * //
silofs_lni_from_hmqe(struct silofs_hmapq_elem *hmqe);

void silofs_lni_remove_from(struct silofs_lnode_info *lni,
                            struct silofs_hmapq      *hmapq);

int silofs_verify_lview_of(const struct silofs_lnode_info *lni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_sbnode_info * //
silofs_sbi_from_lni(struct silofs_lnode_info *lni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_inode_info *
silofs_ii_from_lni(const struct silofs_lnode_info *lni);

struct silofs_inode_info *silofs_ii_from_dqe(struct silofs_dq_elem *dqe);

struct silofs_xanode_info *silofs_xai_from_lni(struct silofs_lnode_info *lni);

struct silofs_symval_info *silofs_svi_from_lni(struct silofs_lnode_info *lni);

struct silofs_dtnode_info *silofs_dti_from_lni(struct silofs_lnode_info *lni);

struct silofs_ftnode_info *silofs_fti_from_lni(struct silofs_lnode_info *lni);

struct silofs_flnode_info *silofs_fli_from_lni(struct silofs_lnode_info *lni);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_lnode_info *
silofs_new_lnode(struct silofs_alloc *alloc, const struct silofs_laddr *laddr);

void silofs_del_lnode(struct silofs_lnode_info *lni,
                      struct silofs_alloc      *alloc);

void silofs_seal_lnode(const struct silofs_lnode_info *lni);

#endif /* SILOFS_LNODES_H_ */
