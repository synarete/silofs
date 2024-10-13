/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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

#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/hmdq.h>

struct silofs_lnode_info;
struct silofs_unode_info;
struct silofs_vnode_info;


enum silofs_lnflags {
	SILOFS_LNF_RECHECK      = SILOFS_BIT(0),
	SILOFS_LNF_PINNED       = SILOFS_BIT(1),
	SILOFS_LNF_ACTIVE       = SILOFS_BIT(2),
	SILOFS_LNF_LOOSE        = SILOFS_BIT(3),
};

/* lnode: base object of all logical-nodes */
struct silofs_lnode_info {
	struct silofs_hmapq_elem        ln_hmqe;
	struct silofs_avl_node          ln_ds_avl_node;
	struct silofs_lnode_info       *ln_ds_next;
	struct silofs_fsenv            *ln_fsenv;
	struct silofs_view             *ln_view;
	enum silofs_lnflags             ln_flags;
	enum silofs_ltype               ln_ltype;
};

/* unode */
struct silofs_unode_info {
	struct silofs_lnode_info        u_lni;
	struct silofs_ulink             u_ulink;
	uint64_t                        u_magic;
};

/* space-stats */
struct silofs_stats_info {
	struct silofs_space_stats      *spst_curr;
	struct silofs_space_stats      *spst_base;
	struct silofs_sb_info          *sbi;
};

/* super-block */
struct silofs_sb_info {
	struct silofs_unode_info        sb_ui;
	struct silofs_stats_info        sb_sti;
	struct silofs_super_block      *sb;
};

/* space-node */
struct silofs_spnode_info {
	struct silofs_unode_info        sn_ui;
	struct silofs_spmap_node       *sn;
	size_t                          sn_nactive_subs;
};

/* space-leaf */
struct silofs_spleaf_info {
	struct silofs_unode_info        sl_ui;
	struct silofs_spmap_leaf       *sl;
	size_t                          sl_nused_bytes;
};

/* vnode */
struct silofs_vnode_info {
	struct silofs_lnode_info        v_lni;
	struct silofs_vaddr             v_vaddr;
	struct silofs_llink             v_llink;
	uint64_t                        v_magic;
	int                             v_asyncwr;
};

/* inode */
struct silofs_inode_info {
	struct silofs_vnode_info        i_vi;
	struct silofs_dirtyq            i_dq_vis;
	struct silofs_inode            *inode;
	struct silofs_inode_info       *i_looseq_next;
	struct timespec                 i_atime_lazy;
	ino_t  i_ino;
	long   i_nopen;
	long   i_nlookup;
	bool   i_in_looseq;
};

/* xattr */
struct silofs_xanode_info {
	struct silofs_vnode_info        xan_vi;
	struct silofs_xattr_node       *xan;
};

/* symval */
struct silofs_symval_info {
	struct silofs_vnode_info        sy_vi;
	struct silofs_symlnk_value     *syv;
};

/* dir-node */
struct silofs_dnode_info {
	struct silofs_vnode_info        dn_vi;
	struct silofs_dtree_node       *dtn;
};

/* file-node */
struct silofs_finode_info {
	struct silofs_vnode_info        fn_vi;
	struct silofs_ftree_node       *ftn;
};

/* file-leaf */
union silofs_fileaf_u {
	struct silofs_data_block1      *db1;
	struct silofs_data_block4      *db4;
	struct silofs_data_block64     *db;
};

struct silofs_fileaf_info {
	struct silofs_vnode_info        fl_vi;
	union silofs_fileaf_u           flu;
};


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_lni_refcnt(const struct silofs_lnode_info *lni);

void silofs_lni_incref(struct silofs_lnode_info *lni);

void silofs_lni_decref(struct silofs_lnode_info *lni);

void silofs_lni_dirtify(struct silofs_lnode_info *lni);

void silofs_lni_undirtify(struct silofs_lnode_info *lni);

void silofs_lni_remove_from(struct silofs_lnode_info *lni,
                            struct silofs_hmapq *hmapq);

bool silofs_lni_isevictable(const struct silofs_lnode_info *lni);

bool silofs_lni_isdirty(const struct silofs_lnode_info *lni);

int silofs_lni_verify_view(struct silofs_lnode_info *lni);

struct silofs_lnode_info *
silofs_lni_from_dqe(const struct silofs_dq_elem *dqe);

struct silofs_lnode_info *
silofs_lni_from_hmqe(const struct silofs_hmapq_elem *hmqe);

struct silofs_hmapq_elem *
silofs_lni_to_hmqe(struct silofs_lnode_info *lni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ui_incref(struct silofs_unode_info *ui);

void silofs_ui_decref(struct silofs_unode_info *ui);

void silofs_ui_dirtify(struct silofs_unode_info *ui);

void silofs_ui_undirtify(struct silofs_unode_info *ui);

bool silofs_ui_isevictable(const struct silofs_unode_info *ui);

bool silofs_ui_isactive(const struct silofs_unode_info *ui);

void silofs_ui_set_active(struct silofs_unode_info *ui);

void silofs_ui_seal_view(struct silofs_unode_info *ui);

enum silofs_ltype silofs_ui_ltype(const struct silofs_unode_info *ui);

void silofs_ui_set_dq(struct silofs_unode_info *ui, struct silofs_dirtyq *dq);

struct silofs_unode_info *
silofs_ui_from_lni(const struct silofs_lnode_info *lni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_vi_refcnt(const struct silofs_vnode_info *vi);

void silofs_vi_incref(struct silofs_vnode_info *vi);

void silofs_vi_decref(struct silofs_vnode_info *vi);

bool silofs_vi_isdirty(const struct silofs_vnode_info *vi);

void silofs_vi_dirtify(struct silofs_vnode_info *vi,
                       struct silofs_inode_info *ii);

void silofs_vi_undirtify(struct silofs_vnode_info *vi);

bool silofs_vi_isevictable(const struct silofs_vnode_info *vi);

void silofs_vi_seal_view(struct silofs_vnode_info *vi);

void silofs_vi_set_dq(struct silofs_vnode_info *vi, struct silofs_dirtyq *dq);

struct silofs_vnode_info *
silofs_vi_from_dqe(struct silofs_dq_elem *dqe);

struct silofs_vnode_info *
silofs_vi_from_lni(const struct silofs_lnode_info *lni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_sb_info *
silofs_sbi_from_ui(struct silofs_unode_info *ui);

struct silofs_spnode_info *
silofs_sni_from_ui(struct silofs_unode_info *ui);

struct silofs_spleaf_info *
silofs_sli_from_ui(struct silofs_unode_info *ui);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_inode_info *
silofs_ii_from_lni(const struct silofs_lnode_info *lni);

struct silofs_inode_info *
silofs_ii_from_vi(const struct silofs_vnode_info *vi);

struct silofs_inode_info *
silofs_ii_from_dqe(struct silofs_dq_elem *dqe);


struct silofs_xanode_info *
silofs_xai_from_vi(struct silofs_vnode_info *vi);

struct silofs_symval_info *
silofs_syi_from_vi(struct silofs_vnode_info *vi);

struct silofs_dnode_info *
silofs_dni_from_vi(struct silofs_vnode_info *vi);

struct silofs_finode_info *
silofs_fni_from_vi(struct silofs_vnode_info *vi);

struct silofs_fileaf_info *
silofs_fli_from_vi(struct silofs_vnode_info *vi);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

struct silofs_unode_info *
silofs_new_unode(struct silofs_alloc *alloc,
                 const struct silofs_ulink *ulink);

void silofs_del_unode(struct silofs_unode_info *ui,
                      struct silofs_alloc *alloc, int flags);

struct silofs_vnode_info *
silofs_new_vnode(struct silofs_alloc *alloc,
                 const struct silofs_vaddr *vaddr);

void silofs_del_vnode(struct silofs_vnode_info *vi,
                      struct silofs_alloc *alloc, int flags);

#endif /* SILOFS_LNODES_H_ */
