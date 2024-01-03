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

struct silofs_lnode_info;
struct silofs_unode_info;
struct silofs_vnode_info;


enum silofs_lnflags {
	SILOFS_LNF_RECHECK      = SILOFS_BIT(0),
	SILOFS_LNF_PINNED       = SILOFS_BIT(1),
	SILOFS_LNF_ACTIVE       = SILOFS_BIT(2),
	SILOFS_LNF_LOOSE        = SILOFS_BIT(3),
};

/* nodes' delete hook */
typedef void (*silofs_lnode_del_fn)(struct silofs_lnode_info *lni,
                                    struct silofs_alloc *alloc, int l_flags);

/* lnode: base object of all logical-nodes */
struct silofs_lnode_info {
	struct silofs_lrumap_elem       l_lme;
	struct silofs_avl_node          l_ds_avl_node;
	struct silofs_lnode_info       *l_ds_next;
	struct silofs_fsenv            *l_fsenv;
	struct silofs_view             *l_view;
	silofs_lnode_del_fn             l_del_cb;
	enum silofs_lnflags             l_flags;
	enum silofs_ltype               l_ltype;
};

/* unode */
struct silofs_unode_info {
	struct silofs_lnode_info        u_lni;
	struct silofs_ulink             u_ulink;
	struct silofs_list_head         u_dq_lh;
	struct silofs_dirtyq           *u_dq;
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
	int                             v_asyncwr;
	struct silofs_list_head         v_dq_lh;
	struct silofs_vaddr             v_vaddr;
	struct silofs_llink             v_llink;
	struct silofs_dirtyq           *v_dq;
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

struct silofs_sb_info *
silofs_sbi_from_ui(const struct silofs_unode_info *ui);

struct silofs_spnode_info *
silofs_sni_from_ui(const struct silofs_unode_info *ui);

struct silofs_spleaf_info *
silofs_sli_from_ui(const struct silofs_unode_info *ui);


struct silofs_inode_info *
silofs_ii_from_lni(const struct silofs_lnode_info *lni);

struct silofs_inode_info *
silofs_ii_from_vi(const struct silofs_vnode_info *vi);

struct silofs_inode_info *
silofs_ii_from_dirty_lh(struct silofs_list_head *lh);

void silofs_ii_set_ino(struct silofs_inode_info *ii, ino_t ino);

void silofs_ii_undirtify_vis(struct silofs_inode_info *ii);


struct silofs_xanode_info *silofs_xai_from_vi(struct silofs_vnode_info *vi);

struct silofs_symval_info *silofs_syi_from_vi(struct silofs_vnode_info *vi);

struct silofs_dnode_info *silofs_dni_from_vi(struct silofs_vnode_info *vi);

struct silofs_finode_info *silofs_fni_from_vi(struct silofs_vnode_info *vi);

struct silofs_fileaf_info *silofs_fli_from_vi(struct silofs_vnode_info *vi);


struct silofs_vnode_info *
silofs_vi_from_dirty_lh(struct silofs_list_head *lh);

struct silofs_vnode_info *
silofs_vi_from_lni(const struct silofs_lnode_info *lni);


struct silofs_unode_info *
silofs_ui_from_lni(const struct silofs_lnode_info *lni);

struct silofs_unode_info *
silofs_ui_from_dirty_lh(struct silofs_list_head *lh);

void silofs_ui_set_fsenv(struct silofs_unode_info *ui,
                         struct silofs_fsenv *fsenv);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_unode_info *
silofs_new_ui(struct silofs_alloc *alloc, const struct silofs_ulink *ulink);

struct silofs_vnode_info *
silofs_new_vi(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr);

bool silofs_ui_is_active(const struct silofs_unode_info *ui);

void silofs_ui_set_active(struct silofs_unode_info *ui);

int silofs_ui_verify_view(struct silofs_unode_info *ui);

int silofs_vi_verify_view(struct silofs_vnode_info *vi);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_seal_vnode(struct silofs_vnode_info *vi);

void silofs_seal_unode(struct silofs_unode_info *ui);

bool silofs_test_evictable(const struct silofs_lnode_info *lni);

#endif /* SILOFS_LNODES_H_ */
