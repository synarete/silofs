/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#ifndef SILOFS_NODES_H_
#define SILOFS_NODES_H_

struct silofs_lnode_info;
struct silofs_unode_info;
struct silofs_vnode_info;


enum silofs_lnflags {
	SILOFS_LNF_NONE         = 0x00,
	SILOFS_LNF_VERIFIED     = 0x01,
	SILOFS_LNF_RECHECK      = 0x02,
	SILOFS_LNF_PINNED       = 0x04,
};

/* nodes' delete hook */
typedef void (*silofs_lnode_del_fn)(struct silofs_lnode_info *lni,
                                    struct silofs_alloc *allocs, int flags);

/* lnode: base object of all logiacal-nodes */
struct silofs_lnode_info {
	struct silofs_cache_elem        ce;
	struct silofs_avl_node          ds_an;
	silofs_lnode_del_fn             del_hook;
	struct silofs_uber             *uber;
	struct silofs_lnode_info       *ds_next;
	struct silofs_lbk_info         *lbki;
	union silofs_view              *view;
	loff_t                          view_pos;
	uint32_t                        view_len;
	enum silofs_stype               stype;
	enum silofs_lnflags             flags;
};

/* unode */
struct silofs_unode_info {
	struct silofs_lnode_info        u;
	struct silofs_ulink             u_ulink;
	struct silofs_list_head         u_dq_lh;
	struct silofs_dirtyq           *u_dq;
	struct silofs_ubk_info         *u_ubki;
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
	struct silofs_lnode_info        v;
	int                             v_asyncwr;
	struct silofs_list_head         v_dq_lh;
	struct silofs_vaddr             v_vaddr;
	struct silofs_olink             v_olink;
	struct silofs_vbk_info         *v_vbki;
	struct silofs_dirtyq           *v_dq;
};

/* inode */
struct silofs_inode_info {
	struct silofs_vnode_info        i_vi;
	struct silofs_dirtyq            i_dq_vis;
	struct silofs_inode            *inode;
	struct timespec                 i_atime_lazy;
	ino_t  i_ino;
	long   i_nopen;
	long   i_nlookup;
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

void silofs_ii_rebind_view(struct silofs_inode_info *ii, ino_t ino);

void silofs_ii_undirtify_vis(struct silofs_inode_info *ii);


struct silofs_xanode_info *silofs_xai_from_vi(struct silofs_vnode_info *vi);

void silofs_xai_rebind_view(struct silofs_xanode_info *xai);


struct silofs_symval_info *silofs_syi_from_vi(struct silofs_vnode_info *vi);

void silofs_syi_rebind_view(struct silofs_symval_info *syi);


struct silofs_dnode_info *silofs_dni_from_vi(struct silofs_vnode_info *vi);

void silofs_dni_rebind_view(struct silofs_dnode_info *dni);


struct silofs_finode_info *silofs_fni_from_vi(struct silofs_vnode_info *vi);

void silofs_fni_rebind_view(struct silofs_finode_info *fni);


struct silofs_fileaf_info *silofs_fli_from_vi(struct silofs_vnode_info *vi);

void silofs_fli_rebind_view(struct silofs_fileaf_info *fli);


struct silofs_vnode_info *
silofs_vi_from_dirty_lh(struct silofs_list_head *lh);

struct silofs_vnode_info *
silofs_vi_from_lni(const struct silofs_lnode_info *lni);

bool silofs_vi_isdata(const struct silofs_vnode_info *vi);

void silofs_stamp_meta_of(struct silofs_vnode_info *vi);


struct silofs_unode_info *
silofs_ui_from_lni(const struct silofs_lnode_info *lni);

struct silofs_unode_info *
silofs_ui_from_dirty_lh(struct silofs_list_head *lh);

void silofs_ui_set_uber(struct silofs_unode_info *ui,
                        struct silofs_uber *uber);

void silofs_zero_stamp_meta(union silofs_view *view, enum silofs_stype stype);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_unode_info *
silofs_new_ui(struct silofs_alloc *alloc, const struct silofs_ulink *ulink);

struct silofs_vnode_info *
silofs_new_vi(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr);

void silofs_ui_bind_view(struct silofs_unode_info *ui);

int silofs_ui_verify_view(struct silofs_unode_info *ui);

void silofs_vi_bind_view(struct silofs_vnode_info *vi);

int silofs_vi_verify_view(struct silofs_vnode_info *vi);

union silofs_view *silofs_make_view_of(struct silofs_header *hdr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_seal_vnode(struct silofs_vnode_info *vi);

void silofs_seal_unode(struct silofs_unode_info *ui);

bool silofs_test_evictable(const struct silofs_lnode_info *lni);

#endif /* SILOFS_NODES_H_ */
