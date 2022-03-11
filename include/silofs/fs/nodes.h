/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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

struct silofs_crypto;
struct silofs_tnode_info;
struct silofs_unode_info;
struct silofs_vnode_info;

/* nodes' vtbl */
struct silofs_tnode_vtbl {
	void (*del)(struct silofs_tnode_info *ti,
	            struct silofs_alloc_if *alif);
	bool (*evictable)(const struct silofs_tnode_info *ti);
	void (*seal)(struct silofs_tnode_info *ti);
	int (*resolve)(const struct silofs_tnode_info *ti,
	               struct silofs_oaddr *out_oaddr);
};

/* tnode */
struct silofs_tnode_info {
	struct silofs_cache_elem        t_ce;
	const struct silofs_tnode_vtbl *t_vtbl;
	struct silofs_fs_apex          *t_apex;
	struct silofs_crypto           *t_crypto;
	struct silofs_list_head         t_dq_lh;
	struct silofs_avl_node          t_ds_an;
	struct silofs_tnode_info       *t_ds_next;
	union silofs_view              *t_view;
	enum silofs_stype               t_stype;
	bool t_noflush;
};

/* unode */
struct silofs_unode_info {
	struct silofs_uaddr             u_uaddr;
	struct silofs_packid            u_packid;
	struct silofs_tnode_info        u_ti;
	struct silofs_list_head         u_unom_lh;
	struct silofs_list_head         u_pack_lh;
	struct silofs_ubk_info         *u_ubi;
	struct silofs_pack_iovs        *u_piov;
	bool                            u_tmapped;
	bool                            u_verified;
	bool                            u_plinked;
};

/* super-block */
struct silofs_sb_info {
	struct silofs_unode_info        s_ui;
	struct silofs_itable_info       s_itbi;
	struct silofs_super_block      *sb;
	struct silofs_alloc_if         *s_alif;
	struct silofs_repo             *s_repo;
	struct silofs_ucred             s_owner;
	unsigned long                   s_ctl_flags;
	unsigned long                   s_ms_flags;
	time_t                          s_mntime;
	loff_t                          s_vspa_data1k;
	loff_t                          s_vspa_data4k;
	loff_t                          s_vspa_databk;
	loff_t                          s_vspa_itnode;
	loff_t                          s_vspa_inode;
	loff_t                          s_vspa_xanode;
	loff_t                          s_vspa_dirnode;
	loff_t                          s_vspa_filenode;
	loff_t                          s_vspa_symval;
};

/* spnode */
struct silofs_spnode_info {
	struct silofs_unode_info        sn_ui;
	struct silofs_spmap_node       *sn;
	size_t                          sn_nactive_subs;
};

/* spleaf */
struct silofs_spleaf_info {
	struct silofs_unode_info        sl_ui;
	struct silofs_spmap_leaf       *sl;
	size_t                          sl_nused_bytes;
};

/* vnode */
struct silofs_vnode_info {
	struct silofs_tnode_info        v_ti;
	struct silofs_vaddr             v_vaddr;
	struct silofs_xiovref           v_fir;
	struct silofs_vbk_info         *v_vbi;
	struct silofs_sb_info          *v_sbi;
	bool                            v_recheck;
	bool                            v_verified;
};

/* itable */
struct silofs_itnode_info {
	struct silofs_vnode_info        itn_vi;
	struct silofs_itable_node      *itn;
};

/* inode */
struct silofs_inode_info {
	struct silofs_vnode_info        i_vi;
	struct silofs_inode            *inode;
	struct timespec                 i_atime_lazy;
	ino_t  i_ino;
	long   i_nopen;
	long   i_nlookup;
	bool   i_pinned;
};

/* xattr */
struct silofs_xanode_info {
	struct silofs_vnode_info        xa_vi;
	struct silofs_xattr_node       *xan;
};

/* symval */
struct silofs_symval_info {
	struct silofs_vnode_info        sy_vi;
	struct silofs_symlnk_value     *syv;
};

/* dnode */
struct silofs_dnode_info {
	struct silofs_vnode_info        dn_vi;
	struct silofs_dtree_node       *dtn;
};

/* finode */
struct silofs_finode_info {
	struct silofs_vnode_info        fn_vi;
	struct silofs_ftree_node       *ftn;
};

/* fileaf */
union silofs_fileaf_u {
	struct silofs_data_block1       *db1;
	struct silofs_data_block4       *db4;
	struct silofs_data_block        *db;
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

void silofs_sni_rebind_view(struct silofs_spnode_info *sni);


struct silofs_spleaf_info *
silofs_sli_from_ui(const struct silofs_unode_info *ui);

void silofs_sli_rebind_view(struct silofs_spleaf_info *sli);


struct silofs_itnode_info *silofs_itni_from_vi(struct silofs_vnode_info *vi);

void silofs_itni_rebind_view(struct silofs_itnode_info *itni);


struct silofs_inode_info *
silofs_ii_from_vi(const struct silofs_vnode_info *vi);

void silofs_ii_rebind_view(struct silofs_inode_info *ii, ino_t ino);


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
silofs_vi_from_ti(const struct silofs_tnode_info *ti);

bool silofs_vi_isdata(const struct silofs_vnode_info *vi);

void silofs_vi_stamp_mark_visible(struct silofs_vnode_info *vi);


struct silofs_unode_info *
silofs_ui_from_ti(const struct silofs_tnode_info *ti);

void silofs_ui_clone_into(const struct silofs_unode_info *ui,
                          struct silofs_unode_info *ui_other);

void silofs_ui_bind_apex(struct silofs_unode_info *ui,
                         struct silofs_fs_apex *apex);


void silofs_zero_stamp_meta(union silofs_view *view, enum silofs_stype stype);

void silofs_fill_csum_meta(union silofs_view *view,
                           const struct silofs_mdigest *md);

int silofs_verify_csum_meta(const union silofs_view *view,
                            const struct silofs_mdigest *md);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_unode_info *
silofs_new_ui(struct silofs_alloc_if *alif, const struct silofs_uaddr *uaddr);

struct silofs_vnode_info *
silofs_new_vi(struct silofs_alloc_if *alif, const struct silofs_vaddr *vaddr);

void silofs_ui_bind_view(struct silofs_unode_info *ui);

int silofs_ui_verify_view(struct silofs_unode_info *ui,
                          const struct silofs_mdigest *md);

void silofs_vi_bind_view(struct silofs_vnode_info *vi);

int silofs_vi_verify_view(struct silofs_vnode_info *vi,
                          const struct silofs_mdigest *md);


union silofs_view *silofs_make_view_of(struct silofs_header *hdr);


#endif /* SILOFS_NODES_H_ */
