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

struct silofs_snode_info;
struct silofs_unode_info;
struct silofs_vnode_info;


/* nodes' delete hook */
typedef void (*silofs_snode_del_fn)(struct silofs_snode_info *si,
                                    struct silofs_alloc *alloc);

/* snode */
struct silofs_snode_info {
	struct silofs_cache_elem        s_ce;
	silofs_snode_del_fn             s_del_hook;
	const struct silofs_snode_vtbl *s_vtbl;
	struct silofs_uber             *s_uber;
	struct silofs_mdigest          *s_md;
	struct silofs_list_head         s_dq_lh;
	struct silofs_avl_node          s_ds_an;
	struct silofs_snode_info       *s_ds_next;
	union silofs_view              *s_view;
	loff_t                          s_view_pos;
	size_t                          s_view_len;
	silofs_dqid_t                   s_dqid;
	enum silofs_stype               s_stype;
	bool                            s_view_dec;
	volatile bool                   s_noflush;
};

/* unode */
struct silofs_unode_info {
	struct silofs_uaddr             u_uaddr;
	struct silofs_snode_info        u_si;
	struct silofs_list_head         u_pack_lh;
	struct silofs_repo             *u_repo;
	struct silofs_ubk_info         *u_ubki;
	bool                            u_verified;
	bool                            u_in_pq;
	char                            u_pad[6];
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
	struct silofs_snode_info        v_si;
	struct silofs_vaddr             v_vaddr;
	struct silofs_oaddr             v_oaddr;
	struct silofs_iovref            v_iovr;
	struct silofs_vbk_info         *v_vbki;
	struct silofs_sb_info          *v_sbi;
	bool                            v_recheck;
	bool                            v_verified;
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
	struct silofs_data_block       *db;
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
silofs_vi_from_si(const struct silofs_snode_info *si);

bool silofs_vi_isdata(const struct silofs_vnode_info *vi);

void silofs_vi_stamp_mark_visible(struct silofs_vnode_info *vi);

void silofs_vi_set_dqid(struct silofs_vnode_info *vi, silofs_dqid_t dqid);


struct silofs_unode_info *
silofs_ui_from_si(const struct silofs_snode_info *si);

void silofs_ui_bind_uber(struct silofs_unode_info *ui,
                         struct silofs_uber *uber);

void silofs_ui_seal_meta(struct silofs_unode_info *ui);

void silofs_zero_stamp_meta(union silofs_view *view, enum silofs_stype stype);

void silofs_fill_csum_meta(union silofs_view *view);

int silofs_verify_csum_meta(const union silofs_view *view);


struct silofs_bk_info *silofs_bki_of(const struct silofs_snode_info *si);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_unode_info *
silofs_new_ui(struct silofs_alloc *alloc, const struct silofs_uaddr *uaddr);

struct silofs_vnode_info *
silofs_new_vi(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr);

void silofs_ui_bind_view(struct silofs_unode_info *ui);

int silofs_ui_verify_view(struct silofs_unode_info *ui);

void silofs_vi_bind_view(struct silofs_vnode_info *vi);

int silofs_vi_verify_view(struct silofs_vnode_info *vi);


int silofs_verify_view_by(const union silofs_view *view,
                          const enum silofs_stype stype);

union silofs_view *silofs_make_view_of(struct silofs_header *hdr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_seal_vnode(struct silofs_vnode_info *vi);

void silofs_seal_unode(struct silofs_unode_info *ui);

bool silofs_test_evictable(const struct silofs_snode_info *si);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/


int silofs_encrypt_view(const struct silofs_uber *uber,
                        const struct silofs_oaddr *oaddr,
                        const union silofs_view *view, void *ptr);

int silofs_decrypt_view(const struct silofs_uber *uber,
                        const struct silofs_oaddr *oaddr,
                        const union silofs_view *view, void *ptr);

#endif /* SILOFS_NODES_H_ */
