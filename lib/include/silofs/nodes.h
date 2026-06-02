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
#ifndef SILOFS_NODES_H_
#define SILOFS_NODES_H_

#include <silofs/ondisk.h>
#include <silofs/types.h>
#include <silofs/base.h>
#include <silofs/crypt.h>
#include <silofs/addr.h>

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* dirtyq */

/* dirty/destage queue element */
struct silofs_dq_elem {
	struct silofs_list_head drq_lh;
	struct silofs_list_head dsq_lh;
	struct silofs_dirtyq   *drq;
	uint32_t                sz;
	bool                    in_drq;
	bool                    in_dsq;
};

/* dirty elements' queue */
struct silofs_dirtyq {
	struct silofs_listq drq;
	size_t              drq_accum;
};

/* de-stage elements' queue */
struct silofs_destageq {
	struct silofs_listq dsq;
};

typedef int (*silofs_dqe_compare_fn)(const struct silofs_dq_elem *dqe1,
                                     const struct silofs_dq_elem *dqe2);

typedef int (*silofs_dqe_execute_fn)(struct silofs_dq_elem *dqe, void *userp);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_dqe_init(struct silofs_dq_elem *dqe, size_t sz);

void silofs_dqe_fini(struct silofs_dq_elem *dqe);

bool silofs_dqe_isinq(const struct silofs_dq_elem *dqe);

void silofs_dqe_set_dirtyq(struct silofs_dq_elem *dqe,
                           struct silofs_dirtyq  *drq);

void silofs_dqe_markdirty(struct silofs_dq_elem *dqe);

void silofs_dqe_cleardirty(struct silofs_dq_elem *dqe);

bool silofs_dqe_isdirty(const struct silofs_dq_elem *dqe);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_dirtyq_init(struct silofs_dirtyq *drq);

void silofs_dirtyq_fini(struct silofs_dirtyq *drq);

struct silofs_dq_elem * //
silofs_dirtyq_front(const struct silofs_dirtyq *drq);

struct silofs_dq_elem * //
silofs_dirtyq_nextof(const struct silofs_dirtyq  *drq,
                     const struct silofs_dq_elem *dqe);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_destageq_init(struct silofs_destageq *dsq);

void silofs_destageq_fini(struct silofs_destageq *dsq);

void silofs_destageq_populate(struct silofs_destageq     *dsq,
                              const struct silofs_dirtyq *drq);

void silofs_destageq_depopulate(struct silofs_destageq *dsq);

void silofs_destageq_sort(struct silofs_destageq *dsq,
                          silofs_dqe_compare_fn   dqe_cmp_fn);

int silofs_destageq_foreach(const struct silofs_destageq *dsq,
                            silofs_dqe_execute_fn dqe_exec_fn, void *usep);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* hmapq */

#define SILOFS_HMAPQ_ITERALL (0xffffffffU)

/* elements' mapping hash-key types */
enum silofs_hkey_type {
	SILOFS_HKEY_NONE,
	SILOFS_HKEY_PADDR,
	SILOFS_HKEY_UADDR,
	SILOFS_HKEY_VADDR,
};

/* addresses as mapping-key */
union silofs_hkey_u {
	const struct silofs_paddr *paddr;
	const struct silofs_uaddr *uaddr;
	const struct silofs_vaddr *vaddr;
	const void                *key;
};

struct silofs_hkey {
	union silofs_hkey_u   keyu;
	uint64_t              hash;
	enum silofs_hkey_type type;
};

/* caching-elements via hash-map + LRU */
struct silofs_hmapq_elem {
	struct silofs_list_head hme_htb_lh;
	int64_t                 hme_htb_hitcnt;
	struct silofs_list_head hme_lru_lh;
	int64_t                 hme_lru_hitcnt;
	struct silofs_hkey      hme_key;
	bool                    hme_mapped;
	bool                    hme_forgot;
	int32_t                 hme_refcnt;
	int32_t                 hme_magic;
};

/* LRU + hash-map */
struct silofs_hmapq {
	struct silofs_listq      hmq_lru;
	struct silofs_list_head *hmq_htbl;
	size_t                   hmq_htbl_nslots;
	size_t                   hmq_htbl_size;
};

/* iteration call-back function */
typedef int (*silofs_hmapq_elem_fn)(struct silofs_hmapq_elem *, void *);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_hkey_by_paddr(struct silofs_hkey        *hkey,
                          const struct silofs_paddr *paddr);

void silofs_hkey_by_uaddr(struct silofs_hkey        *hkey,
                          const struct silofs_uaddr *uaddr);

void silofs_hkey_by_vaddr(struct silofs_hkey        *hkey,
                          const struct silofs_vaddr *vaddr);

long silofs_hkey_compare(const struct silofs_hkey *hkey1,
                         const struct silofs_hkey *hkey2);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_hmqe_init(struct silofs_hmapq_elem *hmqe);

void silofs_hmqe_fini(struct silofs_hmapq_elem *hmqe);

int silofs_hmqe_refcnt(const struct silofs_hmapq_elem *hmqe);

void silofs_hmqe_incref(struct silofs_hmapq_elem *hmqe);

void silofs_hmqe_decref(struct silofs_hmapq_elem *hmqe);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_hmapq_nslots_by(const struct silofs_alloc *alloc, uint8_t fac);

int silofs_hmapq_init(struct silofs_hmapq *hmapq, struct silofs_alloc *alloc,
                      size_t nslots);

void silofs_hmapq_fini(struct silofs_hmapq *hmapq, struct silofs_alloc *alloc);

struct silofs_hmapq_elem *silofs_hmapq_lookup(const struct silofs_hmapq *hmapq,
                                              const struct silofs_hkey  *hkey);

void silofs_hmapq_store(struct silofs_hmapq      *hmapq,
                        struct silofs_hmapq_elem *hmqe);

void silofs_hmapq_promote(struct silofs_hmapq      *hmapq,
                          struct silofs_hmapq_elem *hmqe, bool now);

void silofs_hmapq_unmap(struct silofs_hmapq      *hmapq,
                        struct silofs_hmapq_elem *hmqe);

void silofs_hmapq_remove(struct silofs_hmapq      *hmapq,
                         struct silofs_hmapq_elem *hmqe);

struct silofs_hmapq_elem *
silofs_hmapq_get_lru(const struct silofs_hmapq *hmapq);

void silofs_hmapq_riterate(struct silofs_hmapq *hmapq, size_t limit,
                           silofs_hmapq_elem_fn cb, void *arg);

size_t silofs_hmapq_overpop(const struct silofs_hmapq *hmapq);

size_t silofs_hmapq_usage(const struct silofs_hmapq *hmapq);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_list_head *
silofs_new_lh_array(struct silofs_alloc *alloc, size_t nelems);

void silofs_del_lh_array(struct silofs_list_head *lista, size_t nelems,
                         struct silofs_alloc *alloc);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* nodeview */

void silofs_hdr_setup(struct silofs_header *hdr, uint8_t stype,
                      enum silofs_hdrf flags);

int silofs_hdr_verify(const struct silofs_header *hdr, uint8_t stype,
                      enum silofs_hdrf flags);

void silofs_hdr_seal(struct silofs_header *hdr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_lview_setup(struct silofs_lview *lview, enum silofs_vtype vtype);

struct silofs_lview *silofs_lview_new(struct silofs_alloc *alloc,
                                      enum silofs_vtype vtype, int flags);

void silofs_lview_del(struct silofs_lview *lview, struct silofs_alloc *alloc,
                      enum silofs_vtype vtype, int flags);

void silofs_lview_seal(struct silofs_lview *lview);

int silofs_lview_verify(const struct silofs_lview *lview,
                        enum silofs_vtype          vtype);

int silofs_encrypt_lview(const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_civkey    *civkey,
                         const struct silofs_lview     *lview,
                         enum silofs_vtype vtype, void *ptr);

int silofs_decrypt_lview(const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_civkey    *civkey,
                         const struct silofs_lview     *lview,
                         enum silofs_vtype vtype, void *ptr);

int silofs_encrypt_lview2(const struct silofs_cipher_hd *ci_hd,
                          const struct silofs_civkey    *civkey,
                          const struct silofs_lview     *lview,
                          struct silofs_lview *lview_enc, size_t len);

int silofs_decrypt_lview2(const struct silofs_cipher_hd *ci_hd,
                          const struct silofs_civkey    *civkey,
                          const struct silofs_lview     *lview_enc,
                          struct silofs_lview *lview, size_t len);

int silofs_decrypt_view_inplace(const struct silofs_cipher_hd *ci_hd,
                                const struct silofs_civkey    *civkey,
                                struct silofs_lview           *lview,
                                enum silofs_vtype              vtype);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_pview_setup(struct silofs_pview *pview, enum silofs_ptype ptype);

void silofs_pview_seal(struct silofs_pview *pview);

int silofs_pview_verify(const struct silofs_pview *pview,
                        enum silofs_ptype          ptype);

int silofs_encrypt_pview(const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_civkey    *civkey,
                         const struct silofs_caad      *caad,
                         const struct silofs_pview     *pview_in,
                         struct silofs_pview           *pview_out,
                         struct silofs_ctag *ctag_out, size_t pview_len);

int silofs_decrypt_pview(const struct silofs_cipher_hd *ci_hd,
                         const struct silofs_civkey    *civkey,
                         const struct silofs_caad      *caad,
                         const struct silofs_ctag      *ctag_in,
                         const struct silofs_pview     *pview_in,
                         struct silofs_pview *pview_out, size_t pview_len);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* de-stage queue */
struct silofs_dstgq {
	struct silofs_listq dq;
};

/* union of all sub view */
union silofs_view {
	struct silofs_pview *pview;
	struct silofs_lview *lview;
	void                *opaque_view;
};

/* base of all in-memory node representations */
struct silofs_node_info {
	struct silofs_hmapq_elem hmqe;
	struct silofs_dq_elem    dqe;
	union silofs_view        view;
	union silofs_view        viewx;
};

void silofs_ni_init(struct silofs_node_info *ni, size_t view_size);

void silofs_ni_fini(struct silofs_node_info *ni);

void silofs_ni_incref(struct silofs_node_info *ni);

void silofs_ni_decref(struct silofs_node_info *ni);

size_t silofs_ni_refcnt(const struct silofs_node_info *ni);

bool silofs_ni_ispinned(const struct silofs_node_info *ni);

size_t silofs_ni_view_size(const struct silofs_node_info *ni);

int silofs_ni_attach_view(struct silofs_node_info *ni,  //
                          struct silofs_alloc *alloc, bool bzero);

void silofs_ni_detach_view(struct silofs_node_info *ni, //
                           struct silofs_alloc *alloc, bool bzero);

int silofs_ni_attach_viewx(struct silofs_node_info *ni,
                           struct silofs_alloc     *alloc);

void silofs_ni_detach_viewx(struct silofs_node_info *ni,
                            struct silofs_alloc     *alloc);

const struct silofs_node_info * //
silofs_ni_from_hmqe(const struct silofs_hmapq_elem *hmqe);

struct silofs_node_info *       //
silofs_ni_from_mut_hmqe(struct silofs_hmapq_elem *hmqe);

const struct silofs_node_info * //
silofs_ni_from_dqe(const struct silofs_dq_elem *dqe);

struct silofs_node_info *       //
silofs_ni_from_mut_dqe(struct silofs_dq_elem *dqe);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* pnodes */

enum silofs_pnodef {
	SILOFS_PNODEF_NONE      = 0x00,
	SILOFS_PNODEF_STAGED_OK = 0x01,
	SILOFS_PNODEF_RDONLY    = 0x02,
};

/* base of all persistent nodes */
struct silofs_pnode_info {
	struct silofs_node_info pn_base;
	struct silofs_pnptr     pn_self;
	struct silofs_ctag      pn_ctag;
	struct silofs_list_head pn_dsq_lh;
	unsigned int            pn_flags;
};

/* uber-node in-memory state */
struct silofs_uber_info {
	struct silofs_pnode_info ub_pni;
	struct silofs_uber_node *ubn;
};

/* blob-descriptor node */
struct silofs_bldesc_info {
	struct silofs_pnode_info bld_pni;
	struct silofs_blob_desc *bld;
};

/* btree-node */
struct silofs_btnode_info {
	struct silofs_pnode_info  btn_pni;
	struct silofs_btree_node *btn;
};

const struct silofs_pnptr *
silofs_pni_self(const struct silofs_pnode_info *pni);

void silofs_pni_markdirty(struct silofs_pnode_info *pni);

void silofs_pni_cleardirty(struct silofs_pnode_info *pni);

void silofs_pni_incref(struct silofs_pnode_info *pni);

void silofs_pni_decref(struct silofs_pnode_info *pni);

void silofs_pni_set_dq(struct silofs_pnode_info *pni,
                       struct silofs_dirtyq     *dq);

struct silofs_pview * //
silofs_pni_pview(const struct silofs_pnode_info *pni);

struct silofs_pview * //
silofs_pni_pviewx(const struct silofs_pnode_info *pni);

enum silofs_ptype     //
silofs_pni_ptype(const struct silofs_pnode_info *pni);

const struct silofs_paddr *
silofs_pni_paddr(const struct silofs_pnode_info *pni);

const struct silofs_blobid *
silofs_pni_blobid(const struct silofs_pnode_info *pni);

const struct silofs_layerid *
silofs_pni_layerid(const struct silofs_pnode_info *pni);

const struct silofs_nmeta *
silofs_pni_nmeta(const struct silofs_pnode_info *pni);

const struct silofs_civkey *
silofs_pni_civkey(const struct silofs_pnode_info *pni);

struct silofs_pnode_info *
silofs_pni_from_dqe(const struct silofs_dq_elem *dqe);

struct silofs_pnode_info *       //
silofs_pni_from_mut_ni(struct silofs_node_info *ni);

const struct silofs_pnode_info * //
silofs_pni_from_ni(const struct silofs_node_info *ni);

void silofs_pni_update_ctag(struct silofs_pnode_info *pni,
                            const struct silofs_ctag *ctag);

void silofs_pni_apply_ctag(struct silofs_pnode_info *pni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_uber_info *
silofs_ubi_from_pni(const struct silofs_pnode_info *pni);

struct silofs_bldesc_info *
silofs_bdi_from_pni(const struct silofs_pnode_info *pni);

struct silofs_btnode_info *
silofs_bti_from_pni(const struct silofs_pnode_info *pni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_pnode_info *silofs_new_pnode(const struct silofs_pnptr *pnptr, //
                                           struct silofs_alloc       *alloc);

void silofs_del_pnode(struct silofs_pnode_info *pni,
                      struct silofs_alloc      *alloc);

int silofs_verify_pnode(const struct silofs_pnode_info *pni);

void silofs_seal_pnode(const struct silofs_pnode_info *pni);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* pcache */

struct silofs_pcache {
	struct silofs_hmapq  pc_hmapq;
	struct silofs_dirtyq pc_dirtyq;
	struct silofs_alloc *pc_alloc;
};

int silofs_pcache_init(struct silofs_pcache *pcache,
                       struct silofs_alloc  *alloc);

void silofs_pcache_fini(struct silofs_pcache *pcache);

bool silofs_pcache_isempty(const struct silofs_pcache *pcache);

void silofs_pcache_drop(struct silofs_pcache *pcache);

void silofs_pcache_relax(struct silofs_pcache *pcache, int flags);

struct silofs_pnode_info *
silofs_pcache_dq_front(const struct silofs_pcache *pcache);

struct silofs_pnode_info *
silofs_pcache_create_pnode(struct silofs_pcache      *pcache,
                           const struct silofs_pnptr *pnptr);

struct silofs_pnode_info *
silofs_pcache_lookup_pnode(struct silofs_pcache      *pcache,
                           const struct silofs_paddr *paddr);

void silofs_pcache_delete_pnode(struct silofs_pcache     *pcache,
                                struct silofs_pnode_info *pni);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* vnodes */

enum silofs_lnflags {
	SILOFS_LNF_RECHECK = SILOFS_BIT(0),
	SILOFS_LNF_PINNED  = SILOFS_BIT(1),
	SILOFS_LNF_ACTIVE  = SILOFS_BIT(2),
	SILOFS_LNF_LOOSE   = SILOFS_BIT(3),
};

/* lnode: base object of all logical-nodes */
struct silofs_lnode_info {
	struct silofs_node_info   ln_base;
	struct silofs_avl_node    ln_ds_avl_node;
	struct silofs_lnode_info *ln_ds_next;
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
	struct silofs_paddr      vn_curr_paddr;
	struct silofs_llink      vn_llink;
	uint64_t                 vn_magic;
	int                      vn_asyncwr;
	bool                     vn_has_pn;

	bool (*isevictable_fn)(const struct silofs_vnode_info *vni);
};

/* space allocation node */
struct silofs_space_info {
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

struct silofs_lview *silofs_lni_lview(const struct silofs_lnode_info *lni);

size_t silofs_lni_refcnt(const struct silofs_lnode_info *lni);

void silofs_lni_incref(struct silofs_lnode_info *lni);

void silofs_lni_decref(struct silofs_lnode_info *lni);

void silofs_lni_markdirty(struct silofs_lnode_info *lni);

void silofs_lni_cleardirty(struct silofs_lnode_info *lni);

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

struct silofs_lview *silofs_uni_lview(const struct silofs_unode_info *uni);

void silofs_uni_incref(struct silofs_unode_info *uni);

void silofs_uni_decref(struct silofs_unode_info *uni);

void silofs_uni_markdirty(struct silofs_unode_info *uni);

void silofs_uni_cleardirty(struct silofs_unode_info *uni);

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

struct silofs_lview * //
silofs_vni_lview(const struct silofs_vnode_info *vni);

struct silofs_lview * //
silofs_vni_lviewx(const struct silofs_vnode_info *vni);

size_t silofs_vni_refcnt(const struct silofs_vnode_info *vni);

void silofs_vni_incref(struct silofs_vnode_info *vni);

void silofs_vni_decref(struct silofs_vnode_info *vni);

bool silofs_vni_isdirty(const struct silofs_vnode_info *vni);

void silofs_vni_markdirty(struct silofs_vnode_info *vni,
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
                      struct silofs_alloc      *alloc);

struct silofs_vnode_info *
silofs_new_vnode(struct silofs_alloc *alloc, const struct silofs_vaddr *vaddr);

void silofs_del_vnode(struct silofs_vnode_info *vni,
                      struct silofs_alloc      *alloc);

void silofs_seal_vnode(const struct silofs_vnode_info *vni);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* vcache */

/* in-memory caching */
struct silofs_vcache {
	struct silofs_alloc *vc_alloc;
	struct silofs_hmapq  vc_vni_hmapq;
	struct silofs_dirtyq vc_iis_dq;
	struct silofs_dirtyq vc_vnis_dq;
	struct silofs_dirtyq vc_pn_vnis_dq;
};

int silofs_vcache_init(struct silofs_vcache *vcache,
                       struct silofs_alloc  *alloc);

void silofs_vcache_fini(struct silofs_vcache *vcache);

size_t silofs_vcache_relax(struct silofs_vcache *vcache, int flags);

void silofs_vcache_drop(struct silofs_vcache *vcache);

struct silofs_vnode_info *
silofs_vcache_dq_front(const struct silofs_vcache *vcache);

struct silofs_vnode_info *
silofs_vcache_lookup_vnode(struct silofs_vcache      *vcache,
                           const struct silofs_vaddr *vaddr);

struct silofs_vnode_info *
silofs_vcache_create_vnode(struct silofs_vcache      *vcache,
                           const struct silofs_vaddr *vaddr);

void silofs_vcache_forget_vnode(struct silofs_vcache     *vcache,
                                struct silofs_vnode_info *vni);

void silofs_vcache_rebind_vnode(struct silofs_vcache     *vcache,
                                struct silofs_vnode_info *vni);

void silofs_vcache_collect_stats(const struct silofs_vcache *vcache,
                                 struct silofs_cache_stats  *out_cstats);

#endif /* SILOFS_CACHE_H_ */
