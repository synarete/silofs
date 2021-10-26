/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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
#ifndef SILOFS_CACHE_H_
#define SILOFS_CACHE_H_

#include <stdlib.h>
#include <silofs/fs/types.h>
#include <silofs/fs/spxmap.h>

/* LRU + hash-map */
struct silofs_lrumap {
	struct silofs_listq      lm_lru;
	struct silofs_list_head *lm_htbl;
	size_t lm_htbl_cap;
	size_t lm_htbl_sz;
};

/* dirty-queue of cached-elements */
struct silofs_dirtyq {
	struct silofs_listq     dq_list;
	size_t dq_accum_nbytes;
};

/* in-memory caching */
struct silofs_cache {
	struct silofs_qalloc   *c_qalloc;
	struct silofs_alloc_if *c_alif;
	struct silofs_block    *c_nil_bk;
	struct silofs_lrumap    c_bli_lm;
	struct silofs_lrumap    c_ubi_lm;
	struct silofs_lrumap    c_vbi_lm;
	struct silofs_lrumap    c_ui_lm;
	struct silofs_lrumap    c_vi_lm;
	struct silofs_dirtyq    c_dq;
	struct silofs_spvmap    c_spvm;
	struct silofs_sptmap    c_sptm;
};


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

long silofs_ckey_compare(const struct silofs_ckey *ckey1,
                         const struct silofs_ckey *ckey2);

void silofs_ckey_by_blobid(struct silofs_ckey *ckey,
                           const struct silofs_blobid *bid);

void silofs_ce_init(struct silofs_cache_elem *ce);

void silofs_ce_fini(struct silofs_cache_elem *ce);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_cache_init(struct silofs_cache *cache,
                      struct silofs_qalloc *qalloc,
                      struct silofs_alloc_if *alif);

void silofs_cache_fini(struct silofs_cache *cache);

void silofs_cache_relax(struct silofs_cache *cache, int flags);

void silofs_cache_drop(struct silofs_cache *cache);

void silofs_cache_shrink_once(struct silofs_cache *cache);

bool silofs_cache_need_flush(const struct silofs_cache *cache, int flags);

void silofs_cache_fill_into_dset(const struct silofs_cache *cache,
                                 struct silofs_dset *dset);

void silofs_cache_undirtify_by_dset(struct silofs_cache *cache,
                                    const struct silofs_dset *dset);


struct silofs_blob_info *
silofs_cache_lookup_blob(struct silofs_cache *cache,
                         const struct silofs_blobid *bid);

struct silofs_blob_info *
silofs_cache_spawn_blob(struct silofs_cache *cache,
                        const struct silofs_blobid *bid);

void silofs_cache_evict_blob(struct silofs_cache *cache,
                             struct silofs_blob_info *bli);

void silofs_cache_relax_blobs(struct silofs_cache *cache);


struct silofs_ubk_info *
silofs_cache_lookup_ubk(struct silofs_cache *cache,
                        const struct silofs_oaddr *oaddr);

struct silofs_ubk_info *
silofs_cache_spawn_ubk(struct silofs_cache *cache,
                       const struct silofs_oaddr *oaddr);

void silofs_cache_forget_ubk(struct silofs_cache *cache,
                             struct silofs_ubk_info *ubi);


struct silofs_unode_info *
silofs_cache_spawn_unode(struct silofs_cache *cache,
                         const struct silofs_uaddr *uaddr);

void silofs_cache_forget_unode(struct silofs_cache *cache,
                               struct silofs_unode_info *ui);

struct silofs_unode_info *
silofs_cache_lookup_unode(struct silofs_cache *cache,
                          const struct silofs_uaddr *uaddr);

struct silofs_unode_info *
silofs_cache_find_unode_by(const struct silofs_cache *cache,
                           const struct silofs_taddr *taddr);


struct silofs_vbk_info *
silofs_cache_lookup_vbk(struct silofs_cache *cache, loff_t voff);

struct silofs_vbk_info *
silofs_cache_spawn_vbk(struct silofs_cache *cache, loff_t voff);

void silofs_cache_forget_vbk(struct silofs_cache *cache,
                             struct silofs_vbk_info *vbi);


struct silofs_vnode_info *
silofs_cache_lookup_vnode(struct silofs_cache *cache,
                          const struct silofs_vaddr *vaddr);

struct silofs_vnode_info *
silofs_cache_spawn_vnode(struct silofs_cache *cache,
                         const struct silofs_vaddr *vaddr);

void silofs_cache_forget_vnode(struct silofs_cache *cache,
                               struct silofs_vnode_info *vi);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bli_resolve(struct silofs_blob_info *bli,
                       const struct silofs_oaddr *oaddr,
                       struct silofs_fiovec *fiov);

int silofs_bli_resolve_bk(struct silofs_blob_info *bli,
                          const struct silofs_oaddr *oaddr,
                          struct silofs_fiovec *fiov);

int silofs_bli_datasync(const struct silofs_blob_info *bli);

void silofs_bli_incref(struct silofs_blob_info *bli);

void silofs_bli_decref(struct silofs_blob_info *bli);


void silofs_vi_dirtify(struct silofs_vnode_info *vi);

void silofs_vi_undirtify(struct silofs_vnode_info *vi);

void silofs_vi_incref(struct silofs_vnode_info *vi);

void silofs_vi_decref(struct silofs_vnode_info *vi);

void silofs_vi_attach_bk(struct silofs_vnode_info *vi,
                         struct silofs_vbk_info *vbi);

size_t silofs_vi_refcnt(const struct silofs_vnode_info *vi);

size_t silofs_ii_refcnt(const struct silofs_inode_info *ii);

void silofs_ii_incref(struct silofs_inode_info *ii);

void silofs_ii_decref(struct silofs_inode_info *ii);

void silofs_ii_dirtify(struct silofs_inode_info *ii);

void silofs_ii_undirtify(struct silofs_inode_info *ii);


void silofs_ui_incref(struct silofs_unode_info *ui);

void silofs_ui_decref(struct silofs_unode_info *ui);

void silofs_ui_dirtify(struct silofs_unode_info *ui);

void silofs_ui_undirtify(struct silofs_unode_info *ui);

void silofs_ui_attach_bk(struct silofs_unode_info *ui,
                         struct silofs_ubk_info *ubi);

bool silofs_ti_isevictable(const struct silofs_tnode_info *ti);

void silofs_ti_bind_hyper(struct silofs_tnode_info *ti,
                          struct silofs_fs_apex *apex);

void silofs_sbi_incref(struct silofs_sb_info *sbi);

void silofs_sbi_decref(struct silofs_sb_info *sbi);


#endif /* SILOFS_CACHE_H_ */
