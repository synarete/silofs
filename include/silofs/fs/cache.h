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
#ifndef SILOFS_CACHE_H_
#define SILOFS_CACHE_H_

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
	struct silofs_mdigest   c_mdigest;
	struct silofs_alloc    *c_alloc;
	struct silofs_block    *c_nil_bk;
	struct silofs_lrumap    c_bri_lm;
	struct silofs_lrumap    c_ubki_lm;
	struct silofs_lrumap    c_vbki_lm;
	struct silofs_lrumap    c_ui_lm;
	struct silofs_lrumap    c_vi_lm;
	struct silofs_dirtyq    c_dq;
	struct silofs_spamaps   c_spam;
	struct silofs_uamap     c_uam;
	size_t mem_size_hint;
};


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

long silofs_ckey_compare(const struct silofs_ckey *ckey1,
                         const struct silofs_ckey *ckey2);

void silofs_ckey_by_blobid(struct silofs_ckey *ckey,
                           const struct silofs_blobid *blobid);

void silofs_ce_init(struct silofs_cache_elem *ce);

void silofs_ce_fini(struct silofs_cache_elem *ce);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_cache_init(struct silofs_cache *cache,
                      struct silofs_alloc *alloc, size_t msz_hint);

void silofs_cache_fini(struct silofs_cache *cache);

void silofs_cache_relax(struct silofs_cache *cache, int flags);

void silofs_cache_drop(struct silofs_cache *cache);

void silofs_cache_shrink_once(struct silofs_cache *cache);

bool silofs_cache_need_flush(const struct silofs_cache *cache, int flags);

void silofs_cache_fill_into_dset(const struct silofs_cache *cache,
                                 struct silofs_dset *dset);

void silofs_cache_undirtify_by_dset(struct silofs_cache *cache,
                                    const struct silofs_dset *dset);


struct silofs_blobref_info *
silofs_cache_lookup_blob(struct silofs_cache *cache,
                         const struct silofs_blobid *blobid);

struct silofs_blobref_info *
silofs_cache_spawn_blob(struct silofs_cache *cache,
                        const struct silofs_blobid *blobid);

void silofs_cache_evict_blob(struct silofs_cache *cache,
                             struct silofs_blobref_info *bri);

void silofs_cache_relax_blobs(struct silofs_cache *cache);


struct silofs_ubk_info *
silofs_cache_lookup_ubk(struct silofs_cache *cache,
                        const struct silofs_bkaddr *bkaddr);

struct silofs_ubk_info *
silofs_cache_spawn_ubk(struct silofs_cache *cache,
                       const struct silofs_bkaddr *bkaddr);

void silofs_cache_forget_ubk(struct silofs_cache *cache,
                             struct silofs_ubk_info *ubki);


struct silofs_unode_info *
silofs_cache_spawn_unode(struct silofs_cache *cache,
                         const struct silofs_uaddr *uaddr);

void silofs_cache_forget_unode(struct silofs_cache *cache,
                               struct silofs_unode_info *ui);

struct silofs_unode_info *
silofs_cache_lookup_unode(struct silofs_cache *cache,
                          const struct silofs_uaddr *uaddr);

struct silofs_unode_info *
silofs_cache_find_unode_by(struct silofs_cache *cache,
                           const struct silofs_uakey *uakey);

void silofs_cache_forget_uaddrs(struct silofs_cache *cache);


struct silofs_vbk_info *
silofs_cache_lookup_vbk(struct silofs_cache *cache,
                        loff_t voff, enum silofs_stype vspace);

struct silofs_vbk_info *
silofs_cache_spawn_vbk(struct silofs_cache *cache,
                       loff_t voff, enum silofs_stype vspace);

void silofs_cache_forget_vbk(struct silofs_cache *cache,
                             struct silofs_vbk_info *vbki);


struct silofs_vnode_info *
silofs_cache_lookup_vnode(struct silofs_cache *cache,
                          const struct silofs_vaddr *vaddr);

struct silofs_vnode_info *
silofs_cache_spawn_vnode(struct silofs_cache *cache,
                         const struct silofs_vaddr *vaddr);

void silofs_cache_forget_vnode(struct silofs_cache *cache,
                               struct silofs_vnode_info *vi);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_bri_datasync(const struct silofs_blobref_info *bri);

void silofs_bri_incref(struct silofs_blobref_info *bri);

void silofs_bri_decref(struct silofs_blobref_info *bri);


void silofs_vi_dirtify(struct silofs_vnode_info *vi);

void silofs_vi_undirtify(struct silofs_vnode_info *vi);

void silofs_vi_incref(struct silofs_vnode_info *vi);

void silofs_vi_decref(struct silofs_vnode_info *vi);

void silofs_vi_attach_to(struct silofs_vnode_info *vi,
                         struct silofs_vbk_info *vbki);


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

void silofs_ui_attach_to(struct silofs_unode_info *ui,
                         struct silofs_ubk_info *ubki);


bool silofs_si_isevictable(const struct silofs_snode_info *si);

void silofs_sbi_incref(struct silofs_sb_info *sbi);

void silofs_sbi_decref(struct silofs_sb_info *sbi);

void silofs_vbki_incref(struct silofs_vbk_info *vbki);

void silofs_vbki_decref(struct silofs_vbk_info *vbki);


void silofs_ubki_attach(struct silofs_ubk_info *ubki,
                        struct silofs_blobref_info *bri);

#endif /* SILOFS_CACHE_H_ */
