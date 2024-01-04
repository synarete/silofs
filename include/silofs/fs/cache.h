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
#ifndef SILOFS_CACHE_H_
#define SILOFS_CACHE_H_


/* dirty-queues of cached-elements by owner */
struct silofs_dirtyqs {
	struct silofs_dirtyq    dq_uis;
	struct silofs_dirtyq    dq_iis;
	struct silofs_dirtyq    dq_vis;
};

/* in-memory caching */
struct silofs_cache {
	struct silofs_alloc    *c_alloc;
	struct silofs_lblock   *c_nil_lbk;
	struct silofs_hmapq     c_ui_hmapq;
	struct silofs_hmapq     c_vi_hmapq;
	struct silofs_dirtyqs   c_dqs;
	struct silofs_spamaps   c_spams;
	struct silofs_uamap     c_uamap;
	size_t                  c_mem_size_hint;
};


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_dirtyq_init(struct silofs_dirtyq *dq);

void silofs_dirtyq_fini(struct silofs_dirtyq *dq);

void silofs_dirtyq_append(struct silofs_dirtyq *dq,
                          struct silofs_list_head *lh, size_t len);

void silofs_dirtyq_remove(struct silofs_dirtyq *dq,
                          struct silofs_list_head *lh, size_t len);

struct silofs_list_head *
silofs_dirtyq_front(const struct silofs_dirtyq *dq);

struct silofs_list_head *
silofs_dirtyq_next_of(const struct silofs_dirtyq *dq,
                      const struct silofs_list_head *lh);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_cache_init(struct silofs_cache *cache,
                      struct silofs_alloc *alloc);

void silofs_cache_fini(struct silofs_cache *cache);

void silofs_cache_relax(struct silofs_cache *cache, int flags);

void silofs_cache_drop(struct silofs_cache *cache);


struct silofs_unode_info *
silofs_cache_lookup_ui(struct silofs_cache *cache,
                       const struct silofs_uaddr *uaddr);

struct silofs_unode_info *
silofs_cache_create_ui(struct silofs_cache *cache,
                       const struct silofs_ulink *ulink);

void silofs_cache_forget_ui(struct silofs_cache *cache,
                            struct silofs_unode_info *ui);

struct silofs_unode_info *
silofs_cache_find_ui_by(struct silofs_cache *cache,
                        const struct silofs_uakey *uakey);

void silofs_cache_drop_uamap(struct silofs_cache *cache);


struct silofs_vbk_info *
silofs_cache_lookup_vbk(struct silofs_cache *cache,
                        loff_t voff, enum silofs_ltype vspace);

struct silofs_vbk_info *
silofs_cache_create_vbk(struct silofs_cache *cache,
                        loff_t voff, enum silofs_ltype vspace);

void silofs_cache_forget_vbk(struct silofs_cache *cache,
                             struct silofs_vbk_info *vbki);


struct silofs_vnode_info *
silofs_cache_lookup_vi(struct silofs_cache *cache,
                       const struct silofs_vaddr *vaddr);

struct silofs_vnode_info *
silofs_cache_create_vi(struct silofs_cache *cache,
                       const struct silofs_vaddr *vaddr);

void silofs_cache_forget_vi(struct silofs_cache *cache,
                            struct silofs_vnode_info *vi);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_vi_dirtify(struct silofs_vnode_info *vi,
                       struct silofs_inode_info *ii);

void silofs_vi_undirtify(struct silofs_vnode_info *vi);

void silofs_vi_incref(struct silofs_vnode_info *vi);

void silofs_vi_decref(struct silofs_vnode_info *vi);


int silofs_vi_refcnt(const struct silofs_vnode_info *vi);

void silofs_ii_incref(struct silofs_inode_info *ii);

void silofs_ii_decref(struct silofs_inode_info *ii);

void silofs_ii_dirtify(struct silofs_inode_info *ii);

void silofs_ii_undirtify(struct silofs_inode_info *ii);

bool silofs_ii_isdirty(const struct silofs_inode_info *ii);

void silofs_ii_set_loose(struct silofs_inode_info *ii);

bool silofs_ii_is_loose(const struct silofs_inode_info *ii);


void silofs_ui_incref(struct silofs_unode_info *ui);

void silofs_ui_decref(struct silofs_unode_info *ui);

void silofs_ui_dirtify(struct silofs_unode_info *ui);

void silofs_ui_undirtify(struct silofs_unode_info *ui);


bool silofs_lni_isevictable(const struct silofs_lnode_info *lni);

void silofs_lni_incref(struct silofs_lnode_info *lni);

void silofs_lni_decref(struct silofs_lnode_info *lni);

#endif /* SILOFS_CACHE_H_ */
