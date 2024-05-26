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
#ifndef SILOFS_LCACHE_H_
#define SILOFS_LCACHE_H_


/* dirty-queues of cached-elements by owner */
struct silofs_dirtyqs {
	struct silofs_dirtyq    dq_uis;
	struct silofs_dirtyq    dq_iis;
	struct silofs_dirtyq    dq_vis;
};

/* in-memory caching */
struct silofs_lcache {
	struct silofs_alloc    *lc_alloc;
	struct silofs_lblock   *lc_nil_lbk;
	struct silofs_hmapq     lc_ui_hmapq;
	struct silofs_hmapq     lc_vi_hmapq;
	struct silofs_dirtyqs   lc_dirtyqs;
	struct silofs_spamaps   lc_spamaps;
	struct silofs_uamap     lc_uamap;
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

int silofs_lcache_init(struct silofs_lcache *lcache,
                       struct silofs_alloc *alloc);

void silofs_lcache_fini(struct silofs_lcache *lcache);

void silofs_lcache_relax(struct silofs_lcache *lcache, int flags);

void silofs_lcache_drop(struct silofs_lcache *lcache);


struct silofs_unode_info *
silofs_lcache_lookup_ui(struct silofs_lcache *lcache,
                        const struct silofs_uaddr *uaddr);

struct silofs_unode_info *
silofs_lcache_create_ui(struct silofs_lcache *lcache,
                        const struct silofs_ulink *ulink);

void silofs_lcache_forget_ui(struct silofs_lcache *lcache,
                             struct silofs_unode_info *ui);

struct silofs_unode_info *
silofs_lcache_find_ui_by(struct silofs_lcache *lcache,
                         const struct silofs_uakey *uakey);

void silofs_lcache_drop_uamap(struct silofs_lcache *lcache);


struct silofs_vnode_info *
silofs_lcache_lookup_vi(struct silofs_lcache *lcache,
                        const struct silofs_vaddr *vaddr);

struct silofs_vnode_info *
silofs_lcache_create_vi(struct silofs_lcache *lcache,
                        const struct silofs_vaddr *vaddr);

void silofs_lcache_forget_vi(struct silofs_lcache *lcache,
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

#endif /* SILOFS_LCACHE_H_ */
