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
#include <silofs/configs.h>
#include <silofs/fs/address.h>
#include <silofs/fs/spxmap.h>
#include <silofs/fs/cache.h>
#include <silofs/fs/boot.h>
#include <silofs/fs/repo.h>
#include <silofs/fs/private.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

#define CACHE_RETRY 2


static void cache_evict_some(struct silofs_cache *cache);
static void cache_dirtify_ui(struct silofs_cache *cache,
                             struct silofs_unode_info *ui);
static void cache_undirtify_ui(struct silofs_cache *cache,
                               struct silofs_unode_info *ui);

typedef int (*silofs_cache_elem_fn)(struct silofs_cache_elem *, void *);

struct silofs_cache_ctx {
	struct silofs_cache      *cache;
	struct silofs_blob_info  *bli;
	struct silofs_ubk_info    *ubi;
	struct silofs_vbk_info   *vbi;
	struct silofs_tnode_info *ti;
	struct silofs_unode_info *ui;
	struct silofs_vnode_info *vi;
	size_t limit;
	size_t count;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* prime-value for hash-table of n-elements */
static const unsigned int silofs_primes[] = {
	13, 53, 97, 193, 389, 769, 1543, 3079, 6151, 12289, 24593, 49157,
	98317, 147377, 196613, 294979, 393241, 589933, 786433, 1572869,
	3145739, 6291469, 12582917, 25165843, 50331653, 100663319, 201326611,
	402653189, 805306457, 1610612741, 3221225473, 4294967291
};

static size_t htbl_prime_size(size_t lim)
{
	size_t p = 11;

	for (size_t i = 0; i < ARRAY_SIZE(silofs_primes); ++i) {
		if (silofs_primes[i] > lim) {
			break;
		}
		p = silofs_primes[i];
	}
	return p;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t twang_mix64(uint64_t key)
{
	key = ~key + (key << 21);
	key = key ^ (key >> 24);
	key = key + (key << 3) + (key << 8);
	key = key ^ (key >> 14);
	key = key + (key << 2) + (key << 4);
	key = key ^ (key >> 28);
	key = key + (key << 31);

	return key;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_block *bk_malloc(struct silofs_alloc_if *alif)
{
	struct silofs_block *bk;

	bk = silofs_allocate(alif, sizeof(*bk));
	return bk;
}

static void bk_free(struct silofs_block *bk, struct silofs_alloc_if *alif)
{
	silofs_deallocate(alif, bk, sizeof(*bk));
}

static struct silofs_ubk_info *ubi_malloc(struct silofs_alloc_if *alif)
{
	struct silofs_ubk_info *ubi;

	ubi = silofs_allocate(alif, sizeof(*ubi));
	return ubi;
}

static void ubi_free(struct silofs_ubk_info *ubi,
                     struct silofs_alloc_if *alif)
{
	silofs_deallocate(alif, ubi, sizeof(*ubi));
}

static struct silofs_vbk_info *vbi_malloc(struct silofs_alloc_if *alif)
{
	struct silofs_vbk_info *vbi;

	vbi = silofs_allocate(alif, sizeof(*vbi));
	return vbi;
}

static void vbi_free(struct silofs_vbk_info *vbi,
                     struct silofs_alloc_if *alif)
{
	silofs_deallocate(alif, vbi, sizeof(*vbi));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t hash_of_blobid(const struct silofs_blobid *bid)
{
	return silofs_blobid_hkey(bid);
}

static uint64_t hash_of_vaddr(const struct silofs_vaddr *vaddr)
{
	const uint64_t h = twang_mix64((uint64_t)vaddr->voff);

	return silofs_rotate64(h, vaddr->stype % 59) ^ vaddr->len;
}

static uint64_t hash_of_oaddr(const struct silofs_oaddr *oaddr)
{
	return  hash_of_blobid(&oaddr->bid) ^
	        (((uint64_t)(oaddr->pos) << 17) + oaddr->len);
}

static uint64_t hash_of_uaddr(const struct silofs_uaddr *uaddr)
{
	const uint64_t voff = (uint64_t)uaddr->voff;
	const uint64_t stype = (uint64_t)(uaddr->stype);
	const uint64_t ohash = hash_of_oaddr(&uaddr->oaddr);

	return ohash ^ stype ^ voff;
}

static uint64_t hash_of_voff(const loff_t *voff)
{
	const uint64_t uoff = (uint64_t)(*voff);

	return ~twang_mix64(~uoff);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ckey_setup(struct silofs_ckey *ckey,
                       enum silofs_ckey_type type,
                       const void *key, unsigned long hash)
{
	ckey->keyu.key = key;
	ckey->hash = hash;
	ckey->type = type;
}

static void ckey_reset(struct silofs_ckey *ckey)
{
	ckey->keyu.key = NULL;
	ckey->hash = 0;
	ckey->type = SILOFS_CKEY_NONE;
}

static long ckey_compare_as_oaddr(const struct silofs_ckey *ckey1,
                                  const struct silofs_ckey *ckey2)
{
	return silofs_oaddr_compare(ckey1->keyu.oaddr, ckey2->keyu.oaddr);
}

static long ckey_compare_as_uaddr(const struct silofs_ckey *ckey1,
                                  const struct silofs_ckey *ckey2)
{
	return silofs_uaddr_compare(ckey1->keyu.uaddr, ckey2->keyu.uaddr);
}

static long ckey_compare_as_vaddr(const struct silofs_ckey *ckey1,
                                  const struct silofs_ckey *ckey2)
{
	return silofs_vaddr_compare(ckey1->keyu.vaddr, ckey2->keyu.vaddr);
}

static long ckey_compare_as_blobid(const struct silofs_ckey *ckey1,
                                   const struct silofs_ckey *ckey2)
{
	return silofs_blobid_compare(ckey1->keyu.bid, ckey2->keyu.bid);
}

static long ckey_compare_as_voff(const struct silofs_ckey *ckey1,
                                 const struct silofs_ckey *ckey2)
{
	const loff_t voff1 = *(ckey1->keyu.voff);
	const loff_t voff2 = *(ckey2->keyu.voff);

	return voff1 - voff2;
}

long silofs_ckey_compare(const struct silofs_ckey *ckey1,
                         const struct silofs_ckey *ckey2)
{
	long cmp;

	cmp = (long)ckey2->type - (long)ckey1->type;
	if (cmp == 0) {
		switch (ckey1->type) {
		case SILOFS_CKEY_OADDR:
			cmp = ckey_compare_as_oaddr(ckey1, ckey2);
			break;
		case SILOFS_CKEY_UADDR:
			cmp = ckey_compare_as_uaddr(ckey1, ckey2);
			break;
		case SILOFS_CKEY_VADDR:
			cmp = ckey_compare_as_vaddr(ckey1, ckey2);
			break;
		case SILOFS_CKEY_BLOBID:
			cmp = ckey_compare_as_blobid(ckey1, ckey2);
			break;
		case SILOFS_CKEY_VOFF:
			cmp = ckey_compare_as_voff(ckey1, ckey2);
			break;
		case SILOFS_CKEY_NONE:
		default:
			break;
		}
	}
	return cmp;
}

static bool ckey_isequal(const struct silofs_ckey *ckey1,
                         const struct silofs_ckey *ckey2)
{
	return (ckey1->type == ckey2->type) &&
	       (ckey1->hash == ckey2->hash) &&
	       !silofs_ckey_compare(ckey1, ckey2);
}

void silofs_ckey_by_blobid(struct silofs_ckey *ckey,
                           const struct silofs_blobid *bid)
{
	ckey_setup(ckey, SILOFS_CKEY_BLOBID, bid, hash_of_blobid(bid));
}

static void ckey_by_oaddr(struct silofs_ckey *ckey,
                          const struct silofs_oaddr *oaddr)
{
	ckey_setup(ckey, SILOFS_CKEY_OADDR, oaddr, hash_of_oaddr(oaddr));
}

static void ckey_by_uaddr(struct silofs_ckey *ckey,
                          const struct silofs_uaddr *uaddr)
{
	ckey_setup(ckey, SILOFS_CKEY_UADDR, uaddr, hash_of_uaddr(uaddr));
}

static void ckey_by_vaddr(struct silofs_ckey *ckey,
                          const struct silofs_vaddr *vaddr)
{
	ckey_setup(ckey, SILOFS_CKEY_VADDR, vaddr, hash_of_vaddr(vaddr));
}

static void ckey_by_voff(struct silofs_ckey *ckey, const loff_t *voff)
{
	ckey_setup(ckey, SILOFS_CKEY_VOFF, voff, hash_of_voff(voff));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_cache_elem *
ce_from_htb_link(const struct silofs_list_head *lh)
{
	const struct silofs_cache_elem *ce;

	ce = container_of2(lh, struct silofs_cache_elem, ce_htb_lh);
	return unconst(ce);
}

static struct silofs_cache_elem *
ce_from_lru_link(const struct silofs_list_head *lh)
{
	const struct silofs_cache_elem *ce;

	ce = container_of2(lh, struct silofs_cache_elem, ce_lru_lh);
	return unconst(ce);
}

void silofs_ce_init(struct silofs_cache_elem *ce)
{
	ckey_reset(&ce->ce_ckey);
	list_head_init(&ce->ce_htb_lh);
	list_head_init(&ce->ce_lru_lh);
	ce->ce_cache = NULL;
	ce->ce_refcnt = 0;
	ce->ce_mapped = false;
	ce->ce_forgot = false;
	ce->ce_dirty = false;
}

void silofs_ce_fini(struct silofs_cache_elem *ce)
{
	ckey_reset(&ce->ce_ckey);
	list_head_fini(&ce->ce_htb_lh);
	list_head_fini(&ce->ce_lru_lh);
	ce->ce_refcnt = 0;
	ce->ce_cache = NULL;
}

static void ce_hmap(struct silofs_cache_elem *ce,
                    struct silofs_list_head *hlst)
{
	silofs_assert(!ce->ce_mapped);

	list_push_front(hlst, &ce->ce_htb_lh);
	ce->ce_mapped = true;
}

static void ce_hunmap(struct silofs_cache_elem *ce)
{
	silofs_assert(ce->ce_mapped);

	list_head_remove(&ce->ce_htb_lh);
	ce->ce_mapped = false;
}

static struct silofs_list_head *ce_lru_link(struct silofs_cache_elem *ce)
{
	return &ce->ce_lru_lh;
}

static void ce_lru(struct silofs_cache_elem *ce, struct silofs_listq *lru)
{
	listq_push_front(lru, ce_lru_link(ce));
}

static void ce_unlru(struct silofs_cache_elem *ce, struct silofs_listq *lru)
{
	listq_remove(lru, ce_lru_link(ce));
}

static bool ce_islru_front(struct silofs_cache_elem *ce,
                           struct silofs_listq *lru)
{
	return (listq_front(lru) == ce_lru_link(ce));
}

static void ce_relru(struct silofs_cache_elem *ce, struct silofs_listq *lru)
{
	if (!ce_islru_front(ce, lru)) {
		ce_unlru(ce, lru);
		ce_lru(ce, lru);
	}
}

static size_t ce_refcnt(const struct silofs_cache_elem *ce)
{
	return (size_t)ce->ce_refcnt;
}

static size_t ce_incref(struct silofs_cache_elem *ce)
{
	silofs_assert_lt(ce->ce_refcnt, INT_MAX / 2);
	silofs_assert_ge(ce->ce_refcnt, 0);
	ce->ce_refcnt++;

	return ce_refcnt(ce);
}

static size_t ce_decref(struct silofs_cache_elem *ce)
{
	silofs_assert_gt(ce->ce_refcnt, 0);
	ce->ce_refcnt--;

	return ce_refcnt(ce);
}

static bool ce_is_evictable(const struct silofs_cache_elem *ce)
{
	return !ce->ce_refcnt && !ce->ce_dirty;
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int lrumap_init(struct silofs_lrumap *lm,
                       struct silofs_alloc_if *alif, size_t cap)
{
	struct silofs_list_head *htbl;

	htbl = silofs_lista_new(alif, cap);
	if (htbl == NULL) {
		return -ENOMEM;
	}
	listq_init(&lm->lm_lru);
	lm->lm_htbl = htbl;
	lm->lm_htbl_cap = cap;
	lm->lm_htbl_sz = 0;
	return 0;
}

static void lrumap_fini(struct silofs_lrumap *lm, struct silofs_alloc_if *alif)
{
	if (lm->lm_htbl != NULL) {
		silofs_lista_del(lm->lm_htbl, lm->lm_htbl_cap, alif);
		listq_fini(&lm->lm_lru);
		lm->lm_htbl = NULL;
		lm->lm_htbl_cap = 0;
	}
}

static size_t lrumap_usage(const struct silofs_lrumap *lm)
{
	return lm->lm_htbl_sz;
}

static size_t lrumap_key_to_bin(const struct silofs_lrumap *lm,
                                const struct silofs_ckey *ckey)
{
	return ckey->hash % lm->lm_htbl_cap;
}

static void lrumap_store(struct silofs_lrumap *lm,
                         struct silofs_cache_elem *ce)
{
	const size_t bin = lrumap_key_to_bin(lm, &ce->ce_ckey);

	ce_hmap(ce, &lm->lm_htbl[bin]);
	ce_lru(ce, &lm->lm_lru);
	lm->lm_htbl_sz += 1;

	silofs_assert_ge(lm->lm_lru.sz, lm->lm_htbl_sz);
}

static struct silofs_cache_elem *
lrumap_find(const struct silofs_lrumap *lm, const struct silofs_ckey *ckey)
{
	size_t bin;
	const struct silofs_list_head *lst;
	const struct silofs_list_head *itr;
	const struct silofs_cache_elem *ce;

	bin = lrumap_key_to_bin(lm, ckey);
	lst = &lm->lm_htbl[bin];
	itr = lst->next;
	while (itr != lst) {
		ce = ce_from_htb_link(itr);
		if (ckey_isequal(&ce->ce_ckey, ckey)) {
			return unconst(ce);
		}
		itr = itr->next;
	}
	return NULL;
}

static void lrumap_unmap(struct silofs_lrumap *lm,
                         struct silofs_cache_elem *ce)
{
	ce_hunmap(ce);
	lm->lm_htbl_sz -= 1;
}

static void lrumap_unlru(struct silofs_lrumap *lm,
                         struct silofs_cache_elem *ce)
{
	ce_unlru(ce, &lm->lm_lru);
}

static void lrumap_remove(struct silofs_lrumap *lm,
                          struct silofs_cache_elem *ce)
{
	lrumap_unmap(lm, ce);
	lrumap_unlru(lm, ce);
}

static void lrumap_promote_lru(struct silofs_lrumap *lm,
                               struct silofs_cache_elem *ce)
{
	ce_relru(ce, &lm->lm_lru);
}

static struct silofs_cache_elem *lrumap_get_lru(const struct silofs_lrumap *lm)
{
	struct silofs_cache_elem *ce = NULL;

	if (lm->lm_lru.sz > 0) {
		ce = ce_from_lru_link(lm->lm_lru.ls.prev);
	}
	return ce;
}

static void lrumap_foreach_backward(struct silofs_lrumap *lm,
                                    silofs_cache_elem_fn cb, void *arg)
{
	int ret = 0;
	size_t count;
	struct silofs_cache_elem *ce;
	struct silofs_listq *lru = &lm->lm_lru;
	struct silofs_list_head *itr = lru->ls.prev;

	count = lru->sz;
	while (!ret && count-- && (itr != &lru->ls)) {
		ce = ce_from_lru_link(itr);
		itr = itr->prev;
		ret = cb(ce, arg);
	}
}

static size_t lrumap_overpop(const struct silofs_lrumap *lm)
{
	size_t ovp;

	if (lm->lm_htbl_sz > lm->lm_htbl_cap) {
		ovp = (lm->lm_htbl_sz - lm->lm_htbl_cap);
	} else if (lm->lm_lru.sz > lm->lm_htbl_sz) {
		ovp = (lm->lm_lru.sz - lm->lm_htbl_sz);
	} else {
		ovp = 0;
	}
	return ovp;
}

static size_t lrumap_calc_search_evictable_max(const struct silofs_lrumap *lm)
{
	return silofs_clamp(lm->lm_htbl_sz / 4, 1, 16);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_blob_info *bli_from_ce(const struct silofs_cache_elem *ce)
{
	const struct silofs_blob_info *bli = NULL;

	if (ce != NULL) {
		bli = container_of2(ce, struct silofs_blob_info, bl_ce);
	}
	return unconst(bli);
}

static struct silofs_cache_elem *bli_to_ce(const struct silofs_blob_info *bli)
{
	const struct silofs_cache_elem *ce = &bli->bl_ce;

	return unconst(ce);
}

static struct silofs_blob_info *bli_malloc(struct silofs_alloc_if *alif)
{
	struct silofs_blob_info *bli;

	bli = silofs_allocate(alif, sizeof(*bli));
	return bli;
}

static void bli_free(struct silofs_blob_info *bli,
                     struct silofs_alloc_if *alif)
{
	silofs_deallocate(alif, bli, sizeof(*bli));
}

static void bli_init(struct silofs_blob_info *bli,
                     const struct silofs_blobid *bid)
{
	silofs_bli_init(bli, bid);
}

static void bli_fini(struct silofs_blob_info *bli)
{
	silofs_bli_fini(bli);
}

static void bli_shut(struct silofs_blob_info *bli)
{
	silofs_bli_shut(bli);
}

void silofs_bli_incref(struct silofs_blob_info *bli)
{
	if (likely(bli != NULL)) {
		ce_incref(bli_to_ce(bli));
	}
}

void silofs_bli_decref(struct silofs_blob_info *bli)
{
	if (likely(bli != NULL)) {
		ce_decref(bli_to_ce(bli));
	}
}

static bool bli_is_evictable(const struct silofs_blob_info *bli)
{
	return ce_is_evictable(bli_to_ce(bli));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_ubk_info *
ubi_from_ce(const struct silofs_cache_elem *ce)
{
	const struct silofs_ubk_info *ubi = NULL;

	if (ce != NULL) {
		ubi = container_of2(ce, struct silofs_ubk_info, ubk_ce);
	}
	return unconst(ubi);
}

static struct silofs_cache_elem *ubi_to_ce(const struct silofs_ubk_info *ubi)
{
	const struct silofs_cache_elem *ce = &ubi->ubk_ce;

	return unconst(ce);
}

static void ubi_set_addr(struct silofs_ubk_info *ubi,
                         const struct silofs_oaddr *oaddr)
{
	struct silofs_cache_elem *ce = ubi_to_ce(ubi);

	silofs_oaddr_assign(&ubi->ubk_oaddr, oaddr);
	ckey_by_oaddr(&ce->ce_ckey, &ubi->ubk_oaddr);
}

static void ubi_init(struct silofs_ubk_info *ubi,
                     struct silofs_block *bk,
                     const struct silofs_oaddr *oaddr)
{
	silofs_ce_init(&ubi->ubk_ce);
	ubi_set_addr(ubi, oaddr);
	ubi->ubk = bk;
}

static void ubi_fini(struct silofs_ubk_info *ubi)
{
	silofs_ce_fini(&ubi->ubk_ce);
	ubi->ubk = NULL;
}

static void ubi_incref(struct silofs_ubk_info *ubi)
{
	ce_incref(ubi_to_ce(ubi));
}

static void ubi_decref(struct silofs_ubk_info *ubi)
{
	ce_decref(ubi_to_ce(ubi));
}

static bool ubi_is_evictable(const struct silofs_ubk_info *ubi)
{
	return ce_is_evictable(ubi_to_ce(ubi));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vbk_info *
vbi_from_ce(const struct silofs_cache_elem *ce)
{
	const struct silofs_vbk_info *vbi = NULL;

	if (ce != NULL) {
		vbi = container_of2(ce, struct silofs_vbk_info, vbk_ce);
	}
	return unconst(vbi);
}

static struct silofs_cache_elem *vbi_to_ce(const struct silofs_vbk_info *vbi)
{
	const struct silofs_cache_elem *ce = &vbi->vbk_ce;

	return unconst(ce);
}

static void vbi_set_voff(struct silofs_vbk_info *vbi, loff_t voff)
{
	struct silofs_cache_elem *ce = vbi_to_ce(vbi);

	vbi->vbk_voff = off_align_to_bk(voff);
	ckey_by_voff(&ce->ce_ckey, &vbi->vbk_voff);
}

static void vbi_init(struct silofs_vbk_info *vbi,
                     struct silofs_block *bk, loff_t voff)
{
	silofs_ce_init(&vbi->vbk_ce);
	vbi_set_voff(vbi, voff);
	vbi->vbk = bk;
}

static void vbi_fini(struct silofs_vbk_info *vbi)
{
	silofs_ce_fini(&vbi->vbk_ce);
	vbi->vbk = NULL;
}

static void vbi_incref(struct silofs_vbk_info *vbi)
{
	ce_incref(vbi_to_ce(vbi));
}

static void vbi_decref(struct silofs_vbk_info *vbi)
{
	ce_decref(vbi_to_ce(vbi));
}

static bool vbi_is_evictable(const struct silofs_vbk_info *vbi)
{
	return ce_is_evictable(vbi_to_ce(vbi));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_tnode_info *ti_from_ce(const struct silofs_cache_elem *ce)
{
	const struct silofs_tnode_info *ti = NULL;

	if (likely(ce != NULL)) {
		ti = container_of2(ce, struct silofs_tnode_info, t_ce);
	}
	return unconst(ti);
}

static struct silofs_cache_elem *ti_to_ce(const struct silofs_tnode_info *ti)
{
	const struct silofs_cache_elem *ce = &ti->t_ce;

	return unconst(ce);
}

static struct silofs_cache *ti_cache(const struct silofs_tnode_info *ti)
{
	return ti->t_apex->ap_cache;
}

static void ti_set_cache(struct silofs_tnode_info *ti,
                         struct silofs_cache *cache)
{
	ti->t_ce.ce_cache = cache;
}

bool silofs_ti_isevictable(const struct silofs_tnode_info *ti)
{
	return ce_is_evictable(ti_to_ce(ti));
}

static size_t ti_incref(struct silofs_tnode_info *ti)
{
	return ce_incref(&ti->t_ce);
}

static size_t ti_decref(struct silofs_tnode_info *ti)
{
	return ce_decref(&ti->t_ce);
}

static void ti_remove_from_lrumap(struct silofs_tnode_info *ti,
                                  struct silofs_lrumap *lm)
{
	struct silofs_cache_elem *ce = ti_to_ce(ti);

	if (ce->ce_mapped) {
		lrumap_remove(lm, ce);
	} else {
		lrumap_unlru(lm, ce);
	}
}

static void ti_delete(struct silofs_tnode_info *ti,
                      struct silofs_alloc_if *alif)
{
	ti->t_vtbl->del(ti, alif);
}

static int visit_evictable_ti(struct silofs_cache_elem *ce, void *arg)
{
	struct silofs_cache_ctx *c_ctx = arg;
	struct silofs_tnode_info *ti = ti_from_ce(ce);

	c_ctx->count++;
	if (ti->t_vtbl->evictable(ti)) {
		c_ctx->ti = ti; /* fount evictable */
		return 1;
	}
	if (c_ctx->count >= c_ctx->limit) {
		return 1; /* not found, stop traversal */
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_cache *ui_cache(const struct silofs_unode_info *ui)
{
	return ti_cache(&ui->u_ti);
}

void silofs_ui_incref(struct silofs_unode_info *ui)
{
	if (likely(ui != NULL)) {
		ti_incref(&ui->u_ti);
	}
}

void silofs_ui_decref(struct silofs_unode_info *ui)
{
	if (likely(ui != NULL)) {
		ti_decref(&ui->u_ti);
	}
}

void silofs_ui_dirtify(struct silofs_unode_info *ui)
{
	cache_dirtify_ui(ui_cache(ui), ui);
}

void silofs_ui_undirtify(struct silofs_unode_info *ui)
{
	cache_undirtify_ui(ui_cache(ui), ui);
}

static struct silofs_unode_info *ui_from_ce(struct silofs_cache_elem *ce)
{
	struct silofs_unode_info *ui = NULL;

	if (ce != NULL) {
		ui = silofs_ui_from_ti(ti_from_ce(ce));
	}
	return ui;
}

static struct silofs_cache_elem *ui_to_ce(struct silofs_unode_info *ui)
{
	return ti_to_ce(&ui->u_ti);
}

void silofs_ui_attach_bk(struct silofs_unode_info *ui,
                         struct silofs_ubk_info *ubi)
{
	ubi_incref(ubi);
	ui->u_ubi = ubi;
}

static void ui_detach_bk(struct silofs_unode_info *ui)
{
	struct silofs_ubk_info *ubi = ui->u_ubi;

	if (ubi != NULL) {
		ubi_decref(ubi);
		ui->u_ubi = NULL;
	}
}

static int visit_evictable_ui(struct silofs_cache_elem *ce, void *arg)
{
	int ret;
	struct silofs_cache_ctx *c_ctx = arg;

	ret = visit_evictable_ti(ce, arg);
	if (ret && (c_ctx->ti != NULL)) {
		c_ctx->ui = silofs_ui_from_ti(c_ctx->ti);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_cache *vi_cache(const struct silofs_vnode_info *vi)
{
	return ti_cache(&vi->v_ti);
}

static struct silofs_vnode_info *vi_from_ce(struct silofs_cache_elem *ce)
{
	struct silofs_vnode_info *vi = NULL;

	if (ce != NULL) {
		vi = silofs_vi_from_ti(ti_from_ce(ce));
	}
	return vi;
}

static struct silofs_cache_elem *vi_to_ce(const struct silofs_vnode_info *vi)
{
	const struct silofs_cache_elem *ce = &vi->v_ti.t_ce;

	return unconst(ce);
}

static int visit_evictable_vi(struct silofs_cache_elem *ce, void *arg)
{
	int ret;
	struct silofs_cache_ctx *c_ctx = arg;

	ret = visit_evictable_ti(ce, arg);
	if (ret && (c_ctx->ti != NULL)) {
		c_ctx->vi = silofs_vi_from_ti(c_ctx->ti);
	}
	return ret;
}

size_t silofs_vi_refcnt(const struct silofs_vnode_info *vi)
{
	size_t refcnt = 0;

	if (likely(vi != NULL)) {
		refcnt = ce_refcnt(vi_to_ce(vi));
	}
	return refcnt;
}

void silofs_vi_incref(struct silofs_vnode_info *vi)
{
	if (likely(vi != NULL)) {
		ce_incref(vi_to_ce(vi));
	}
}

static void vi_decref_fixup(struct silofs_vnode_info *vi)
{
	size_t refcnt_post;
	struct silofs_cache_elem *ce = vi_to_ce(vi);

	refcnt_post = ce_decref(ce);

	/*
	 * Special case where data-node has been unmapped due to forget, yet
	 * it still had a live ref-count due to on-going I/O operation.
	 */
	if (!refcnt_post && ce->ce_forgot) {
		silofs_cache_forget_vnode(vi_cache(vi), vi);
	}
}

void silofs_vi_decref(struct silofs_vnode_info *vi)
{
	if (likely(vi != NULL)) {
		vi_decref_fixup(vi);
	}
}

void silofs_vi_attach_bk(struct silofs_vnode_info *vi,
                         struct silofs_vbk_info *vbi)
{
	vbi_incref(vbi);
	vi->v_vbi = vbi;
}

static void vi_detach_bk(struct silofs_vnode_info *vi)
{
	struct silofs_vbk_info *vbi = vi->v_vbi;

	if (vbi != NULL) {
		vbi_decref(vbi);
		vi->v_vbi = NULL;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void dq_init(struct silofs_dirtyq *dq)
{
	listq_init(&dq->dq_list);
	dq->dq_accum_nbytes = 0;
}

static void dq_fini(struct silofs_dirtyq *dq)
{
	listq_fini(&dq->dq_list);
	dq->dq_accum_nbytes = 0;
}

static void dq_append(struct silofs_dirtyq *dq,
                      struct silofs_list_head *lh, size_t len)
{
	listq_push_back(&dq->dq_list, lh);
	dq->dq_accum_nbytes += len;
}

static void dq_remove(struct silofs_dirtyq *dq,
                      struct silofs_list_head *lh, size_t len)
{
	silofs_assert_ge(dq->dq_accum_nbytes, len);

	listq_remove(&dq->dq_list, lh);
	dq->dq_accum_nbytes -= len;
}

static struct silofs_list_head *dq_front(const struct silofs_dirtyq *dq)
{
	return listq_front(&dq->dq_list);
}

static struct silofs_list_head *
dq_next_of(const struct silofs_dirtyq *dq,
           const struct silofs_list_head *lh)
{
	return listq_next(&dq->dq_list, lh);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_tnode_info *dq_lh_to_ti(struct silofs_list_head *dq_lh)
{
	const struct silofs_tnode_info *ti = NULL;

	if (dq_lh != NULL) {
		ti = container_of(dq_lh, struct silofs_tnode_info, t_dq_lh);
	}
	return unconst(ti);
}

static void cache_dq_enq_ti(struct silofs_cache *cache,
                            struct silofs_tnode_info *ti)
{
	struct silofs_dirtyq *dq = &cache->c_dq;

	if (!ti->t_ce.ce_dirty) {
		dq_append(dq, &ti->t_dq_lh, stype_size(ti->t_stype));
		ti->t_ce.ce_dirty = true;
	}
}

static void cache_dq_dec_ti(struct silofs_cache *cache,
                            struct silofs_tnode_info *ti)
{
	struct silofs_dirtyq *dq = &cache->c_dq;

	if (ti->t_ce.ce_dirty) {
		dq_remove(dq, &ti->t_dq_lh, stype_size(ti->t_stype));
		ti->t_ce.ce_dirty = false;
	}
}

static void cache_dirtify_ti(struct silofs_cache *cache,
                             struct silofs_tnode_info *ti)
{
	cache_dq_enq_ti(cache, ti);
}

static void cache_undirtify_ti(struct silofs_cache *cache,
                               struct silofs_tnode_info *ti)
{
	cache_dq_dec_ti(cache, ti);
}

static struct silofs_tnode_info *
cache_dq_front_ti(const struct silofs_cache *cache)
{
	const struct silofs_dirtyq *dq = &cache->c_dq;

	return dq_lh_to_ti(dq_front(dq));
}

static struct silofs_tnode_info *
cache_dq_next_ti(const struct silofs_cache *cache,
                 const struct silofs_tnode_info *ti)
{
	const struct silofs_dirtyq *dq = &cache->c_dq;

	return dq_lh_to_ti(dq_next_of(dq, &ti->t_dq_lh));
}

static void cache_dirtify_ui(struct silofs_cache *cache,
                             struct silofs_unode_info *ui)
{
	cache_dirtify_ti(cache, &ui->u_ti);
}

static void cache_undirtify_ui(struct silofs_cache *cache,
                               struct silofs_unode_info *ui)
{
	cache_undirtify_ti(cache, &ui->u_ti);
}

static void cache_dirtify_vi(struct silofs_cache *cache,
                             struct silofs_vnode_info *vi)
{
	cache_dirtify_ti(cache, &vi->v_ti);
}

static void cache_undirtify_vi(struct silofs_cache *cache,
                               struct silofs_vnode_info *vi)
{
	cache_undirtify_ti(cache, &vi->v_ti);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_blob_info *
cache_new_bli(const struct silofs_cache *cache,
              const struct silofs_blobid *bid)
{
	struct silofs_blob_info *bli;

	bli = bli_malloc(cache->c_alif);
	if (bli == NULL) {
		return NULL;
	}
	bli_init(bli, bid);
	return bli;
}

static void cache_del_bli(const struct silofs_cache *cache,
                          struct silofs_blob_info *bli)
{
	bli_shut(bli);
	bli_fini(bli);
	bli_free(bli, cache->c_alif);
}

static int cache_init_bli_lm(struct silofs_cache *cache, size_t htbl_size)
{
	return lrumap_init(&cache->c_bli_lm, cache->c_alif, htbl_size);
}

static void cache_fini_bli_lm(struct silofs_cache *cache)
{
	lrumap_fini(&cache->c_bli_lm, cache->c_alif);
}

static struct silofs_blob_info *
cache_find_bli(const struct silofs_cache *cache,
               const struct silofs_blobid *bid)
{
	struct silofs_ckey ckey;
	struct silofs_cache_elem *ce;

	silofs_ckey_by_blobid(&ckey, bid);
	ce = lrumap_find(&cache->c_bli_lm, &ckey);
	return bli_from_ce(ce);
}

static void cache_store_bli(struct silofs_cache *cache,
                            struct silofs_blob_info *bli)
{
	lrumap_store(&cache->c_bli_lm, bli_to_ce(bli));
}

static void cache_promote_lru_bli(struct silofs_cache *cache,
                                  struct silofs_blob_info *bli)
{
	lrumap_promote_lru(&cache->c_bli_lm, bli_to_ce(bli));
}

static void cache_evict_bli(struct silofs_cache *cache,
                            struct silofs_blob_info *bli)
{
	silofs_assert(ce_is_evictable(bli_to_ce(bli)));

	lrumap_remove(&cache->c_bli_lm, bli_to_ce(bli));
	cache_del_bli(cache, bli);
}

static struct silofs_blob_info *
cache_spawn_bli(struct silofs_cache *cache, const struct silofs_blobid *bid)
{
	struct silofs_blob_info *bli;

	bli = cache_new_bli(cache, bid);
	if (bli == NULL) {
		return NULL;
	}
	cache_store_bli(cache, bli);
	return bli;
}

static struct silofs_blob_info *
cache_find_relru_bli(struct silofs_cache *cache,
                     const struct silofs_blobid *bid)
{
	struct silofs_blob_info *bli;

	bli = cache_find_bli(cache, bid);
	if (bli != NULL) {
		cache_promote_lru_bli(cache, bli);
	}
	return bli;
}

struct silofs_blob_info *
silofs_cache_lookup_blob(struct silofs_cache *cache,
                         const struct silofs_blobid *bid)
{
	return cache_find_relru_bli(cache, bid);
}

static struct silofs_blob_info *
cache_find_or_spawn_bli(struct silofs_cache *cache,
                        const struct silofs_blobid *bid)
{
	struct silofs_blob_info *bli;

	bli = cache_find_relru_bli(cache, bid);
	if (bli != NULL) {
		return bli;
	}
	bli = cache_spawn_bli(cache, bid);
	if (bli == NULL) {
		return NULL; /* TODO: debug-trace */
	}
	return bli;
}

static int visit_evictable_bli(struct silofs_cache_elem *ce, void *arg)
{
	struct silofs_cache_ctx *c_ctx = arg;
	struct silofs_blob_info *bli = bli_from_ce(ce);

	c_ctx->count++;
	if (bli_is_evictable(bli)) {
		c_ctx->bli = bli;
		return 1;
	}
	if (c_ctx->count >= c_ctx->limit) {
		return 1;
	}
	return 0;
}

static struct silofs_blob_info *
cache_find_evictable_bli(struct silofs_cache *cache)
{
	struct silofs_cache_ctx c_ctx = {
		.cache = cache,
		.bli = NULL,
		.limit = 4
	};

	lrumap_foreach_backward(&cache->c_bli_lm, visit_evictable_bli, &c_ctx);
	return c_ctx.bli;
}

static struct silofs_blob_info *
cache_require_bli(struct silofs_cache *cache, const struct silofs_blobid *bid)
{
	int retry = CACHE_RETRY;
	struct silofs_blob_info *bli = NULL;

	while (retry-- > 0) {
		bli = cache_find_or_spawn_bli(cache, bid);
		if (bid != NULL) {
			break;
		}
		cache_evict_some(cache);
	}
	return bli;
}

struct silofs_blob_info *
silofs_cache_spawn_blob(struct silofs_cache *cache,
                        const struct silofs_blobid *bid)
{
	return cache_require_bli(cache, bid);
}

void silofs_cache_evict_blob(struct silofs_cache *cache,
                             struct silofs_blob_info *bli)
{
	cache_evict_bli(cache, bli);
}

static struct silofs_blob_info *cache_get_lru_bli(struct silofs_cache *cache)
{
	struct silofs_cache_elem *ce;

	ce = lrumap_get_lru(&cache->c_bli_lm);
	return bli_from_ce(ce);
}

static void cache_try_evict_bli(struct silofs_cache *cache,
                                struct silofs_blob_info *bli)
{
	silofs_assert_not_null(bli);

	if (bli_is_evictable(bli)) {
		cache_evict_bli(cache, bli);
	}
}

static int try_evict_bli(struct silofs_cache_elem *ce, void *arg)
{
	struct silofs_cache_ctx *c_ctx = arg;
	struct silofs_blob_info *bli = bli_from_ce(ce);

	cache_try_evict_bli(c_ctx->cache, bli);
	return 0;
}

static void cache_drop_evictable_blis(struct silofs_cache *cache)
{
	struct silofs_cache_ctx c_ctx = {
		.cache = cache
	};

	lrumap_foreach_backward(&cache->c_bli_lm, try_evict_bli, &c_ctx);
}

static bool cache_evict_or_relru_bli(struct silofs_cache *cache,
                                     struct silofs_blob_info *bli)
{
	bool evicted;

	if (bli_is_evictable(bli)) {
		cache_evict_bli(cache, bli);
		evicted = true;
	} else {
		cache_promote_lru_bli(cache, bli);
		evicted = false;
	}
	return evicted;
}

static size_t
cache_shrink_or_relru_blis(struct silofs_cache *cache, size_t cnt)
{
	bool ok;
	size_t evicted = 0;
	struct silofs_blob_info *bli;
	const size_t n = min(cnt, cache->c_bli_lm.lm_lru.sz);

	for (size_t i = 0; i < n; ++i) {
		bli = cache_get_lru_bli(cache);
		if (bli == NULL) {
			break;
		}
		ok = cache_evict_or_relru_bli(cache, bli);
		if (!ok) {
			break;
		}
		evicted++;
	}
	return evicted;
}

void silofs_cache_relax_blobs(struct silofs_cache *cache)
{
	cache_shrink_or_relru_blis(cache, 1);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_ubk_info *
cache_new_ubi(const struct silofs_cache *cache,
              const struct silofs_oaddr *oaddr)
{
	struct silofs_block *bk;
	struct silofs_ubk_info *ubi;

	bk = bk_malloc(cache->c_alif);
	if (bk == NULL) {
		return NULL;
	}
	ubi = ubi_malloc(cache->c_alif);
	if (ubi == NULL) {
		bk_free(bk, cache->c_alif);
		return NULL;
	}
	ubi_init(ubi, bk, oaddr);
	return ubi;
}

static void cache_del_ubi(const struct silofs_cache *cache,
                          struct silofs_ubk_info *ubi)
{
	struct silofs_block *bk = ubi->ubk;

	ubi_fini(ubi);
	bk_free(bk, cache->c_alif);
	ubi_free(ubi, cache->c_alif);
}

static int cache_init_ubi_lm(struct silofs_cache *cache, size_t htbl_size)
{
	return lrumap_init(&cache->c_ubi_lm, cache->c_alif, htbl_size);
}

static void cache_fini_ubi_lm(struct silofs_cache *cache)
{
	lrumap_fini(&cache->c_ubi_lm, cache->c_alif);
}

static struct silofs_ubk_info *
cache_find_ubi(const struct silofs_cache *cache,
               const struct silofs_oaddr *oaddr)
{
	struct silofs_ckey ckey;
	struct silofs_cache_elem *ce;

	ckey_by_oaddr(&ckey, oaddr);
	ce = lrumap_find(&cache->c_ubi_lm, &ckey);
	return ubi_from_ce(ce);
}

static void cache_store_ubi(struct silofs_cache *cache,
                            struct silofs_ubk_info *ubi)
{
	lrumap_store(&cache->c_ubi_lm, ubi_to_ce(ubi));
}

static void cache_promote_lru_ubi(struct silofs_cache *cache,
                                  struct silofs_ubk_info *ubi)
{
	lrumap_promote_lru(&cache->c_ubi_lm, ubi_to_ce(ubi));
}

static void cache_evict_ubi(struct silofs_cache *cache,
                            struct silofs_ubk_info *ubi)
{
	lrumap_remove(&cache->c_ubi_lm, ubi_to_ce(ubi));
	cache_del_ubi(cache, ubi);
}

void silofs_cache_forget_ubk(struct silofs_cache *cache,
                             struct silofs_ubk_info *ubi)
{
	silofs_assert_eq(ubi->ubk_ce.ce_refcnt, 0);

	cache_evict_ubi(cache, ubi);
}

static struct silofs_ubk_info *
cache_spawn_ubi(struct silofs_cache *cache,
                const struct silofs_oaddr *oaddr)
{
	struct silofs_ubk_info *ubi;

	ubi = cache_new_ubi(cache, oaddr);
	if (ubi == NULL) {
		return NULL;
	}
	cache_store_ubi(cache, ubi);
	return ubi;
}

static struct silofs_ubk_info *
cache_find_relru_ubi(struct silofs_cache *cache,
                     const struct silofs_oaddr *oaddr)
{
	struct silofs_ubk_info *ubi;

	ubi = cache_find_ubi(cache, oaddr);
	if (ubi != NULL) {
		cache_promote_lru_ubi(cache, ubi);
	}
	return ubi;
}

static struct silofs_ubk_info *
cache_find_or_spawn_ubi(struct silofs_cache *cache,
                        const struct silofs_oaddr *oaddr)
{
	struct silofs_ubk_info *ubi;

	ubi = cache_find_relru_ubi(cache, oaddr);
	if (ubi != NULL) {
		return ubi;
	}
	ubi = cache_spawn_ubi(cache, oaddr);
	if (ubi == NULL) {
		return NULL; /* TODO: debug-trace */
	}
	return ubi;
}

static int visit_evictable_ubi(struct silofs_cache_elem *ce, void *arg)
{
	struct silofs_cache_ctx *c_ctx = arg;
	struct silofs_ubk_info *ubi = ubi_from_ce(ce);

	c_ctx->count++;
	if (ubi_is_evictable(ubi)) {
		c_ctx->ubi = ubi;
		return 1;
	}
	if (c_ctx->count >= c_ctx->limit) {
		return 1;
	}
	return 0;
}

static struct silofs_ubk_info *
cache_find_evictable_ubi(struct silofs_cache *cache)
{
	struct silofs_lrumap *lm = &cache->c_ubi_lm;
	struct silofs_cache_ctx c_ctx = {
		.cache = cache,
		.ubi = NULL,
		.limit = lrumap_calc_search_evictable_max(lm)
	};

	lrumap_foreach_backward(lm, visit_evictable_ubi, &c_ctx);
	return c_ctx.ubi;
}

static struct silofs_ubk_info *
cache_require_ubi(struct silofs_cache *cache,
                  const struct silofs_oaddr *oaddr)
{
	int retry = CACHE_RETRY;
	struct silofs_ubk_info *ubi = NULL;

	while (retry-- > 0) {
		ubi = cache_find_or_spawn_ubi(cache, oaddr);
		if (ubi != NULL) {
			break;
		}
		cache_evict_some(cache);
	}
	return ubi;
}

static struct silofs_ubk_info *cache_get_lru_ubi(struct silofs_cache *cache)
{
	struct silofs_cache_elem *ce;

	ce = lrumap_get_lru(&cache->c_ubi_lm);
	return ubi_from_ce(ce);
}

static void cache_try_evict_ubi(struct silofs_cache *cache,
                                struct silofs_ubk_info *ubi)
{
	silofs_assert_not_null(ubi);

	if (ubi_is_evictable(ubi)) {
		cache_evict_ubi(cache, ubi);
	}
}

static int try_evict_ubi(struct silofs_cache_elem *ce, void *arg)
{
	struct silofs_cache_ctx *c_ctx = arg;
	struct silofs_ubk_info *ubi = ubi_from_ce(ce);

	cache_try_evict_ubi(c_ctx->cache, ubi);
	return 0;
}

static void cache_drop_evictable_ubis(struct silofs_cache *cache)
{
	struct silofs_cache_ctx c_ctx = {
		.cache = cache
	};

	lrumap_foreach_backward(&cache->c_ubi_lm, try_evict_ubi, &c_ctx);
}

static bool cache_evict_or_relru_ubi(struct silofs_cache *cache,
                                     struct silofs_ubk_info *ubi)
{
	bool evicted;

	if (ubi_is_evictable(ubi)) {
		cache_evict_ubi(cache, ubi);
		evicted = true;
	} else {
		cache_promote_lru_ubi(cache, ubi);
		evicted = false;
	}
	return evicted;
}

static size_t
cache_shrink_or_relru_ubis(struct silofs_cache *cache, size_t cnt)
{
	bool ok;
	size_t evicted = 0;
	struct silofs_ubk_info *ubi;
	const size_t n = min(cnt, cache->c_ubi_lm.lm_lru.sz);

	for (size_t i = 0; i < n; ++i) {
		ubi = cache_get_lru_ubi(cache);
		if (ubi == NULL) {
			break;
		}
		ok = cache_evict_or_relru_ubi(cache, ubi);
		if (!ok) {
			break;
		}
		evicted++;
	}
	return evicted;
}

struct silofs_ubk_info *
silofs_cache_lookup_ubk(struct silofs_cache *cache,
                        const struct silofs_oaddr *oaddr)
{
	struct silofs_oaddr bk_oaddr;

	silofs_oaddr_of_bk(&bk_oaddr, &oaddr->bid, oaddr_lba(oaddr));
	return cache_find_relru_ubi(cache, &bk_oaddr);
}

struct silofs_ubk_info *
silofs_cache_spawn_ubk(struct silofs_cache *cache,
                       const struct silofs_oaddr *oaddr)
{
	struct silofs_oaddr bk_oaddr;

	silofs_oaddr_of_bk(&bk_oaddr, &oaddr->bid, oaddr_lba(oaddr));
	return cache_require_ubi(cache, &bk_oaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int cache_init_ui_lm(struct silofs_cache *cache, size_t htbl_size)
{
	return lrumap_init(&cache->c_ui_lm, cache->c_alif, htbl_size);
}

static void cache_fini_ui_lm(struct silofs_cache *cache)
{
	lrumap_fini(&cache->c_ui_lm, cache->c_alif);
}

static struct silofs_unode_info *
cache_find_evictable_ui(struct silofs_cache *cache)
{
	struct silofs_lrumap *lm = &cache->c_ui_lm;
	struct silofs_cache_ctx c_ctx = {
		.cache = cache,
		.ui = NULL,
		.limit = lrumap_calc_search_evictable_max(lm)
	};

	lrumap_foreach_backward(lm, visit_evictable_ui, &c_ctx);
	return c_ctx.ui;
}

static struct silofs_unode_info *
cache_find_ui(struct silofs_cache *cache, const struct silofs_uaddr *uaddr)
{
	struct silofs_ckey ckey;
	struct silofs_cache_elem *ce;

	ckey_by_uaddr(&ckey, uaddr);
	ce = lrumap_find(&cache->c_ui_lm, &ckey);
	return ui_from_ce(ce);
}

static void cache_promote_lru_ui(struct silofs_cache *cache,
                                 struct silofs_unode_info *ui)
{
	lrumap_promote_lru(&cache->c_ui_lm, ui_to_ce(ui));
}

static struct silofs_unode_info *
cache_find_relru_ui(struct silofs_cache *cache,
                    const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *ui;

	ui = cache_find_ui(cache, uaddr);
	if (ui != NULL) {
		cache_promote_lru_ui(cache, ui);
	}
	return ui;
}

static void cache_remove_ui(struct silofs_cache *cache,
                            struct silofs_unode_info *ui)
{
	ti_remove_from_lrumap(&ui->u_ti, &cache->c_ui_lm);
}

static void cache_unmap_ui(struct silofs_cache *cache,
                           struct silofs_unode_info *ui)
{
	silofs_sptmap_remove(&cache->c_sptm, ui);
}

static void cache_map_ui(struct silofs_cache *cache,
                         struct silofs_unode_info *ui)
{
	silofs_sptmap_insert(&cache->c_sptm, ui);
}

static void cache_evict_ui(struct silofs_cache *cache,
                           struct silofs_unode_info *ui)
{
	struct silofs_tnode_info *ti = &ui->u_ti;

	cache_unmap_ui(cache, ui);
	cache_remove_ui(cache, ui);
	ui_detach_bk(ui);
	ti_delete(ti, cache->c_alif);
}

static void cache_store_ui_lrumap(struct silofs_cache *cache,
                                  struct silofs_unode_info *ui)
{
	lrumap_store(&cache->c_ui_lm, ui_to_ce(ui));
}

static struct silofs_unode_info *cache_get_lru_ui(struct silofs_cache *cache)
{
	struct silofs_cache_elem *ce;

	ce = lrumap_get_lru(&cache->c_ui_lm);
	return (ce != NULL) ? ui_from_ce(ce) : NULL;
}

static bool cache_evict_or_relru_ui(struct silofs_cache *cache,
                                    struct silofs_unode_info *ui)
{
	bool evicted;
	struct silofs_tnode_info *ti = &ui->u_ti;

	if (ti->t_vtbl->evictable(ti)) {
		cache_evict_ui(cache, ui);
		evicted = true;
	} else {
		cache_promote_lru_ui(cache, ui);
		evicted = false;
	}
	return evicted;
}

static size_t cache_shrink_or_relru_uis(struct silofs_cache *cache, size_t cnt)
{
	bool ok;
	size_t evicted = 0;
	struct silofs_unode_info *ui;
	const size_t n = min(cnt, cache->c_ui_lm.lm_lru.sz);

	for (size_t i = 0; i < n; ++i) {
		ui = cache_get_lru_ui(cache);
		if (ui == NULL) {
			break;
		}
		ok = cache_evict_or_relru_ui(cache, ui);
		if (!ok) {
			break;
		}
		evicted++;
	}
	return evicted;
}

static int try_evict_ui(struct silofs_cache_elem *ce, void *arg)
{
	struct silofs_cache *cache = arg;
	struct silofs_unode_info *ui = ui_from_ce(ce);

	cache_evict_or_relru_ui(cache, ui);
	return 0;
}

static void cache_drop_evictable_uis(struct silofs_cache *cache)
{
	lrumap_foreach_backward(&cache->c_ui_lm, try_evict_ui, cache);
}

static struct silofs_unode_info *
cache_new_ui(const struct silofs_cache *cache,
             const struct silofs_uaddr *uaddr)
{
	return silofs_new_ui(cache->c_alif, uaddr);
}

struct silofs_unode_info *
silofs_cache_lookup_unode(struct silofs_cache *cache,
                          const struct silofs_uaddr *uaddr)
{
	return cache_find_relru_ui(cache, uaddr);
}

static struct silofs_unode_info *
cache_require_ui(struct silofs_cache *cache, const struct silofs_uaddr *uaddr)
{
	int retry = CACHE_RETRY;
	struct silofs_unode_info *ui = NULL;

	while (retry-- > 0) {
		ui = cache_new_ui(cache, uaddr);
		if (ui != NULL) {
			break;
		}
		cache_evict_some(cache);
	}
	return ui;
}

static void cache_store_ui(struct silofs_cache *cache,
                           struct silofs_unode_info *ui)
{
	struct silofs_tnode_info *ti = &ui->u_ti;
	const struct silofs_uaddr *uaddr = ui_uaddr(ui);

	ckey_by_uaddr(&ti->t_ce.ce_ckey, uaddr);
	cache_store_ui_lrumap(cache, ui);
	cache_map_ui(cache, ui);
}

struct silofs_unode_info *
silofs_cache_spawn_unode(struct silofs_cache *cache,
                         const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *ui;

	ui = cache_require_ui(cache, uaddr);
	if (ui != NULL) {
		ti_set_cache(&ui->u_ti, cache);
		cache_store_ui(cache, ui);
	}
	return ui;
}

void silofs_cache_forget_unode(struct silofs_cache *cache,
                               struct silofs_unode_info *ui)
{
	ui_undirtify(ui);
	cache_evict_ui(cache, ui);
}

struct silofs_unode_info *
silofs_cache_find_unode_by(const struct silofs_cache *cache,
                           const struct silofs_taddr *taddr)
{
	return silofs_sptmap_lookup(&cache->c_sptm, taddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vbk_info *
cache_new_vbi(const struct silofs_cache *cache, loff_t voff)
{
	struct silofs_block *bk;
	struct silofs_vbk_info *vbi;

	bk = bk_malloc(cache->c_alif);
	if (bk == NULL) {
		return NULL;
	}
	vbi = vbi_malloc(cache->c_alif);
	if (vbi == NULL) {
		bk_free(bk, cache->c_alif);
		return NULL;
	}
	vbi_init(vbi, bk, voff);
	return vbi;
}

static void cache_del_vbi(const struct silofs_cache *cache,
                          struct silofs_vbk_info *vbi)
{
	struct silofs_block *bk = vbi->vbk;

	vbi_fini(vbi);
	bk_free(bk, cache->c_alif);
	vbi_free(vbi, cache->c_alif);
}

static int cache_init_vbi_lm(struct silofs_cache *cache, size_t htbl_size)
{
	return lrumap_init(&cache->c_vbi_lm, cache->c_alif, htbl_size);
}

static void cache_fini_vbi_lm(struct silofs_cache *cache)
{
	lrumap_fini(&cache->c_vbi_lm, cache->c_alif);
}

static struct silofs_vbk_info *
cache_find_vbi(const struct silofs_cache *cache, loff_t voff)
{
	struct silofs_ckey ckey;
	struct silofs_cache_elem *ce;
	const loff_t bk_voff = off_align_to_bk(voff);

	ckey_by_voff(&ckey, &bk_voff);
	ce = lrumap_find(&cache->c_vbi_lm, &ckey);
	return vbi_from_ce(ce);
}

static void cache_store_vbi(struct silofs_cache *cache,
                            struct silofs_vbk_info *vbi)
{
	lrumap_store(&cache->c_vbi_lm, vbi_to_ce(vbi));
}

static void cache_promote_lru_vbi(struct silofs_cache *cache,
                                  struct silofs_vbk_info *vbi)
{
	lrumap_promote_lru(&cache->c_vbi_lm, vbi_to_ce(vbi));
}

static void cache_evict_vbi(struct silofs_cache *cache,
                            struct silofs_vbk_info *vbi)
{
	lrumap_remove(&cache->c_vbi_lm, vbi_to_ce(vbi));
	cache_del_vbi(cache, vbi);
}

void silofs_cache_forget_vbk(struct silofs_cache *cache,
                             struct silofs_vbk_info *vbi)
{
	cache_evict_vbi(cache, vbi);
}

static struct silofs_vbk_info *
cache_spawn_vbi(struct silofs_cache *cache, loff_t voff)
{
	struct silofs_vbk_info *vbi;

	vbi = cache_new_vbi(cache, voff);
	if (vbi == NULL) {
		return NULL;
	}
	cache_store_vbi(cache, vbi);
	return vbi;
}

static struct silofs_vbk_info *
cache_find_relru_vbi(struct silofs_cache *cache, loff_t voff)
{
	struct silofs_vbk_info *vbi;

	vbi = cache_find_vbi(cache, voff);
	if (vbi != NULL) {
		cache_promote_lru_vbi(cache, vbi);
	}
	return vbi;
}

static struct silofs_vbk_info *
cache_find_or_spawn_vbi(struct silofs_cache *cache, loff_t voff)
{
	struct silofs_vbk_info *vbi;

	vbi = cache_find_relru_vbi(cache, voff);
	if (vbi != NULL) {
		return vbi;
	}
	vbi = cache_spawn_vbi(cache, voff);
	if (vbi == NULL) {
		return NULL; /* TODO: debug-trace */
	}
	return vbi;
}

static int visit_evictable_vbi(struct silofs_cache_elem *ce, void *arg)
{
	struct silofs_cache_ctx *c_ctx = arg;
	struct silofs_vbk_info *vbi = vbi_from_ce(ce);

	c_ctx->count++;
	if (vbi_is_evictable(vbi)) {
		c_ctx->vbi = vbi;
		return 1;
	}
	if (c_ctx->count >= c_ctx->limit) {
		return 1;
	}
	return 0;
}

static struct silofs_vbk_info *
cache_find_evictable_vbi(struct silofs_cache *cache)
{
	struct silofs_lrumap *lm = &cache->c_vbi_lm;
	struct silofs_cache_ctx c_ctx = {
		.cache = cache,
		.ubi = NULL,
		.limit = lrumap_calc_search_evictable_max(lm)
	};

	lrumap_foreach_backward(lm, visit_evictable_vbi, &c_ctx);
	return c_ctx.vbi;
}

static struct silofs_vbk_info *
cache_require_vbi(struct silofs_cache *cache, loff_t voff)
{
	int retry = CACHE_RETRY;
	struct silofs_vbk_info *vbi = NULL;

	while (retry-- > 0) {
		vbi = cache_find_or_spawn_vbi(cache, voff);
		if (vbi != NULL) {
			break;
		}
		cache_evict_some(cache);
	}
	return vbi;
}

static struct silofs_vbk_info *cache_get_lru_vbi(struct silofs_cache *cache)
{
	struct silofs_cache_elem *ce;

	ce = lrumap_get_lru(&cache->c_vbi_lm);
	return vbi_from_ce(ce);
}

static void cache_try_evict_vbi(struct silofs_cache *cache,
                                struct silofs_vbk_info *vbi)
{
	if (vbi_is_evictable(vbi)) {
		cache_evict_vbi(cache, vbi);
	}
}

static int try_evict_vbi(struct silofs_cache_elem *ce, void *arg)
{
	struct silofs_cache_ctx *c_ctx = arg;
	struct silofs_vbk_info *vbi = vbi_from_ce(ce);

	cache_try_evict_vbi(c_ctx->cache, vbi);
	return 0;
}

static void cache_drop_evictable_vbis(struct silofs_cache *cache)
{
	struct silofs_cache_ctx c_ctx = {
		.cache = cache
	};

	lrumap_foreach_backward(&cache->c_vbi_lm, try_evict_vbi, &c_ctx);
}

static bool cache_evict_or_relru_vbi(struct silofs_cache *cache,
                                     struct silofs_vbk_info *vbi)
{
	bool evicted;

	if (vbi_is_evictable(vbi)) {
		cache_evict_vbi(cache, vbi);
		evicted = true;
	} else {
		cache_promote_lru_vbi(cache, vbi);
		evicted = false;
	}
	return evicted;
}

static size_t
cache_shrink_or_relru_vbis(struct silofs_cache *cache, size_t cnt)
{
	bool ok;
	size_t evicted = 0;
	struct silofs_vbk_info *vbi;
	const size_t n = min(cnt, cache->c_vbi_lm.lm_lru.sz);

	for (size_t i = 0; i < n; ++i) {
		vbi = cache_get_lru_vbi(cache);
		if (vbi == NULL) {
			break;
		}
		ok = cache_evict_or_relru_vbi(cache, vbi);
		if (!ok) {
			break;
		}
		evicted++;
	}
	return evicted;
}

struct silofs_vbk_info *
silofs_cache_lookup_vbk(struct silofs_cache *cache, loff_t voff)
{
	return cache_find_relru_vbi(cache, voff);
}

struct silofs_vbk_info *
silofs_cache_spawn_vbk(struct silofs_cache *cache, loff_t voff)
{
	return cache_require_vbi(cache, voff);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int cache_init_vi_lm(struct silofs_cache *cache, size_t htbl_size)
{
	return lrumap_init(&cache->c_vi_lm, cache->c_alif, htbl_size);
}

static void cache_fini_vi_lm(struct silofs_cache *cache)
{
	lrumap_fini(&cache->c_vi_lm, cache->c_alif);
}

static struct silofs_vnode_info *
cache_find_evictable_vi(struct silofs_cache *cache)
{
	struct silofs_lrumap *lm = &cache->c_vi_lm;
	struct silofs_cache_ctx c_ctx = {
		.cache = cache,
		.vi = NULL,
		.limit = lrumap_calc_search_evictable_max(lm)
	};

	lrumap_foreach_backward(lm, visit_evictable_vi, &c_ctx);
	return c_ctx.vi;
}

static struct silofs_vnode_info *
cache_find_vi(struct silofs_cache *cache, const struct silofs_vaddr *vaddr)
{
	struct silofs_ckey ckey;
	struct silofs_cache_elem *ce;

	ckey_by_vaddr(&ckey, vaddr);
	ce = lrumap_find(&cache->c_vi_lm, &ckey);
	return vi_from_ce(ce);
}

static void cache_promote_lru_vi(struct silofs_cache *cache,
                                 struct silofs_vnode_info *vi)
{
	lrumap_promote_lru(&cache->c_vi_lm, vi_to_ce(vi));
}

static struct silofs_vnode_info *
cache_find_relru_vi(struct silofs_cache *cache,
                    const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi;

	vi = cache_find_vi(cache, vaddr);
	if (vi != NULL) {
		cache_promote_lru_vi(cache, vi);
	}
	return vi;
}

static void cache_remove_vi(struct silofs_cache *cache,
                            struct silofs_vnode_info *vi)
{
	ti_remove_from_lrumap(&vi->v_ti, &cache->c_vi_lm);
}

static void cache_evict_vi(struct silofs_cache *cache,
                           struct silofs_vnode_info *vi)
{
	struct silofs_tnode_info *ti = &vi->v_ti;

	cache_remove_vi(cache, vi);
	vi_detach_bk(vi);
	ti_delete(ti, cache->c_alif);
}

static void cache_store_vi_lrumap(struct silofs_cache *cache,
                                  struct silofs_vnode_info *vi)
{
	lrumap_store(&cache->c_vi_lm, vi_to_ce(vi));
}

static void cache_store_vi(struct silofs_cache *cache,
                           struct silofs_vnode_info *vi)
{
	struct silofs_tnode_info *ti = &vi->v_ti;

	ckey_by_vaddr(&ti->t_ce.ce_ckey, &vi->v_vaddr);
	cache_store_vi_lrumap(cache, vi);
}

static struct silofs_vnode_info *cache_get_lru_vi(struct silofs_cache *cache)
{
	struct silofs_cache_elem *ce;

	ce = lrumap_get_lru(&cache->c_vi_lm);
	return (ce != NULL) ? vi_from_ce(ce) : NULL;
}

static bool cache_evict_or_relru_vi(struct silofs_cache *cache,
                                    struct silofs_vnode_info *vi)
{
	struct silofs_tnode_info *ti = &vi->v_ti;
	bool evicted;

	if (ti->t_vtbl->evictable(ti)) {
		cache_evict_vi(cache, vi);
		evicted = true;
	} else {
		cache_promote_lru_vi(cache, vi);
		evicted = false;
	}
	return evicted;
}

static size_t cache_shrink_or_relru_vis(struct silofs_cache *cache, size_t cnt)
{
	bool ok;
	size_t evicted = 0;
	struct silofs_vnode_info *vi;
	const size_t n = min(cnt, cache->c_vi_lm.lm_lru.sz);

	for (size_t i = 0; i < n; ++i) {
		vi = cache_get_lru_vi(cache);
		if (vi == NULL) {
			break;
		}
		ok = cache_evict_or_relru_vi(cache, vi);
		if (!ok) {
			break;
		}
		evicted++;
	}
	return evicted;
}

static int try_evict_vi(struct silofs_cache_elem *ce, void *arg)
{
	struct silofs_cache *cache = arg;
	struct silofs_vnode_info *vi = vi_from_ce(ce);

	cache_evict_or_relru_vi(cache, vi);
	return 0;
}

static void cache_drop_evictable_vis(struct silofs_cache *cache)
{
	lrumap_foreach_backward(&cache->c_vi_lm, try_evict_vi, cache);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vnode_info *
cache_new_vi(const struct silofs_cache *cache,
             const struct silofs_vaddr *vaddr)
{
	return silofs_new_vi(cache->c_alif, vaddr);
}

struct silofs_vnode_info *
silofs_cache_lookup_vnode(struct silofs_cache *cache,
                          const struct silofs_vaddr *vaddr)
{
	return cache_find_relru_vi(cache, vaddr);
}

static struct silofs_vnode_info *
cache_require_vi(struct silofs_cache *cache, const struct silofs_vaddr *vaddr)
{
	int retry = CACHE_RETRY;
	struct silofs_vnode_info *vi = NULL;

	while (retry-- > 0) {
		vi = cache_new_vi(cache, vaddr);
		if (vi != NULL) {
			break;
		}
		cache_evict_some(cache);
	}
	return vi;
}

static void cache_unmap_vi(struct silofs_cache *cache,
                           struct silofs_vnode_info *vi)
{
	if (vi->v_ti.t_ce.ce_mapped) {
		lrumap_unmap(&cache->c_vi_lm, vi_to_ce(vi));
	}
}

void silofs_cache_forget_vnode(struct silofs_cache *cache,
                               struct silofs_vnode_info *vi)
{
	vi_undirtify(vi);
	if (vi_refcnt(vi) > 0) {
		cache_unmap_vi(cache, vi);
		vi->v_ti.t_ce.ce_forgot = true;
	} else {
		cache_evict_vi(cache, vi);
	}
}

struct silofs_vnode_info *
silofs_cache_spawn_vnode(struct silofs_cache *cache,
                         const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi;

	vi = cache_require_vi(cache, vaddr);
	if (vi != NULL) {
		ti_set_cache(&vi->v_ti, cache);
		cache_store_vi(cache, vi);
	}
	return vi;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool cache_shrink_some(struct silofs_cache *cache, size_t factor)
{
	size_t count;
	size_t shrink;
	size_t actual = 0;

	count = lrumap_overpop(&cache->c_vi_lm) + 1;
	shrink = min(count * factor, SILOFS_NKB_IN_BK);
	actual += cache_shrink_or_relru_vis(cache, shrink);

	count = lrumap_overpop(&cache->c_ui_lm) + 1;
	shrink = min(count * factor, 8);
	actual += cache_shrink_or_relru_uis(cache, shrink);

	count = lrumap_overpop(&cache->c_ubi_lm) + 1;
	shrink = min(count * factor, SILOFS_MEGA / SILOFS_BK_SIZE);
	actual += cache_shrink_or_relru_ubis(cache, shrink);

	count = lrumap_overpop(&cache->c_vbi_lm) + 1;
	shrink = min(count * factor, SILOFS_MEGA / SILOFS_BK_SIZE);
	actual += cache_shrink_or_relru_vbis(cache, shrink);

	count = lrumap_overpop(&cache->c_bli_lm) + 1;
	shrink = min(count * factor, 8);
	actual += cache_shrink_or_relru_blis(cache, shrink);

	return (actual > 0);
}

static bool cache_has_overpop(const struct silofs_cache *cache)
{
	const struct silofs_lrumap *lms[] = {
		&cache->c_vi_lm,
		&cache->c_ui_lm,
		&cache->c_ubi_lm,
		&cache->c_vbi_lm,
		&cache->c_bli_lm
	};

	for (size_t i = 0; i < ARRAY_SIZE(lms); ++i) {
		if (lrumap_overpop(lms[i])) {
			return true;
		}
	}
	return false;
}

static uint64_t cache_memory_pressure(const struct silofs_cache *cache)
{
	uint64_t nbits;
	struct silofs_alloc_stat st;

	silofs_allocstat(cache->c_alif, &st);
	nbits = ((61UL * st.npages_used) / st.npages_tota);

	/* returns memory-pressure represented as bit-mask */
	return ((1UL << nbits) - 1);
}

static size_t cache_calc_niter(const struct silofs_cache *cache, int flags)
{
	size_t niter = 0;
	const uint64_t mem_press = cache_memory_pressure(cache);

	if (flags & SILOFS_F_BRINGUP) {
		niter += silofs_popcount64(mem_press >> 3);
	}
	if (flags & SILOFS_F_TIMEOUT) {
		niter += silofs_popcount64(mem_press >> 5);
	}
	if (flags & SILOFS_F_OPSTART) {
		niter += silofs_popcount64(mem_press >> 11);
	}
	if ((flags & SILOFS_F_SLUGGISH) && (mem_press & ~3UL)) {
		niter += 1;
	}
	if ((flags & SILOFS_F_IDLE) && (mem_press & ~1UL)) {
		niter += 2;
	}
	if (cache_has_overpop(cache)) {
		niter += 2;
	}
	return niter;
}

void silofs_cache_relax(struct silofs_cache *cache, int flags)
{
	bool evicted = true;
	const size_t factor = 1;
	const size_t niter = cache_calc_niter(cache, flags);

	for (size_t i = 0; (i < niter) && evicted; ++i) {
		evicted = cache_shrink_some(cache, factor);
	}
}

void silofs_cache_shrink_once(struct silofs_cache *cache)
{
	const size_t bk_size = SILOFS_BK_SIZE;
	const size_t memsz_ubis = bk_size * cache->c_ubi_lm.lm_htbl_sz;
	const size_t memsz_data = cache->c_qalloc->st.memsz_data;

	if ((8 * memsz_ubis) > memsz_data) {
		cache_shrink_some(cache, 1);
	}
}

static size_t cache_lrumap_usage_sum(const struct silofs_cache *cache)
{
	return lrumap_usage(&cache->c_bli_lm) +
	       lrumap_usage(&cache->c_ubi_lm) +
	       lrumap_usage(&cache->c_vbi_lm) +
	       lrumap_usage(&cache->c_vi_lm) +
	       lrumap_usage(&cache->c_ui_lm);
}

static void cache_drop_evictables_once(struct silofs_cache *cache)
{
	cache_drop_evictable_vis(cache);
	cache_drop_evictable_uis(cache);
	cache_drop_evictable_vbis(cache);
	cache_drop_evictable_ubis(cache);
	cache_drop_evictable_blis(cache);
}

static void cache_drop_evictables(struct silofs_cache *cache)
{
	size_t usage_now;
	size_t usage_pre = 0;
	size_t iter_count = 0;

	usage_now = cache_lrumap_usage_sum(cache);
	while ((iter_count++ < 10) && (usage_now != usage_pre)) {
		usage_pre = usage_now;
		cache_drop_evictables_once(cache);
		usage_now = cache_lrumap_usage_sum(cache);
	}
}

static void cache_drop_spcmaps(struct silofs_cache *cache)
{
	silofs_spvmap_drop(&cache->c_spvm);
}

void silofs_cache_drop(struct silofs_cache *cache)
{
	cache_drop_evictables(cache);
	cache_drop_spcmaps(cache);
}

static size_t flush_threshold_of(int flags)
{
	size_t threshold;
	const size_t mega = SILOFS_UMEGA;

	if (flags & SILOFS_F_NOW) {
		threshold = 0;
	} else if (flags & (SILOFS_F_SLUGGISH | SILOFS_F_IDLE)) {
		threshold = mega / 2;
	} else if (flags & SILOFS_F_SYNC) {
		threshold = mega;
	} else {
		threshold = 2 * mega;
	}
	return threshold;
}

static bool cache_dq_need_flush(const struct silofs_cache *cache,
                                const struct silofs_dirtyq *dq, int flags)
{
	const size_t threshold = flush_threshold_of(flags);

	silofs_unused(cache);
	return (dq->dq_accum_nbytes > threshold);
}

static bool cache_mem_press_need_flush(const struct silofs_cache *cache)
{
	const uint64_t mem_press = cache_memory_pressure(cache);

	return silofs_popcount64(mem_press) > 12;
}

bool silofs_cache_need_flush(const struct silofs_cache *cache, int flags)
{
	return cache_dq_need_flush(cache, &cache->c_dq, flags) ||
	       cache_mem_press_need_flush(cache);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool cache_evict_by_bli(struct silofs_cache *cache,
                               struct silofs_blob_info *bli)
{
	bool ret = false;

	if ((bli != NULL) && bli_is_evictable(bli)) {
		cache_evict_bli(cache, bli);
		ret = true;
	}
	return ret;
}

static bool cache_evict_by_ubi(struct silofs_cache *cache,
                               struct silofs_ubk_info *ubi)
{
	bool ret = false;

	if ((ubi != NULL) && ubi_is_evictable(ubi)) {
		cache_evict_ubi(cache, ubi);
		ret = true;
	}
	return ret;
}

static bool cache_evict_by_vbi(struct silofs_cache *cache,
                               struct silofs_vbk_info *vbi)
{
	bool ret = false;

	if ((vbi != NULL) && vbi_is_evictable(vbi)) {
		cache_evict_vbi(cache, vbi);
		ret = true;
	}
	return ret;
}

static bool cache_evict_by_vi(struct silofs_cache *cache,
                              struct silofs_vnode_info *vi)
{
	bool ret = false;
	struct silofs_tnode_info *ti = &vi->v_ti;

	if ((ti != NULL) && (ti->t_vtbl->evictable(ti))) {
		cache_evict_vi(cache, vi);
		ret = true;
	}
	return ret;
}

static bool cache_evict_by_ui(struct silofs_cache *cache,
                              struct silofs_unode_info *ui)
{
	bool ret = false;

	if ((ui != NULL) && (ui->u_ti.t_vtbl->evictable(&ui->u_ti))) {

		cache_evict_ui(cache, ui);
		ret = true;
	}
	return ret;
}

static void cache_evict_some(struct silofs_cache *cache)
{
	bool ok = false;
	struct silofs_vnode_info *vi = NULL;
	struct silofs_unode_info *ui = NULL;
	struct silofs_vbk_info *vbi = NULL;
	struct silofs_ubk_info *ubi = NULL;
	struct silofs_blob_info *bli = NULL;

	vi = cache_find_evictable_vi(cache);
	if (cache_evict_by_vi(cache, vi)) {
		ok = true;
	}
	ui = cache_find_evictable_ui(cache);
	if (cache_evict_by_ui(cache, ui)) {
		ok = true;
	}
	vbi = cache_find_evictable_vbi(cache);
	if (cache_evict_by_vbi(cache, vbi)) {
		ok = true;
	}
	ubi = cache_find_evictable_ubi(cache);
	if (cache_evict_by_ubi(cache, ubi)) {
		ok = true;
	}
	bli = cache_find_evictable_bli(cache);
	if (cache_evict_by_bli(cache, bli)) {
		ok = true;
	}
	if (!ok) {
		cache_shrink_some(cache, 1);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int cache_init_nil_bk(struct silofs_cache *cache)
{
	struct silofs_block *nil_bk;

	nil_bk = silofs_allocate(cache->c_alif, sizeof(*nil_bk));
	if (nil_bk == NULL) {
		return -ENOMEM;
	}
	silofs_memzero(nil_bk, sizeof(*nil_bk));
	cache->c_nil_bk = nil_bk;
	return 0;
}

static void cache_fini_nil_bk(struct silofs_cache *cache)
{
	struct silofs_block *nil_bk = cache->c_nil_bk;

	if (nil_bk != NULL) {
		silofs_deallocate(cache->c_alif, nil_bk, sizeof(*nil_bk));
		cache->c_nil_bk = NULL;
	}
}

static size_t cache_htbl_size(const struct silofs_cache *cache, size_t div)
{
	const struct silofs_qalloc *qal = cache->c_qalloc;
	const size_t hwant = qal->st.memsz_data / div;
	const size_t limit = silofs_clamp(hwant, 1U << 14, 1U << 20);

	return htbl_prime_size(limit);
}

static void cache_fini_lrumaps(struct silofs_cache *cache)
{
	cache_fini_vi_lm(cache);
	cache_fini_ui_lm(cache);
	cache_fini_vbi_lm(cache);
	cache_fini_ubi_lm(cache);
	cache_fini_bli_lm(cache);
}

static int cache_init_lrumaps(struct silofs_cache *cache)
{
	int err;
	size_t hsize;

	hsize = cache_htbl_size(cache, sizeof(struct silofs_block));
	err = cache_init_bli_lm(cache, hsize);
	if (err) {
		goto out_err;
	}
	hsize = cache_htbl_size(cache, sizeof(struct silofs_block));
	err = cache_init_vbi_lm(cache, hsize);
	if (err) {
		goto out_err;
	}
	err = cache_init_ubi_lm(cache, hsize);
	if (err) {
		goto out_err;
	}
	hsize = cache_htbl_size(cache, sizeof(struct silofs_data_block4));
	err = cache_init_vi_lm(cache, hsize);
	if (err) {
		goto out_err;
	}
	hsize = cache_htbl_size(cache, sizeof(struct silofs_block));
	err = cache_init_ui_lm(cache, hsize);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	cache_fini_lrumaps(cache);
	return err;
}

static int cache_init_spvmap(struct silofs_cache *cache)
{
	return silofs_spvmap_init(&cache->c_spvm, cache->c_alif);
}

static void cache_fini_spvmap(struct silofs_cache *cache)
{
	silofs_spvmap_fini(&cache->c_spvm);
}

static int cache_init_sptmap(struct silofs_cache *cache)
{
	return silofs_sptmap_init(&cache->c_sptm, cache->c_alif);
}

static void cache_fini_sptmap(struct silofs_cache *cache)
{
	silofs_sptmap_fini(&cache->c_sptm, cache->c_alif);
}


int silofs_cache_init(struct silofs_cache *cache,
                      struct silofs_qalloc *qalloc,
                      struct silofs_alloc_if *alif)
{
	int err;

	dq_init(&cache->c_dq);
	cache->c_qalloc = qalloc;
	cache->c_alif = alif;
	cache->c_nil_bk = NULL;

	err = cache_init_spvmap(cache);
	if (err) {
		return err;
	}
	err = cache_init_sptmap(cache);
	if (err) {
		return err;
	}
	err = cache_init_nil_bk(cache);
	if (err) {
		goto out_err;
	}
	err = cache_init_lrumaps(cache);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	cache_fini_nil_bk(cache);
	cache_fini_sptmap(cache);
	cache_fini_spvmap(cache);
	return err;
}

void silofs_cache_fini(struct silofs_cache *cache)
{
	dq_fini(&cache->c_dq);
	cache_fini_lrumaps(cache);
	cache_fini_nil_bk(cache);
	cache_fini_sptmap(cache);
	cache_fini_spvmap(cache);
	cache->c_qalloc = NULL;
	cache->c_alif = NULL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_vi_dirtify(struct silofs_vnode_info *vi)
{
	cache_dirtify_vi(vi_cache(vi), vi);
}

void silofs_vi_undirtify(struct silofs_vnode_info *vi)
{
	cache_undirtify_vi(vi_cache(vi), vi);
}

void silofs_ii_dirtify(struct silofs_inode_info *ii)
{
	silofs_vi_dirtify(ii_to_vi(ii));
}

void silofs_ii_undirtify(struct silofs_inode_info *ii)
{
	silofs_vi_undirtify(ii_to_vi(ii));
}

size_t silofs_ii_refcnt(const struct silofs_inode_info *ii)
{
	return silofs_vi_refcnt(ii_to_vi(ii));
}

void silofs_ii_incref(struct silofs_inode_info *ii)
{
	if (likely(ii != NULL)) {
		silofs_vi_incref(ii_to_vi(ii));
	}
}

void silofs_ii_decref(struct silofs_inode_info *ii)
{
	if (likely(ii != NULL)) {
		silofs_vi_decref(ii_to_vi(ii));
	}
}


void silofs_sbi_incref(struct silofs_sb_info *sbi)
{
	ti_incref(&sbi->s_ui.u_ti);
}

void silofs_sbi_decref(struct silofs_sb_info *sbi)
{
	ti_decref(&sbi->s_ui.u_ti);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_cache_fill_into_dset(const struct silofs_cache *cache,
                                 struct silofs_dset *dset)
{
	struct silofs_tnode_info *ti = NULL;

	ti = cache_dq_front_ti(cache);
	while (ti != NULL) {
		dset->ds_add_fn(dset, ti);
		ti = cache_dq_next_ti(cache, ti);
	}
}

void silofs_cache_undirtify_by_dset(struct silofs_cache *cache,
                                    const struct silofs_dset *dset)
{
	struct silofs_tnode_info *next = NULL;
	struct silofs_tnode_info *ti = dset->ds_tiq;

	while (ti != NULL) {
		next = ti->t_ds_next;
		cache_undirtify_ti(cache, ti);
		ti->t_ds_next = NULL;
		ti = next;
	}
}
