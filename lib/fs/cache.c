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
#include <silofs/infra.h>
#include <silofs/fs/types.h>
#include <silofs/fs/address.h>
#include <silofs/fs/nodes.h>
#include <silofs/fs/spxmap.h>
#include <silofs/fs/crypto.h>
#include <silofs/fs/cache.h>
#include <silofs/fs/boot.h>
#include <silofs/fs/repo.h>
#include <silofs/fs/private.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

#define CACHE_RETRY 2

static void cache_drop_uamap(struct silofs_cache *cache);
static void cache_evict_some(struct silofs_cache *cache);
static void cache_dirtify_ui(struct silofs_cache *cache,
                             struct silofs_unode_info *ui);
static void cache_undirtify_ui(struct silofs_cache *cache,
                               struct silofs_unode_info *ui);

typedef int (*silofs_cache_elem_fn)(struct silofs_cache_elem *, void *);

struct silofs_cache_ctx {
	struct silofs_cache      *cache;
	struct silofs_blob_info  *bli;
	struct silofs_ubk_info   *ubki;
	struct silofs_vbk_info   *vbki;
	struct silofs_snode_info *si;
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

static struct silofs_block *bk_malloc(struct silofs_alloc *alloc)
{
	struct silofs_block *bk;

	bk = silofs_allocate(alloc, sizeof(*bk));
	return bk;
}

static void bk_free(struct silofs_block *bk, struct silofs_alloc *alloc)
{
	silofs_deallocate(alloc, bk, sizeof(*bk));
}

static struct silofs_ubk_info *ubki_malloc(struct silofs_alloc *alloc)
{
	struct silofs_ubk_info *ubki;

	ubki = silofs_allocate(alloc, sizeof(*ubki));
	return ubki;
}

static void ubki_free(struct silofs_ubk_info *ubki,
                      struct silofs_alloc *alloc)
{
	silofs_deallocate(alloc, ubki, sizeof(*ubki));
}

static struct silofs_vbk_info *vbki_malloc(struct silofs_alloc *alloc)
{
	struct silofs_vbk_info *vbki;

	vbki = silofs_allocate(alloc, sizeof(*vbki));
	return vbki;
}

static void vbki_free(struct silofs_vbk_info *vbki,
                      struct silofs_alloc *alloc)
{
	silofs_deallocate(alloc, vbki, sizeof(*vbki));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t hash_of_blobid(const struct silofs_blobid *blobid)
{
	return silofs_blobid_as_u64(blobid);
}

static uint64_t hash_of_vaddr(const struct silofs_vaddr *vaddr)
{
	const uint64_t h = twang_mix64((uint64_t)vaddr->voff);

	return silofs_rotate64(h, vaddr->stype % 59) ^ vaddr->len;
}

static uint64_t hash_of_bkaddr(const struct silofs_bkaddr *bkaddr)
{
	return hash_of_blobid(&bkaddr->blobid) ^ (uint64_t)bkaddr->lba;
}

static uint64_t hash_of_oaddr(const struct silofs_oaddr *oaddr)
{
	const uint64_t pos = (uint64_t)(oaddr->pos);

	return hash_of_bkaddr(&oaddr->bka) ^ ((pos << 17) + oaddr->len);
}

static uint64_t hash_of_uaddr(const struct silofs_uaddr *uaddr)
{
	const uint64_t voff = (uint64_t)uaddr->voff;
	const uint64_t stype = (uint64_t)(uaddr->stype);
	const uint64_t ohash = hash_of_oaddr(&uaddr->oaddr);
	const uint32_t height = (uint32_t)uaddr->height;

	return silofs_rotate64(ohash + stype, height % 7) ^ voff;
}

static uint64_t hash_of_vbk_addr(const struct silofs_vbk_addr *vbk_addr)
{
	const uint64_t uoff = (uint64_t)(vbk_addr->vbk_voff);
	const uint32_t vspc = (uint64_t)vbk_addr->vbk_vspace;

	return ~twang_mix64(uoff + vspc);
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

static long ckey_compare_as_bkaddr(const struct silofs_ckey *ckey1,
                                   const struct silofs_ckey *ckey2)
{
	return silofs_bkaddr_compare(ckey1->keyu.bkaddr, ckey2->keyu.bkaddr);
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
	return silofs_blobid_compare(ckey1->keyu.blobid, ckey2->keyu.blobid);
}

static long ckey_compare_as_vbk_addr(const struct silofs_ckey *ckey1,
                                     const struct silofs_ckey *ckey2)
{
	const struct silofs_vbk_addr *vbk_addr1 = ckey1->keyu.vbk_addr;
	const struct silofs_vbk_addr *vbk_addr2 = ckey2->keyu.vbk_addr;
	long cmp;

	cmp = (long)vbk_addr2->vbk_vspace - (long)vbk_addr1->vbk_vspace;
	if (cmp) {
		return cmp;
	}
	cmp = (long)vbk_addr2->vbk_voff - (long)vbk_addr1->vbk_voff;
	if (cmp) {
		return cmp;
	}
	return 0;
}

long silofs_ckey_compare(const struct silofs_ckey *ckey1,
                         const struct silofs_ckey *ckey2)
{
	long cmp;

	cmp = (long)ckey2->type - (long)ckey1->type;
	if (cmp == 0) {
		switch (ckey1->type) {
		case SILOFS_CKEY_BKADDR:
			cmp = ckey_compare_as_bkaddr(ckey1, ckey2);
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
		case SILOFS_CKEY_VBKADDR:
			cmp = ckey_compare_as_vbk_addr(ckey1, ckey2);
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
                           const struct silofs_blobid *blobid)
{
	ckey_setup(ckey, SILOFS_CKEY_BLOBID, blobid, hash_of_blobid(blobid));
}

static void ckey_by_bkaddr(struct silofs_ckey *ckey,
                           const struct silofs_bkaddr *bkaddr)
{
	ckey_setup(ckey, SILOFS_CKEY_BKADDR, bkaddr, hash_of_bkaddr(bkaddr));
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

static void ckey_by_vbk_addr(struct silofs_ckey *ckey,
                             const struct silofs_vbk_addr *vbk_addr)
{
	ckey_setup(ckey, SILOFS_CKEY_VBKADDR, vbk_addr,
	           hash_of_vbk_addr(vbk_addr));
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
	silofs_assert_ge(ce->ce_refcnt, 0);
	silofs_assert_lt(ce->ce_refcnt, INT_MAX / 2);
	silofs_assert(!ce->ce_mapped);
	silofs_assert(!ce->ce_dirty);

	ckey_reset(&ce->ce_ckey);
	list_head_fini(&ce->ce_htb_lh);
	list_head_fini(&ce->ce_lru_lh);
	ce->ce_refcnt = INT_MIN;
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

static bool ce_need_relru(struct silofs_cache_elem *ce,
                          const struct silofs_listq *lru)
{
	const struct silofs_list_head *lru_front = listq_front(lru);
	const struct silofs_list_head *ce_lru_lnk = ce_lru_link(ce);

	if (unlikely(lru_front == NULL)) {
		return false; /* make clang-scan happy */
	}
	if (lru_front == ce_lru_lnk) {
		return false;
	}
	if (lru_front->next == ce_lru_lnk) {
		return false;
	}
	return true;
}

static void ce_relru(struct silofs_cache_elem *ce, struct silofs_listq *lru)
{
	if (ce_need_relru(ce, lru)) {
		ce_unlru(ce, lru);
		ce_lru(ce, lru);
	}
}

static size_t ce_refcnt(const struct silofs_cache_elem *ce)
{
	/*
	struct silofs_cache_elem *ce2 = unconst(ce);
	int *p_refcnt = (int *)(&ce2->ce_refcnt);
	return (size_t)silofs_atomic_get(p_refcnt);
	*/
	silofs_assert_ge(ce->ce_refcnt, 0);
	return (size_t)ce->ce_refcnt;
}

static void ce_incref(struct silofs_cache_elem *ce)
{
	/* silofs_atomic_add(&ce->ce_refcnt, 1); */
	ce->ce_refcnt++;
}

static void ce_decref(struct silofs_cache_elem *ce)
{
	/* silofs_atomic_sub(&ce->ce_refcnt, 1); */
	ce->ce_refcnt--;
	silofs_assert_ge(ce->ce_refcnt, 0);
}

static bool ce_is_evictable(const struct silofs_cache_elem *ce)
{
	return !ce->ce_dirty && !ce_refcnt(ce);
}

void silofs_ce_incref(struct silofs_cache_elem *ce)
{
	ce_incref(ce);
}

void silofs_ce_decref(struct silofs_cache_elem *ce)
{
	ce_decref(ce);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int lrumap_init(struct silofs_lrumap *lm,
                       struct silofs_alloc *alloc, size_t cap)
{
	struct silofs_list_head *htbl;

	htbl = silofs_lista_new(alloc, cap);
	if (htbl == NULL) {
		return -ENOMEM;
	}
	listq_init(&lm->lm_lru);
	lm->lm_htbl = htbl;
	lm->lm_htbl_cap = cap;
	lm->lm_htbl_sz = 0;
	return 0;
}

static void lrumap_fini(struct silofs_lrumap *lm, struct silofs_alloc *alloc)
{
	if (lm->lm_htbl != NULL) {
		silofs_lista_del(lm->lm_htbl, lm->lm_htbl_cap, alloc);
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
	const struct silofs_list_head *lst;
	const struct silofs_list_head *itr;
	const struct silofs_cache_elem *ce;
	size_t bin;

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
	struct silofs_cache_elem *ce;
	struct silofs_listq *lru = &lm->lm_lru;
	struct silofs_list_head *itr = lru->ls.prev;
	size_t count = lru->sz;
	int ret = 0;

	while (!ret && count-- && (itr != &lru->ls)) {
		ce = ce_from_lru_link(itr);
		itr = itr->prev;
		ret = cb(ce, arg);
	}
}

static size_t lrumap_overpop(const struct silofs_lrumap *lm)
{
	size_t ovp = 0;

	if (lm->lm_htbl_sz > lm->lm_htbl_cap) {
		ovp = (lm->lm_htbl_sz - lm->lm_htbl_cap);
	} else if (lm->lm_lru.sz > lm->lm_htbl_sz) {
		ovp = (lm->lm_lru.sz - lm->lm_htbl_sz);
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
ubki_from_ce(const struct silofs_cache_elem *ce)
{
	const struct silofs_ubk_info *ubki = NULL;

	if (ce != NULL) {
		ubki = container_of2(ce, struct silofs_ubk_info, ubk_ce);
	}
	return unconst(ubki);
}

static struct silofs_cache_elem *ubki_to_ce(const struct silofs_ubk_info *ubki)
{
	const struct silofs_cache_elem *ce = &ubki->ubk_ce;

	return unconst(ce);
}

static void ubki_set_addr(struct silofs_ubk_info *ubki,
                          const struct silofs_bkaddr *bkaddr)
{
	struct silofs_cache_elem *ce = ubki_to_ce(ubki);

	silofs_bkaddr_assign(&ubki->ubk_addr, bkaddr);
	ckey_by_bkaddr(&ce->ce_ckey, &ubki->ubk_addr);
}

static void ubki_init(struct silofs_ubk_info *ubki, struct silofs_block *ubk,
                      const struct silofs_bkaddr *bkaddr)
{
	silofs_ce_init(&ubki->ubk_ce);
	ubki_set_addr(ubki, bkaddr);
	ubki->ubk = ubk;
	ubki->ubk_bli = NULL;
}

static void ubki_fini(struct silofs_ubk_info *ubki)
{
	silofs_ce_fini(&ubki->ubk_ce);
	ubki->ubk = NULL;
}

static void ubki_incref(struct silofs_ubk_info *ubki)
{
	ce_incref(ubki_to_ce(ubki));
}

static void ubki_decref(struct silofs_ubk_info *ubki)
{
	ce_decref(ubki_to_ce(ubki));
}

static bool ubki_is_evictable(const struct silofs_ubk_info *ubki)
{
	return ce_is_evictable(ubki_to_ce(ubki));
}

void silofs_ubki_attach(struct silofs_ubk_info *ubki,
                        struct silofs_blob_info *bli)
{
	if (ubki->ubk_bli == NULL) {
		bli_incref(bli);
		ubki->ubk_bli = bli;
	}
}

static void ubki_detach(struct silofs_ubk_info *ubki)
{
	struct silofs_blob_info *bli = ubki->ubk_bli;

	if (bli != NULL) {
		bli_decref(bli);
		ubki->ubk_bli = NULL;
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vbk_info *
vbki_from_ce(const struct silofs_cache_elem *ce)
{
	const struct silofs_vbk_info *vbki = NULL;

	if (ce != NULL) {
		vbki = container_of2(ce, struct silofs_vbk_info, vbk_ce);
	}
	return unconst(vbki);
}

static struct silofs_cache_elem *vbki_to_ce(const struct silofs_vbk_info *vbki)
{
	const struct silofs_cache_elem *ce = &vbki->vbk_ce;

	return unconst(ce);
}

static void vbki_set_vbk_addr(struct silofs_vbk_info *vbki,
                              loff_t voff, enum silofs_stype vspace)
{
	struct silofs_cache_elem *ce = vbki_to_ce(vbki);

	vbki->vbk_addr.vbk_voff = off_align_to_bk(voff);
	vbki->vbk_addr.vbk_vspace = vspace;
	ckey_by_vbk_addr(&ce->ce_ckey, &vbki->vbk_addr);
}

static void vbki_init(struct silofs_vbk_info *vbki,
                      struct silofs_block *bk,
                      loff_t voff, enum silofs_stype vspace)
{
	silofs_ce_init(&vbki->vbk_ce);
	vbki_set_vbk_addr(vbki, voff, vspace);
	vbki->vbk = bk;
}

static void vbki_fini(struct silofs_vbk_info *vbki)
{
	silofs_ce_fini(&vbki->vbk_ce);
	vbki->vbk = NULL;
}

void silofs_vbki_incref(struct silofs_vbk_info *vbki)
{
	ce_incref(vbki_to_ce(vbki));
}

void silofs_vbki_decref(struct silofs_vbk_info *vbki)
{
	ce_decref(vbki_to_ce(vbki));
}

static bool vbki_is_evictable(const struct silofs_vbk_info *vbki)
{
	return ce_is_evictable(vbki_to_ce(vbki));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_snode_info *si_from_ce(const struct silofs_cache_elem *ce)
{
	const struct silofs_snode_info *si = NULL;

	if (likely(ce != NULL)) {
		si = container_of2(ce, struct silofs_snode_info, s_ce);
	}
	return unconst(si);
}

static struct silofs_cache_elem *si_to_ce(const struct silofs_snode_info *si)
{
	const struct silofs_cache_elem *ce = &si->s_ce;

	return unconst(ce);
}

static struct silofs_cache *si_cache(const struct silofs_snode_info *si)
{
	return si->s_ce.ce_cache;
}

static void si_set_cache(struct silofs_snode_info *si,
                         struct silofs_cache *cache)
{
	si->s_ce.ce_cache = cache;
}

bool silofs_si_isevictable(const struct silofs_snode_info *si)
{
	return ce_is_evictable(si_to_ce(si));
}

static void si_incref(struct silofs_snode_info *si)
{
	ce_incref(&si->s_ce);
}

static void si_decref(struct silofs_snode_info *si)
{
	ce_decref(&si->s_ce);
}

static void si_remove_from_lrumap(struct silofs_snode_info *si,
                                  struct silofs_lrumap *lm)
{
	struct silofs_cache_elem *ce = si_to_ce(si);

	if (ce->ce_mapped) {
		lrumap_remove(lm, ce);
	} else {
		lrumap_unlru(lm, ce);
	}
}

static void si_delete(struct silofs_snode_info *si, struct silofs_alloc *alloc)
{
	si->s_vtbl->del(si, alloc);
}

static int visit_evictable_ti(struct silofs_cache_elem *ce, void *arg)
{
	struct silofs_cache_ctx *c_ctx = arg;
	struct silofs_snode_info *si = si_from_ce(ce);

	c_ctx->count++;
	if (si->s_vtbl->evictable(si)) {
		c_ctx->si = si; /* fount evictable */
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
	return si_cache(&ui->u_si);
}

void silofs_ui_incref(struct silofs_unode_info *ui)
{
	if (likely(ui != NULL)) {
		si_incref(&ui->u_si);
	}
}

void silofs_ui_decref(struct silofs_unode_info *ui)
{
	if (likely(ui != NULL)) {
		si_decref(&ui->u_si);
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
		ui = silofs_ui_from_si(si_from_ce(ce));
	}
	return ui;
}

static struct silofs_cache_elem *ui_to_ce(struct silofs_unode_info *ui)
{
	return si_to_ce(&ui->u_si);
}

static void ui_attach_bk(struct silofs_unode_info *ui,
                         struct silofs_ubk_info *ubki)
{
	ubki_incref(ubki);
	ui->u_ubki = ubki;
}

static void ui_detach_bk(struct silofs_unode_info *ui)
{
	struct silofs_ubk_info *ubki = ui->u_ubki;

	if (ubki != NULL) {
		ubki_decref(ubki);
		ui->u_ubki = NULL;
	}
}

static int visit_evictable_ui(struct silofs_cache_elem *ce, void *arg)
{
	struct silofs_cache_ctx *c_ctx = arg;
	int ret;

	ret = visit_evictable_ti(ce, arg);
	if (ret && (c_ctx->si != NULL)) {
		c_ctx->ui = silofs_ui_from_si(c_ctx->si);
	}
	return ret;
}

void silofs_ui_attach_to(struct silofs_unode_info *ui,
                         struct silofs_ubk_info *ubki)
{
	ui_detach_bk(ui);
	ui_attach_bk(ui, ubki);
	silofs_ui_bind_view(ui);
}

static bool ui_is_evictable(const struct silofs_unode_info *ui)
{
	return ui->u_si.s_vtbl->evictable(&ui->u_si);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_cache *vi_cache(const struct silofs_vnode_info *vi)
{
	return si_cache(&vi->v_si);
}

static struct silofs_vnode_info *vi_from_ce(struct silofs_cache_elem *ce)
{
	struct silofs_vnode_info *vi = NULL;

	if (ce != NULL) {
		vi = silofs_vi_from_si(si_from_ce(ce));
	}
	return vi;
}

static struct silofs_cache_elem *vi_to_ce(const struct silofs_vnode_info *vi)
{
	const struct silofs_cache_elem *ce = &vi->v_si.s_ce;

	return unconst(ce);
}

static int visit_evictable_vi(struct silofs_cache_elem *ce, void *arg)
{
	int ret;
	struct silofs_cache_ctx *c_ctx = arg;

	ret = visit_evictable_ti(ce, arg);
	if (ret && (c_ctx->si != NULL)) {
		c_ctx->vi = silofs_vi_from_si(c_ctx->si);
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

void silofs_vi_decref(struct silofs_vnode_info *vi)
{
	if (likely(vi != NULL)) {
		ce_decref(vi_to_ce(vi));
	}
}

static void vi_attach_bk(struct silofs_vnode_info *vi,
                         struct silofs_vbk_info *vbki)
{
	silofs_vbki_incref(vbki);
	vi->v_vbki = vbki;
}

static void vi_detach_bk(struct silofs_vnode_info *vi)
{
	struct silofs_vbk_info *vbki = vi->v_vbki;

	if (vbki != NULL) {
		silofs_vbki_decref(vbki);
		vi->v_vbki = NULL;
	}
}

void silofs_vi_attach_to(struct silofs_vnode_info *vi,
                         struct silofs_vbk_info *vbki)
{
	vi_attach_bk(vi, vbki);
	silofs_vi_bind_view(vi);
}

static bool vi_is_evictable(const struct silofs_vnode_info *vi)
{
	return vi->v_si.s_vtbl->evictable(&vi->v_si);
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

static struct silofs_snode_info *dq_lh_to_si(struct silofs_list_head *dq_lh)
{
	const struct silofs_snode_info *si = NULL;

	if (dq_lh != NULL) {
		si = container_of(dq_lh, struct silofs_snode_info, s_dq_lh);
	}
	return unconst(si);
}

static void cache_dq_enq_si(struct silofs_cache *cache,
                            struct silofs_snode_info *si)
{
	struct silofs_dirtyq *dq = &cache->c_dq;

	if (!si->s_ce.ce_dirty) {
		dq_append(dq, &si->s_dq_lh, stype_size(si->s_stype));
		si->s_ce.ce_dirty = true;
	}
}

static void cache_dq_dec_si(struct silofs_cache *cache,
                            struct silofs_snode_info *si)
{
	struct silofs_dirtyq *dq = &cache->c_dq;

	if (si->s_ce.ce_dirty) {
		dq_remove(dq, &si->s_dq_lh, stype_size(si->s_stype));
		si->s_ce.ce_dirty = false;
	}
}

static void cache_dirtify_si(struct silofs_cache *cache,
                             struct silofs_snode_info *si)
{
	cache_dq_enq_si(cache, si);
}

static void cache_undirtify_si(struct silofs_cache *cache,
                               struct silofs_snode_info *si)
{
	cache_dq_dec_si(cache, si);
}

static struct silofs_snode_info *
cache_dq_front_si(const struct silofs_cache *cache)
{
	const struct silofs_dirtyq *dq = &cache->c_dq;

	return dq_lh_to_si(dq_front(dq));
}

static struct silofs_snode_info *
cache_dq_next_si(const struct silofs_cache *cache,
                 const struct silofs_snode_info *si)
{
	const struct silofs_dirtyq *dq = &cache->c_dq;

	return dq_lh_to_si(dq_next_of(dq, &si->s_dq_lh));
}

static void cache_dirtify_ui(struct silofs_cache *cache,
                             struct silofs_unode_info *ui)
{
	cache_dirtify_si(cache, &ui->u_si);
}

static void cache_undirtify_ui(struct silofs_cache *cache,
                               struct silofs_unode_info *ui)
{
	cache_undirtify_si(cache, &ui->u_si);
}

static void cache_dirtify_vi(struct silofs_cache *cache,
                             struct silofs_vnode_info *vi)
{
	cache_dirtify_si(cache, &vi->v_si);
}

static void cache_undirtify_vi(struct silofs_cache *cache,
                               struct silofs_vnode_info *vi)
{
	cache_undirtify_si(cache, &vi->v_si);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_blob_info *
cache_new_bli(const struct silofs_cache *cache,
              const struct silofs_blobid *blobid)
{
	return silofs_bli_new(cache->c_alloc, blobid);
}

static void cache_del_bli(const struct silofs_cache *cache,
                          struct silofs_blob_info *bli)
{
	silofs_bli_del(bli, cache->c_alloc);
}

static int cache_init_bli_lm(struct silofs_cache *cache, size_t htbl_size)
{
	return lrumap_init(&cache->c_bli_lm, cache->c_alloc, htbl_size);
}

static void cache_fini_bli_lm(struct silofs_cache *cache)
{
	lrumap_fini(&cache->c_bli_lm, cache->c_alloc);
}

static struct silofs_blob_info *
cache_find_bli(const struct silofs_cache *cache,
               const struct silofs_blobid *blobid)
{
	struct silofs_ckey ckey;
	struct silofs_cache_elem *ce;

	silofs_ckey_by_blobid(&ckey, blobid);
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
cache_spawn_bli(struct silofs_cache *cache, const struct silofs_blobid *blobid)
{
	struct silofs_blob_info *bli;

	bli = cache_new_bli(cache, blobid);
	if (bli == NULL) {
		return NULL;
	}
	cache_store_bli(cache, bli);
	return bli;
}

static struct silofs_blob_info *
cache_find_relru_bli(struct silofs_cache *cache,
                     const struct silofs_blobid *blobid)
{
	struct silofs_blob_info *bli;

	bli = cache_find_bli(cache, blobid);
	if (bli != NULL) {
		cache_promote_lru_bli(cache, bli);
	}
	return bli;
}

struct silofs_blob_info *
silofs_cache_lookup_blob(struct silofs_cache *cache,
                         const struct silofs_blobid *blobid)
{
	return cache_find_relru_bli(cache, blobid);
}

static struct silofs_blob_info *
cache_find_or_spawn_bli(struct silofs_cache *cache,
                        const struct silofs_blobid *blobid)
{
	struct silofs_blob_info *bli;

	bli = cache_find_relru_bli(cache, blobid);
	if (bli != NULL) {
		return bli;
	}
	bli = cache_spawn_bli(cache, blobid);
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
cache_require_bli(struct silofs_cache *cache,
                  const struct silofs_blobid *blobid)
{
	struct silofs_blob_info *bli = NULL;
	int retry = CACHE_RETRY;

	while (retry-- > 0) {
		bli = cache_find_or_spawn_bli(cache, blobid);
		if (blobid != NULL) {
			break;
		}
		cache_evict_some(cache);
	}
	return bli;
}

struct silofs_blob_info *
silofs_cache_spawn_blob(struct silofs_cache *cache,
                        const struct silofs_blobid *blobid)
{
	return cache_require_bli(cache, blobid);
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
cache_shrink_or_relru_blis(struct silofs_cache *cache, size_t cnt, bool force)
{
	struct silofs_blob_info *bli;
	const size_t n = min(cnt, cache->c_bli_lm.lm_lru.sz);
	size_t evicted = 0;
	bool ok;

	for (size_t i = 0; i < n; ++i) {
		bli = cache_get_lru_bli(cache);
		if (bli == NULL) {
			break;
		}
		ok = cache_evict_or_relru_bli(cache, bli);
		if (ok) {
			evicted++;
		} else if (!force) {
			break;
		}
	}
	return evicted;
}

/*
 * Shrink-relru of blobs is different from other shrinker, as elements do not
 * get promoted often in LRU, but rather stay alive due to ref-count by live
 * blocks. Thus, we end up with lots of elements which are live with active
 * ref-count at the tail of LRU, and therefore we need to keep on iterating in
 * search for other candidate for eviction.
 */
/*
 * TODO-0035: Define proper upper-bound.
 *
 * Have explicit upper-limit to cached blobs, based on the process' rlimit
 * RLIMIT_NOFILE and memory limits.
 */
static size_t cache_blobs_overflow(const struct silofs_cache *cache)
{
	const size_t bar = 256;
	const size_t cur = cache->c_bli_lm.lm_lru.sz;

	return (cur > bar) ? (cur - bar) : 0;
}

void silofs_cache_relax_blobs(struct silofs_cache *cache)
{
	const size_t cnt = cache_blobs_overflow(cache);

	cache_shrink_or_relru_blis(cache, cnt, true);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_ubk_info *
cache_new_ubki(const struct silofs_cache *cache,
               const struct silofs_bkaddr *bkaddr)
{
	struct silofs_block *ubk;
	struct silofs_ubk_info *ubki = NULL;
	struct silofs_alloc *alloc = cache->c_alloc;

	ubk = bk_malloc(alloc);
	if (ubk == NULL) {
		return NULL;
	}
	ubki = ubki_malloc(alloc);
	if (ubki == NULL) {
		bk_free(ubk, alloc);
		return NULL;
	}
	ubki_init(ubki, ubk, bkaddr);
	return ubki;
}

static void cache_del_ubki(const struct silofs_cache *cache,
                           struct silofs_ubk_info *ubki)
{
	struct silofs_block *ubk = ubki->ubk;
	struct silofs_alloc *alloc = cache->c_alloc;

	ubki_detach(ubki);
	ubki_fini(ubki);
	ubki_free(ubki, alloc);
	bk_free(ubk, alloc);
}

static int cache_init_ubki_lm(struct silofs_cache *cache, size_t htbl_size)
{
	return lrumap_init(&cache->c_ubki_lm, cache->c_alloc, htbl_size);
}

static void cache_fini_ubki_lm(struct silofs_cache *cache)
{
	lrumap_fini(&cache->c_ubki_lm, cache->c_alloc);
}

static struct silofs_ubk_info *
cache_find_ubki(const struct silofs_cache *cache,
                const struct silofs_bkaddr *bkaddr)
{
	struct silofs_ckey ckey;
	struct silofs_cache_elem *ce;

	ckey_by_bkaddr(&ckey, bkaddr);
	ce = lrumap_find(&cache->c_ubki_lm, &ckey);
	return ubki_from_ce(ce);
}

static void cache_store_ubki(struct silofs_cache *cache,
                             struct silofs_ubk_info *ubki)
{
	lrumap_store(&cache->c_ubki_lm, ubki_to_ce(ubki));
}

static void cache_promote_lru_ubki(struct silofs_cache *cache,
                                   struct silofs_ubk_info *ubki)
{
	lrumap_promote_lru(&cache->c_ubki_lm, ubki_to_ce(ubki));
}

static void cache_evict_ubki(struct silofs_cache *cache,
                             struct silofs_ubk_info *ubki)
{
	lrumap_remove(&cache->c_ubki_lm, ubki_to_ce(ubki));
	cache_del_ubki(cache, ubki);
}

void silofs_cache_forget_ubk(struct silofs_cache *cache,
                             struct silofs_ubk_info *ubki)
{
	if (ubki_is_evictable(ubki)) {
		cache_evict_ubki(cache, ubki);
	}
}

static struct silofs_ubk_info *
cache_spawn_ubki(struct silofs_cache *cache,
                 const struct silofs_bkaddr *bkaddr)
{
	struct silofs_ubk_info *ubki;

	ubki = cache_new_ubki(cache, bkaddr);
	if (ubki == NULL) {
		return NULL;
	}
	cache_store_ubki(cache, ubki);
	return ubki;
}

static struct silofs_ubk_info *
cache_find_relru_ubki(struct silofs_cache *cache,
                      const struct silofs_bkaddr *bkaddr)
{
	struct silofs_ubk_info *ubki;

	ubki = cache_find_ubki(cache, bkaddr);
	if (ubki != NULL) {
		cache_promote_lru_ubki(cache, ubki);
	}
	return ubki;
}

static struct silofs_ubk_info *
cache_find_or_spawn_ubki(struct silofs_cache *cache,
                         const struct silofs_bkaddr *bkaddr)
{
	struct silofs_ubk_info *ubki;

	ubki = cache_find_relru_ubki(cache, bkaddr);
	if (ubki != NULL) {
		return ubki;
	}
	ubki = cache_spawn_ubki(cache, bkaddr);
	if (ubki == NULL) {
		return NULL; /* TODO: debug-trace */
	}
	return ubki;
}

static int visit_evictable_ubki(struct silofs_cache_elem *ce, void *arg)
{
	struct silofs_cache_ctx *c_ctx = arg;
	struct silofs_ubk_info *ubki = ubki_from_ce(ce);

	c_ctx->count++;
	if (ubki_is_evictable(ubki)) {
		c_ctx->ubki = ubki;
		return 1;
	}
	if (c_ctx->count >= c_ctx->limit) {
		return 1;
	}
	return 0;
}

static struct silofs_ubk_info *
cache_find_evictable_ubki(struct silofs_cache *cache)
{
	struct silofs_lrumap *lm = &cache->c_ubki_lm;
	struct silofs_cache_ctx c_ctx = {
		.cache = cache,
		.ubki = NULL,
		.limit = lrumap_calc_search_evictable_max(lm)
	};

	lrumap_foreach_backward(lm, visit_evictable_ubki, &c_ctx);
	return c_ctx.ubki;
}

static struct silofs_ubk_info *
cache_require_ubki(struct silofs_cache *cache,
                   const struct silofs_bkaddr *bkaddr)
{
	struct silofs_ubk_info *ubki = NULL;
	int retry = CACHE_RETRY;

	while (retry-- > 0) {
		ubki = cache_find_or_spawn_ubki(cache, bkaddr);
		if (ubki != NULL) {
			break;
		}
		cache_evict_some(cache);
	}
	return ubki;
}

static struct silofs_ubk_info *cache_get_lru_ubki(struct silofs_cache *cache)
{
	struct silofs_cache_elem *ce;

	ce = lrumap_get_lru(&cache->c_ubki_lm);
	return ubki_from_ce(ce);
}

static void cache_try_evict_ubki(struct silofs_cache *cache,
                                 struct silofs_ubk_info *ubki)
{
	silofs_assert_not_null(ubki);

	if (ubki_is_evictable(ubki)) {
		cache_evict_ubki(cache, ubki);
	}
}

static int try_evict_ubki(struct silofs_cache_elem *ce, void *arg)
{
	struct silofs_cache_ctx *c_ctx = arg;
	struct silofs_ubk_info *ubki = ubki_from_ce(ce);

	cache_try_evict_ubki(c_ctx->cache, ubki);
	return 0;
}

static void cache_drop_evictable_ubkis(struct silofs_cache *cache)
{
	struct silofs_cache_ctx c_ctx = {
		.cache = cache
	};

	lrumap_foreach_backward(&cache->c_ubki_lm, try_evict_ubki, &c_ctx);
}

static bool cache_evict_or_relru_ubki(struct silofs_cache *cache,
                                      struct silofs_ubk_info *ubki)
{
	bool evicted;

	if (ubki_is_evictable(ubki)) {
		cache_evict_ubki(cache, ubki);
		evicted = true;
	} else {
		cache_promote_lru_ubki(cache, ubki);
		evicted = false;
	}
	return evicted;
}

static size_t
cache_shrink_or_relru_ubkis(struct silofs_cache *cache, size_t cnt, bool force)
{
	struct silofs_ubk_info *ubki;
	const size_t n = min(cnt, cache->c_ubki_lm.lm_lru.sz);
	size_t evicted = 0;
	bool ok;

	for (size_t i = 0; i < n; ++i) {
		ubki = cache_get_lru_ubki(cache);
		if (ubki == NULL) {
			break;
		}
		ok = cache_evict_or_relru_ubki(cache, ubki);
		if (ok) {
			evicted++;
		} else if (!force) {
			break;
		}
	}
	return evicted;
}

struct silofs_ubk_info *
silofs_cache_lookup_ubk(struct silofs_cache *cache,
                        const struct silofs_bkaddr *bkaddr)
{
	return cache_find_relru_ubki(cache, bkaddr);
}

struct silofs_ubk_info *
silofs_cache_spawn_ubk(struct silofs_cache *cache,
                       const struct silofs_bkaddr *bkaddr)
{
	return cache_require_ubki(cache, bkaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int cache_init_ui_lm(struct silofs_cache *cache, size_t htbl_size)
{
	return lrumap_init(&cache->c_ui_lm, cache->c_alloc, htbl_size);
}

static void cache_fini_ui_lm(struct silofs_cache *cache)
{
	lrumap_fini(&cache->c_ui_lm, cache->c_alloc);
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
	si_remove_from_lrumap(&ui->u_si, &cache->c_ui_lm);
}

static void cache_evict_ui(struct silofs_cache *cache,
                           struct silofs_unode_info *ui)
{
	struct silofs_snode_info *ti = &ui->u_si;

	cache_remove_ui(cache, ui);
	ui_detach_bk(ui);
	si_delete(ti, cache->c_alloc);
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
	struct silofs_snode_info *ti = &ui->u_si;
	bool evicted;

	if (ti->s_vtbl->evictable(ti)) {
		cache_evict_ui(cache, ui);
		evicted = true;
	} else {
		cache_promote_lru_ui(cache, ui);
		evicted = false;
	}
	return evicted;
}

static size_t
cache_shrink_or_relru_uis(struct silofs_cache *cache, size_t cnt, bool force)
{
	struct silofs_unode_info *ui;
	const size_t n = min(cnt, cache->c_ui_lm.lm_lru.sz);
	size_t evicted = 0;
	bool ok;

	for (size_t i = 0; i < n; ++i) {
		ui = cache_get_lru_ui(cache);
		if (ui == NULL) {
			break;
		}
		ok = cache_evict_or_relru_ui(cache, ui);
		if (ok) {
			evicted++;
		} else if (!force) {
			break;
		}
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
	return silofs_new_ui(cache->c_alloc, uaddr);
}

static void cache_track_uaddr(struct silofs_cache *cache,
                              const struct silofs_uaddr *uaddr)
{
	silofs_uamap_insert(&cache->c_uam, uaddr);
}

static void cache_forget_uaddr(struct silofs_cache *cache,
                               const struct silofs_uaddr *uaddr)
{
	silofs_uamap_remove(&cache->c_uam, uaddr);
}

static const struct silofs_uaddr *
cache_lookup_uaddr_by(struct silofs_cache *cache,
                      const struct silofs_uakey *uakey)
{
	return silofs_uamap_lookup(&cache->c_uam, uakey);
}

static void cache_track_uaddr_of(struct silofs_cache *cache,
                                 const struct silofs_unode_info *ui)
{
	struct silofs_uakey uakey;
	const struct silofs_uaddr *uaddr = ui_uaddr(ui);

	silofs_uakey_setup_by(&uakey, uaddr);
	if (!cache_lookup_uaddr_by(cache, &uakey)) {
		cache_track_uaddr(cache, uaddr);
	}
}

struct silofs_unode_info *
silofs_cache_lookup_unode(struct silofs_cache *cache,
                          const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *ui;

	ui = cache_find_relru_ui(cache, uaddr);
	if (ui != NULL) {
		cache_track_uaddr_of(cache, ui);
	}
	return ui;
}

static struct silofs_unode_info *
cache_require_ui(struct silofs_cache *cache, const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *ui = NULL;
	int retry = CACHE_RETRY;

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
	struct silofs_snode_info *si = &ui->u_si;
	const struct silofs_uaddr *uaddr = ui_uaddr(ui);

	ckey_by_uaddr(&si->s_ce.ce_ckey, uaddr);
	cache_store_ui_lrumap(cache, ui);
}

struct silofs_unode_info *
silofs_cache_spawn_unode(struct silofs_cache *cache,
                         const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *ui;

	ui = cache_require_ui(cache, uaddr);
	if (ui != NULL) {
		si_set_cache(&ui->u_si, cache);
		cache_store_ui(cache, ui);
		cache_track_uaddr(cache, ui_uaddr(ui));
	}
	return ui;
}

void silofs_cache_forget_unode(struct silofs_cache *cache,
                               struct silofs_unode_info *ui)
{
	ui_undirtify(ui);
	cache_forget_uaddr(cache, ui_uaddr(ui));
	cache_evict_ui(cache, ui);
}

struct silofs_unode_info *
silofs_cache_find_unode_by(struct silofs_cache *cache,
                           const struct silofs_uakey *uakey)
{
	const struct silofs_uaddr *uaddr;
	struct silofs_unode_info *ui = NULL;

	uaddr = cache_lookup_uaddr_by(cache, uakey);
	if (uaddr != NULL) {
		ui = silofs_cache_lookup_unode(cache, uaddr);
	}
	return ui;
}

void silofs_cache_forget_uaddrs(struct silofs_cache *cache)
{
	cache_drop_uamap(cache);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vbk_info *
cache_new_vbki(const struct silofs_cache *cache,
               loff_t voff, enum silofs_stype vspace)
{
	struct silofs_block *bk;
	struct silofs_vbk_info *vbki;

	bk = bk_malloc(cache->c_alloc);
	if (bk == NULL) {
		return NULL;
	}
	vbki = vbki_malloc(cache->c_alloc);
	if (vbki == NULL) {
		bk_free(bk, cache->c_alloc);
		return NULL;
	}
	vbki_init(vbki, bk, voff, vspace);
	return vbki;
}

static void cache_del_vbki(const struct silofs_cache *cache,
                           struct silofs_vbk_info *vbki)
{
	struct silofs_block *bk = vbki->vbk;

	vbki_fini(vbki);
	bk_free(bk, cache->c_alloc);
	vbki_free(vbki, cache->c_alloc);
}

static int cache_init_vbki_lm(struct silofs_cache *cache, size_t htbl_size)
{
	return lrumap_init(&cache->c_vbki_lm, cache->c_alloc, htbl_size);
}

static void cache_fini_vbki_lm(struct silofs_cache *cache)
{
	lrumap_fini(&cache->c_vbki_lm, cache->c_alloc);
}

static struct silofs_vbk_info *
cache_find_vbki(const struct silofs_cache *cache,
                loff_t voff, enum silofs_stype vspace)
{
	struct silofs_ckey ckey;
	struct silofs_cache_elem *ce;
	const struct silofs_vbk_addr vbk_addr = {
		.vbk_voff = off_align_to_bk(voff),
		.vbk_vspace = vspace,
	};

	ckey_by_vbk_addr(&ckey, &vbk_addr);
	ce = lrumap_find(&cache->c_vbki_lm, &ckey);
	return vbki_from_ce(ce);
}

static void cache_store_vbki(struct silofs_cache *cache,
                             struct silofs_vbk_info *vbki)
{
	lrumap_store(&cache->c_vbki_lm, vbki_to_ce(vbki));
}

static void cache_promote_lru_vbki(struct silofs_cache *cache,
                                   struct silofs_vbk_info *vbki)
{
	lrumap_promote_lru(&cache->c_vbki_lm, vbki_to_ce(vbki));
}

static void cache_evict_vbki(struct silofs_cache *cache,
                             struct silofs_vbk_info *vbki)
{
	lrumap_remove(&cache->c_vbki_lm, vbki_to_ce(vbki));
	cache_del_vbki(cache, vbki);
}

void silofs_cache_forget_vbk(struct silofs_cache *cache,
                             struct silofs_vbk_info *vbki)
{
	cache_evict_vbki(cache, vbki);
}

static struct silofs_vbk_info *
cache_spawn_vbki(struct silofs_cache *cache,
                 loff_t voff, enum silofs_stype vspace)
{
	struct silofs_vbk_info *vbki;

	vbki = cache_new_vbki(cache, voff, vspace);
	if (vbki == NULL) {
		return NULL;
	}
	cache_store_vbki(cache, vbki);
	return vbki;
}

static struct silofs_vbk_info *
cache_find_relru_vbki(struct silofs_cache *cache,
                      loff_t voff, enum silofs_stype vspace)
{
	struct silofs_vbk_info *vbki;

	vbki = cache_find_vbki(cache, voff, vspace);
	if (vbki != NULL) {
		cache_promote_lru_vbki(cache, vbki);
	}
	return vbki;
}

static struct silofs_vbk_info *
cache_find_or_spawn_vbki(struct silofs_cache *cache,
                         loff_t voff, enum silofs_stype vspace)
{
	struct silofs_vbk_info *vbki;

	vbki = cache_find_relru_vbki(cache, voff, vspace);
	if (vbki != NULL) {
		return vbki;
	}
	vbki = cache_spawn_vbki(cache, voff, vspace);
	if (vbki == NULL) {
		return NULL; /* TODO: debug-trace */
	}
	return vbki;
}

static int visit_evictable_vbki(struct silofs_cache_elem *ce, void *arg)
{
	struct silofs_cache_ctx *c_ctx = arg;
	struct silofs_vbk_info *vbki = vbki_from_ce(ce);

	c_ctx->count++;
	if (vbki_is_evictable(vbki)) {
		c_ctx->vbki = vbki;
		return 1;
	}
	if (c_ctx->count >= c_ctx->limit) {
		return 1;
	}
	return 0;
}

static struct silofs_vbk_info *
cache_find_evictable_vbki(struct silofs_cache *cache)
{
	struct silofs_lrumap *lm = &cache->c_vbki_lm;
	struct silofs_cache_ctx c_ctx = {
		.cache = cache,
		.ubki = NULL,
		.limit = lrumap_calc_search_evictable_max(lm)
	};

	lrumap_foreach_backward(lm, visit_evictable_vbki, &c_ctx);
	return c_ctx.vbki;
}

static struct silofs_vbk_info *
cache_require_vbki(struct silofs_cache *cache,
                   loff_t voff, enum silofs_stype vspace)
{
	struct silofs_vbk_info *vbki = NULL;
	int retry = CACHE_RETRY;

	while (retry-- > 0) {
		vbki = cache_find_or_spawn_vbki(cache, voff, vspace);
		if (vbki != NULL) {
			break;
		}
		cache_evict_some(cache);
	}
	return vbki;
}

static struct silofs_vbk_info *cache_get_lru_vbki(struct silofs_cache *cache)
{
	struct silofs_cache_elem *ce;

	ce = lrumap_get_lru(&cache->c_vbki_lm);
	return vbki_from_ce(ce);
}

static void cache_try_evict_vbki(struct silofs_cache *cache,
                                 struct silofs_vbk_info *vbki)
{
	if (vbki_is_evictable(vbki)) {
		cache_evict_vbki(cache, vbki);
	}
}

static int try_evict_vbki(struct silofs_cache_elem *ce, void *arg)
{
	struct silofs_cache_ctx *c_ctx = arg;
	struct silofs_vbk_info *vbki = vbki_from_ce(ce);

	cache_try_evict_vbki(c_ctx->cache, vbki);
	return 0;
}

static void cache_drop_evictable_vbkis(struct silofs_cache *cache)
{
	struct silofs_cache_ctx c_ctx = {
		.cache = cache
	};

	lrumap_foreach_backward(&cache->c_vbki_lm, try_evict_vbki, &c_ctx);
}

static bool cache_evict_or_relru_vbki(struct silofs_cache *cache,
                                      struct silofs_vbk_info *vbki)
{
	bool evicted;

	if (vbki_is_evictable(vbki)) {
		cache_evict_vbki(cache, vbki);
		evicted = true;
	} else {
		cache_promote_lru_vbki(cache, vbki);
		evicted = false;
	}
	return evicted;
}

static size_t
cache_shrink_or_relru_vbkis(struct silofs_cache *cache, size_t cnt, bool force)
{
	struct silofs_vbk_info *vbki = NULL;
	const size_t n = min(cnt, cache->c_vbki_lm.lm_lru.sz);
	size_t evicted = 0;
	bool ok;

	for (size_t i = 0; i < n; ++i) {
		vbki = cache_get_lru_vbki(cache);
		if (vbki == NULL) {
			break;
		}
		ok = cache_evict_or_relru_vbki(cache, vbki);
		if (ok) {
			evicted++;
		} else if (!force) {
			break;
		}
	}
	return evicted;
}

struct silofs_vbk_info *
silofs_cache_lookup_vbk(struct silofs_cache *cache,
                        loff_t voff, enum silofs_stype vspace)
{
	return cache_find_relru_vbki(cache, voff, vspace);
}

struct silofs_vbk_info *
silofs_cache_spawn_vbk(struct silofs_cache *cache,
                       loff_t voff, enum silofs_stype vspace)
{
	return cache_require_vbki(cache, voff, vspace);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int cache_init_vi_lm(struct silofs_cache *cache, size_t htbl_size)
{
	return lrumap_init(&cache->c_vi_lm, cache->c_alloc, htbl_size);
}

static void cache_fini_vi_lm(struct silofs_cache *cache)
{
	lrumap_fini(&cache->c_vi_lm, cache->c_alloc);
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
	si_remove_from_lrumap(&vi->v_si, &cache->c_vi_lm);
}

static void cache_evict_vi(struct silofs_cache *cache,
                           struct silofs_vnode_info *vi)
{
	struct silofs_snode_info *ti = &vi->v_si;

	cache_remove_vi(cache, vi);
	vi_detach_bk(vi);
	si_delete(ti, cache->c_alloc);
}

static void cache_store_vi_lrumap(struct silofs_cache *cache,
                                  struct silofs_vnode_info *vi)
{
	lrumap_store(&cache->c_vi_lm, vi_to_ce(vi));
}

static void cache_store_vi(struct silofs_cache *cache,
                           struct silofs_vnode_info *vi)
{
	struct silofs_snode_info *si = &vi->v_si;

	ckey_by_vaddr(&si->s_ce.ce_ckey, &vi->v_vaddr);
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
	struct silofs_snode_info *si = &vi->v_si;
	bool evicted;

	if (si->s_vtbl->evictable(si)) {
		cache_evict_vi(cache, vi);
		evicted = true;
	} else {
		cache_promote_lru_vi(cache, vi);
		evicted = false;
	}
	return evicted;
}

static size_t
cache_shrink_or_relru_vis(struct silofs_cache *cache, size_t cnt, bool force)
{
	struct silofs_vnode_info *vi = NULL;
	const size_t n = min(cnt, cache->c_vi_lm.lm_lru.sz);
	size_t evicted = 0;
	bool ok;

	for (size_t i = 0; i < n; ++i) {
		vi = cache_get_lru_vi(cache);
		if (vi == NULL) {
			break;
		}
		ok = cache_evict_or_relru_vi(cache, vi);
		if (ok) {
			evicted++;
		} else if (!force) {
			break;
		}
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
	return silofs_new_vi(cache->c_alloc, vaddr);
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
	if (vi->v_si.s_ce.ce_mapped) {
		lrumap_unmap(&cache->c_vi_lm, vi_to_ce(vi));
	}
}

void silofs_cache_forget_vnode(struct silofs_cache *cache,
                               struct silofs_vnode_info *vi)
{
	vi_undirtify(vi);
	if (vi_refcnt(vi) > 0) {
		cache_unmap_vi(cache, vi);
		vi->v_si.s_ce.ce_forgot = true;
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
		si_set_cache(&vi->v_si, cache);
		cache_store_vi(cache, vi);
	}
	return vi;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t cache_shrink_some(struct silofs_cache *cache, int shift)
{
	const size_t extra = silofs_clamp(1UL << shift, 1, 64);
	size_t actual = 0;
	size_t count;

	count = lrumap_overpop(&cache->c_vi_lm) + extra;
	actual += cache_shrink_or_relru_vis(cache, count, false);

	count = lrumap_overpop(&cache->c_ui_lm) + extra;
	actual += cache_shrink_or_relru_uis(cache, count, false);

	count = lrumap_overpop(&cache->c_ubki_lm) + extra;
	actual += cache_shrink_or_relru_ubkis(cache, count, false);

	count = lrumap_overpop(&cache->c_vbki_lm) + extra;
	actual += cache_shrink_or_relru_vbkis(cache, count, false);

	count = lrumap_overpop(&cache->c_bli_lm) + extra;
	actual += cache_shrink_or_relru_blis(cache, count, false);

	return actual;
}

static size_t cache_lrumaps_overpop(const struct silofs_cache *cache)
{
	const struct silofs_lrumap *lms[] = {
		&cache->c_vi_lm,
		&cache->c_ui_lm,
		&cache->c_ubki_lm,
		&cache->c_vbki_lm,
		&cache->c_bli_lm
	};
	size_t ovp = 0;

	for (size_t i = 0; i < ARRAY_SIZE(lms); ++i) {
		ovp += lrumap_overpop(lms[i]);
	}
	return ovp;
}

static uint64_t cache_memory_pressure(const struct silofs_cache *cache)
{
	struct silofs_alloc_stat st;
	uint64_t nbits;

	silofs_allocstat(cache->c_alloc, &st);
	nbits = min((64UL * st.npages_used) / st.npages_tota, 63);

	/* returns memory-pressure represented as bit-mask */
	return ((1UL << nbits) - 1);
}

static size_t cache_calc_niter(const struct silofs_cache *cache, int flags)
{
	const size_t blobs_over = cache_blobs_overflow(cache);
	const size_t lrumaps_over = cache_lrumaps_overpop(cache);
	const uint64_t mem_press = cache_memory_pressure(cache);
	size_t niter;

	niter = min(lrumaps_over, 64);
	if (flags & SILOFS_F_WALKFS) {
		niter += silofs_popcount64(mem_press >> 1);
	}
	if (flags & SILOFS_F_BRINGUP) {
		niter += silofs_popcount64(mem_press >> 3);
	}
	if (flags & SILOFS_F_IDLE) {
		niter += silofs_popcount64(mem_press >> 4);
	}
	if (flags & SILOFS_F_TIMEOUT) {
		niter += silofs_popcount64(mem_press >> 8);
	}
	if (flags & SILOFS_F_OPSTART) {
		niter += silofs_popcount64(mem_press >> 20);
	}
	if ((flags & (SILOFS_F_IDLE | SILOFS_F_WALKFS))) {
		niter += (mem_press & ~1UL) ? 2 : 1;
	}
	if (flags & SILOFS_F_NOW) {
		niter += 1;
	}
	if (flags && blobs_over) {
		niter += 2;
	}
	return niter;
}

static void cache_relax_niter(struct silofs_cache *cache, size_t niter)
{
	int shift = 0;

	for (size_t i = 0; i < niter; ++i) {
		if (!cache_shrink_some(cache, shift++)) {
			break;
		}
	}
}

void silofs_cache_relax(struct silofs_cache *cache, int flags)
{
	cache_relax_niter(cache, cache_calc_niter(cache, flags));
}

void silofs_cache_shrink_once(struct silofs_cache *cache)
{
	const size_t bk_size = SILOFS_BK_SIZE;
	const size_t memsz_ubkis = bk_size * cache->c_ubki_lm.lm_htbl_sz;
	const size_t memsz_data = cache->mem_size_hint;

	if ((8 * memsz_ubkis) > memsz_data) {
		cache_shrink_some(cache, 0);
	}
}

static size_t cache_lrumap_usage_sum(const struct silofs_cache *cache)
{
	return lrumap_usage(&cache->c_bli_lm) +
	       lrumap_usage(&cache->c_ubki_lm) +
	       lrumap_usage(&cache->c_vbki_lm) +
	       lrumap_usage(&cache->c_vi_lm) +
	       lrumap_usage(&cache->c_ui_lm);
}

static void cache_drop_evictables_once(struct silofs_cache *cache)
{
	cache_drop_evictable_vis(cache);
	cache_drop_evictable_uis(cache);
	cache_drop_evictable_vbkis(cache);
	cache_drop_evictable_ubkis(cache);
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
	silofs_spamaps_drop(&cache->c_spam);
}

static void cache_drop_uamap(struct silofs_cache *cache)
{
	silofs_uamap_drop_all(&cache->c_uam);
}

void silofs_cache_drop(struct silofs_cache *cache)
{
	cache_drop_evictables(cache);
	cache_drop_spcmaps(cache);
	cache_drop_uamap(cache);
}

static size_t flush_threshold_of(int flags)
{
	size_t threshold;
	const size_t mega = SILOFS_UMEGA;

	if (flags & SILOFS_F_NOW) {
		threshold = 0;
	} else if (flags & SILOFS_F_SYNC) {
		threshold = mega / 2;
	} else if (flags & (SILOFS_F_TIMEOUT | SILOFS_F_IDLE)) {
		threshold = mega;
	} else {
		threshold = 2 * mega;
	}
	return threshold;
}

static bool dq_need_flush(const struct silofs_dirtyq *dq, int flags)
{
	size_t threshold;
	bool ret = false;

	if (dq->dq_accum_nbytes) {
		threshold = flush_threshold_of(flags);
		ret = (dq->dq_accum_nbytes > threshold);
	}
	return ret;
}

static bool cache_mem_press_need_flush(const struct silofs_cache *cache)
{
	const uint64_t mem_press = cache_memory_pressure(cache);

	return silofs_popcount64(mem_press) > 12;
}

bool silofs_cache_need_flush(const struct silofs_cache *cache, int flags)
{
	if (cache_blobs_overflow(cache) > 0) {
		return true;
	}
	if (dq_need_flush(&cache->c_dq, flags)) {
		return true;
	}
	if (cache_mem_press_need_flush(cache)) {
		return true;
	}
	return false;
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

static bool cache_evict_by_ubki(struct silofs_cache *cache,
                                struct silofs_ubk_info *ubki)
{
	bool ret = false;

	if ((ubki != NULL) && ubki_is_evictable(ubki)) {
		cache_evict_ubki(cache, ubki);
		ret = true;
	}
	return ret;
}

static bool cache_evict_by_vbki(struct silofs_cache *cache,
                                struct silofs_vbk_info *vbki)
{
	bool ret = false;

	if ((vbki != NULL) && vbki_is_evictable(vbki)) {
		cache_evict_vbki(cache, vbki);
		ret = true;
	}
	return ret;
}

static bool cache_evict_by_vi(struct silofs_cache *cache,
                              struct silofs_vnode_info *vi)
{
	bool ret = false;

	if ((vi != NULL) && vi_is_evictable(vi)) {
		cache_evict_vi(cache, vi);
		ret = true;
	}
	return ret;
}

static bool cache_evict_by_ui(struct silofs_cache *cache,
                              struct silofs_unode_info *ui)
{
	bool ret = false;

	if ((ui != NULL) && ui_is_evictable(ui)) {
		cache_evict_ui(cache, ui);
		ret = true;
	}
	return ret;
}

static void cache_evict_some(struct silofs_cache *cache)
{
	struct silofs_vnode_info *vi = NULL;
	struct silofs_unode_info *ui = NULL;
	struct silofs_vbk_info *vbki = NULL;
	struct silofs_ubk_info *ubki = NULL;
	struct silofs_blob_info *bli = NULL;
	bool evicted = false;

	vi = cache_find_evictable_vi(cache);
	if (cache_evict_by_vi(cache, vi)) {
		evicted = true;
	}
	ui = cache_find_evictable_ui(cache);
	if (cache_evict_by_ui(cache, ui)) {
		evicted = true;
	}
	vbki = cache_find_evictable_vbki(cache);
	if (cache_evict_by_vbki(cache, vbki)) {
		evicted = true;
	}
	ubki = cache_find_evictable_ubki(cache);
	if (cache_evict_by_ubki(cache, ubki)) {
		evicted = true;
	}
	bli = cache_find_evictable_bli(cache);
	if (cache_evict_by_bli(cache, bli)) {
		evicted = true;
	}
	if (!evicted) {
		cache_shrink_some(cache, 0);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int cache_init_nil_bk(struct silofs_cache *cache)
{
	struct silofs_block *nil_bk;

	nil_bk = silofs_allocate(cache->c_alloc, sizeof(*nil_bk));
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
		silofs_deallocate(cache->c_alloc, nil_bk, sizeof(*nil_bk));
		cache->c_nil_bk = NULL;
	}
}

static size_t cache_htbl_size(const struct silofs_cache *cache, size_t div)
{
	const size_t hwant = cache->mem_size_hint / div;
	const size_t limit = silofs_clamp(hwant, 1U << 14, 1U << 20);

	return htbl_prime_size(limit);
}

static void cache_fini_lrumaps(struct silofs_cache *cache)
{
	cache_fini_vi_lm(cache);
	cache_fini_ui_lm(cache);
	cache_fini_vbki_lm(cache);
	cache_fini_ubki_lm(cache);
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
	err = cache_init_vbki_lm(cache, hsize);
	if (err) {
		goto out_err;
	}
	err = cache_init_ubki_lm(cache, hsize);
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

static int cache_init_spamaps(struct silofs_cache *cache)
{
	return silofs_spamaps_init(&cache->c_spam, cache->c_alloc);
}

static void cache_fini_spamaps(struct silofs_cache *cache)
{
	silofs_spamaps_fini(&cache->c_spam);
}

static int cache_init_uamap(struct silofs_cache *cache)
{
	return silofs_uamap_init(&cache->c_uam, cache->c_alloc);
}

static void cache_fini_uamap(struct silofs_cache *cache)
{
	silofs_uamap_fini(&cache->c_uam);
}

static int cache_init_mdigest(struct silofs_cache *cache)
{
	return silofs_mdigest_init(&cache->c_mdigest);
}

static void cache_fini_mdigest(struct silofs_cache *cache)
{
	silofs_mdigest_fini(&cache->c_mdigest);
}

int silofs_cache_init(struct silofs_cache *cache,
                      struct silofs_alloc *alloc, size_t msz_hint)
{
	int err;

	cache->c_alloc = alloc;
	cache->c_nil_bk = NULL;
	cache->mem_size_hint = msz_hint;
	dq_init(&cache->c_dq);

	err = cache_init_mdigest(cache);
	if (err) {
		return err;
	}
	err = cache_init_spamaps(cache);
	if (err) {
		goto out_err;
	}
	err = cache_init_uamap(cache);
	if (err) {
		goto out_err;
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
	silofs_cache_fini(cache);
	return err;
}

void silofs_cache_fini(struct silofs_cache *cache)
{
	dq_fini(&cache->c_dq);
	cache_fini_lrumaps(cache);
	cache_fini_nil_bk(cache);
	cache_fini_uamap(cache);
	cache_fini_spamaps(cache);
	cache_fini_mdigest(cache);
	cache->c_alloc = NULL;
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
	if (likely(sbi != NULL)) {
		si_incref(&sbi->sb_ui.u_si);
	}
}

void silofs_sbi_decref(struct silofs_sb_info *sbi)
{
	if (likely(sbi != NULL)) {
		si_decref(&sbi->sb_ui.u_si);
	}
}


void silofs_spi_incref(struct silofs_spstats_info *spi)
{
	if (likely(spi != NULL)) {
		si_incref(&spi->sp_ui.u_si);
	}
}

void silofs_spi_decref(struct silofs_spstats_info *spi)
{
	if (likely(spi != NULL)) {
		si_decref(&spi->sp_ui.u_si);
	}
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_cache_fill_into_dset(const struct silofs_cache *cache,
                                 struct silofs_dset *dset)
{
	struct silofs_snode_info *si = NULL;

	si = cache_dq_front_si(cache);
	while (si != NULL) {
		if (!si->s_noflush) {
			dset->ds_add_fn(dset, si);
		}
		si = cache_dq_next_si(cache, si);
	}
}

void silofs_cache_undirtify_by_dset(struct silofs_cache *cache,
                                    const struct silofs_dset *dset)
{
	struct silofs_snode_info *si_next = NULL;
	struct silofs_snode_info *si = dset->ds_siq;

	while (si != NULL) {
		si_next = si->s_ds_next;
		cache_undirtify_si(cache, si);
		si->s_ds_next = NULL;
		si = si_next;
	}
}
