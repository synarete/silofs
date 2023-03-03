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
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/types.h>
#include <silofs/address.h>
#include <silofs/nodes.h>
#include <silofs/spxmap.h>
#include <silofs/crypto.h>
#include <silofs/cache.h>
#include <silofs/boot.h>
#include <silofs/repo.h>
#include <silofs/fs-private.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>

#define CACHE_RETRY 4


static void cache_pre_op(struct silofs_cache *cache);
static void cache_post_op(struct silofs_cache *cache);
static void cache_drop_uamap(struct silofs_cache *cache);
static void cache_evict_some(struct silofs_cache *cache);
static void cache_dirtify_ui(struct silofs_cache *cache,
                             struct silofs_unode_info *ui);
static void cache_undirtify_ui(struct silofs_cache *cache,
                               struct silofs_unode_info *ui);

typedef int (*silofs_cache_elem_fn)(struct silofs_cache_elem *, void *);

struct silofs_cache_ctx {
	struct silofs_cache      *cache;
	struct silofs_blobf      *blobf;
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

static size_t htbl_cap_as_prime(size_t lim)
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
	return silofs_blobid_hash(blobid);
}

static uint64_t hash_of_vaddr(const struct silofs_vaddr *vaddr)
{
	const uint64_t h = twang_mix64((uint64_t)vaddr->off);

	return silofs_rotate64(h, vaddr->stype % 59) ^ vaddr->len;
}

static uint64_t hash_of_bkaddr(const struct silofs_bkaddr *bkaddr)
{
	return silofs_blobid_hash(&bkaddr->blobid) ^ (uint64_t)bkaddr->lba;
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
	const uint64_t voff = (uint64_t)(vbk_addr->vbk_voff);
	const uint64_t vspc = (uint64_t)(vbk_addr->vbk_vspace);

	return ~twang_mix64(voff + vspc);
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
	ce->ce_hitcnt = 0;
	ce->ce_mapped = false;
	ce->ce_forgot = false;
	ce->ce_dirty = false;
}

void silofs_ce_fini(struct silofs_cache_elem *ce)
{
	silofs_assert_eq(ce->ce_refcnt, 0);
	silofs_assert(!ce->ce_mapped);
	silofs_assert(!ce->ce_dirty);

	ckey_reset(&ce->ce_ckey);
	list_head_fini(&ce->ce_htb_lh);
	list_head_fini(&ce->ce_lru_lh);
	ce->ce_refcnt = INT_MIN;
	ce->ce_hitcnt = -1;
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

static struct silofs_list_head *
ce_lru_link(struct silofs_cache_elem *ce)
{
	return &ce->ce_lru_lh;
}

static const struct silofs_list_head *
ce_lru_link2(const struct silofs_cache_elem *ce)
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

static bool ce_need_relru(const struct silofs_cache_elem *ce,
                          const struct silofs_listq *lru)
{
	const struct silofs_list_head *lru_front = listq_front(lru);
	const struct silofs_list_head *ce_lru_lnk = ce_lru_link2(ce);

	if (unlikely(lru_front == NULL)) {
		return false; /* make clang-scan happy */
	}
	if (lru_front == ce_lru_lnk) {
		return false; /* already first */
	}
	if (lru_front->next == ce_lru_lnk) {
		return false; /* second in line */
	}
	if (lru->sz < 16) {
		return false; /* don't bother in case of small LRU */
	}
	if (ce->ce_hitcnt < 4) {
		return false; /* low hit count */
	}
	return true;
}

static void ce_relru(struct silofs_cache_elem *ce, struct silofs_listq *lru)
{
	ce_unlru(ce, lru);
	ce_lru(ce, lru);
}

static int ce_refcnt(const struct silofs_cache_elem *ce)
{
	return ce->ce_refcnt;
}

static void ce_incref(struct silofs_cache_elem *ce)
{
	ce->ce_refcnt++;
}

static void ce_decref(struct silofs_cache_elem *ce)
{
	ce->ce_refcnt--;
}

static bool ce_is_evictable(const struct silofs_cache_elem *ce)
{
	return !ce->ce_dirty && !ce_refcnt(ce);
}

static int ce_refcnt_atomic(const struct silofs_cache_elem *ce)
{
	silofs_assert_ge(ce->ce_refcnt, 0);
	return silofs_atomic_get(&ce->ce_refcnt);
}

static void ce_incref_atomic(struct silofs_cache_elem *ce)
{
	silofs_atomic_add(&ce->ce_refcnt, 1);
}

static void ce_decref_atomic(struct silofs_cache_elem *ce)
{
	silofs_assert_ge(ce->ce_refcnt, 1);
	silofs_atomic_sub(&ce->ce_refcnt, 1);
}

static bool ce_is_evictable_atomic(const struct silofs_cache_elem *ce)
{
	return !ce->ce_dirty && !ce_refcnt_atomic(ce);
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
                               struct silofs_cache_elem *ce, bool now)
{
	struct silofs_listq *lru = &lm->lm_lru;

	ce->ce_hitcnt++;
	if (now || ce_need_relru(ce, lru)) {
		ce_relru(ce, &lm->lm_lru);
		ce->ce_hitcnt = 0;
	}
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

static struct silofs_blobf *
blobf_from_ce(const struct silofs_cache_elem *ce)
{
	const struct silofs_blobf *blobf = NULL;

	if (ce != NULL) {
		blobf = container_of2(ce, struct silofs_blobf, b_ce);
	}
	return unconst(blobf);
}

static struct silofs_cache_elem *
blobf_to_ce(const struct silofs_blobf *blobf)
{
	const struct silofs_cache_elem *ce = &blobf->b_ce;

	return unconst(ce);
}

void silofs_blobf_incref(struct silofs_blobf *blobf)
{
	if (likely(blobf != NULL)) {
		ce_incref_atomic(blobf_to_ce(blobf));
	}
}

void silofs_blobf_decref(struct silofs_blobf *blobf)
{
	if (likely(blobf != NULL)) {
		ce_decref_atomic(blobf_to_ce(blobf));
	}
}

static bool blobf_is_evictable(const struct silofs_blobf *blobf)
{
	return ce_is_evictable_atomic(blobf_to_ce(blobf));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_bk_info *bki_from_ce(const struct silofs_cache_elem *ce)
{
	const struct silofs_bk_info *bki = NULL;

	if (ce != NULL) {
		bki = container_of2(ce, struct silofs_bk_info, bk_ce);
	}
	return unconst(bki);
}

static struct silofs_cache_elem *bki_to_ce(const struct silofs_bk_info *bki)
{
	const struct silofs_cache_elem *ce = &bki->bk_ce;

	return unconst(ce);
}

static void bki_init(struct silofs_bk_info *bki, struct silofs_block *bk)
{
	silofs_ce_init(&bki->bk_ce);
	bki->bk = bk;
	bki->bk_view = 0;
}

static void bki_fini(struct silofs_bk_info *bki)
{
	silofs_ce_fini(&bki->bk_ce);
	bki->bk = NULL;
}

static void bki_incref(struct silofs_bk_info *bki)
{
	ce_incref_atomic(bki_to_ce(bki));
}

void silofs_bki_incref(struct silofs_bk_info *bki)
{
	if (likely(bki != NULL)) {
		bki_incref(bki);
	}
}

static void bki_decref(struct silofs_bk_info *bki)
{
	ce_decref_atomic(bki_to_ce(bki));
}

void silofs_bki_decref(struct silofs_bk_info *bki)
{
	if (likely(bki != NULL)) {
		bki_decref(bki);
	}
}

static bool bki_is_evictable(const struct silofs_bk_info *bki)
{
	return ce_is_evictable_atomic(bki_to_ce(bki));
}

static uint64_t bk_view_mask_of(loff_t off, size_t len)
{
	const ssize_t kb_size = SILOFS_KB_SIZE;
	const loff_t  pos = silofs_off_in_bk(off);
	const ssize_t idx = pos / kb_size;
	const ssize_t nkb = (ssize_t)len / kb_size;
	uint64_t mask = 0;

	STATICASSERT_EQ(8 * sizeof(mask), SILOFS_NKB_IN_BK);
	silofs_assert_ge(len, SILOFS_KB_SIZE);
	silofs_assert_le(len, SILOFS_BK_SIZE);

	if ((idx == 0) && (nkb == SILOFS_NKB_IN_BK)) {
		mask = ~mask;
	} else {
		mask = ((1UL << nkb) - 1) << idx;
	}
	return mask;
}

bool silofs_bki_has_view_at(const struct silofs_bk_info *bki,
                            loff_t view_pos, size_t view_len)
{
	const uint64_t view_mask = bk_view_mask_of(view_pos, view_len);

	return ((bki->bk_view & view_mask) == view_mask);
}

void silofs_bki_set_view_at(struct silofs_bk_info *bki,
                            loff_t view_pos, size_t view_len)
{
	const uint64_t view_mask = bk_view_mask_of(view_pos, view_len);

	bki->bk_view |= view_mask;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_ubk_info *
ubki_from_base(const struct silofs_bk_info *bki)
{
	const struct silofs_ubk_info *ubki = NULL;

	if (bki != NULL) {
		ubki = container_of2(bki, struct silofs_ubk_info, ubk_base);
	}
	return unconst(ubki);
}

static struct silofs_ubk_info *
ubki_from_ce(const struct silofs_cache_elem *ce)
{
	const struct silofs_ubk_info *ubki = NULL;

	if (ce != NULL) {
		ubki = ubki_from_base(bki_from_ce(ce));
	}
	return unconst(ubki);
}

static struct silofs_cache_elem *ubki_to_ce(const struct silofs_ubk_info *ubki)
{
	return bki_to_ce(&ubki->ubk_base);
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
	bki_init(&ubki->ubk_base, ubk);
	ubki_set_addr(ubki, bkaddr);
	ubki->ubk_blobf = NULL;
}

static void ubki_fini(struct silofs_ubk_info *ubki)
{
	bki_fini(&ubki->ubk_base);
}

static void ubki_incref(struct silofs_ubk_info *ubki)
{
	bki_incref(&ubki->ubk_base);
}

static void ubki_decref(struct silofs_ubk_info *ubki)
{
	bki_decref(&ubki->ubk_base);
}

static bool ubki_is_evictable(const struct silofs_ubk_info *ubki)
{
	return bki_is_evictable(&ubki->ubk_base);
}

void silofs_ubki_attach(struct silofs_ubk_info *ubki,
                        struct silofs_blobf *blobf)
{
	if (ubki->ubk_blobf == NULL) {
		blobf_incref(blobf);
		ubki->ubk_blobf = blobf;
	}
}

static void ubki_detach(struct silofs_ubk_info *ubki)
{
	struct silofs_blobf *blobf = ubki->ubk_blobf;

	if (blobf != NULL) {
		blobf_decref(blobf);
		ubki->ubk_blobf = NULL;
	}
}

void silofs_ubki_incref(struct silofs_ubk_info *ubki)
{
	if (likely(ubki != NULL)) {
		bki_incref(&ubki->ubk_base);
	}
}

void silofs_ubki_decref(struct silofs_ubk_info *ubki)
{
	if (likely(ubki != NULL)) {
		bki_decref(&ubki->ubk_base);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vbk_info *
vbki_from_base(const struct silofs_bk_info *bki)
{
	const struct silofs_vbk_info *vbki = NULL;

	if (bki != NULL) {
		vbki = container_of2(bki, struct silofs_vbk_info, vbk_base);
	}
	return unconst(vbki);
}

static struct silofs_vbk_info *
vbki_from_ce(const struct silofs_cache_elem *ce)
{
	const struct silofs_vbk_info *vbki = NULL;

	if (ce != NULL) {
		vbki = vbki_from_base(bki_from_ce(ce));
	}
	return unconst(vbki);
}

static struct silofs_cache_elem *vbki_to_ce(const struct silofs_vbk_info *vbki)
{
	return bki_to_ce(&vbki->vbk_base);
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
	bki_init(&vbki->vbk_base, bk);
	vbki_set_vbk_addr(vbki, voff, vspace);
}

static void vbki_fini(struct silofs_vbk_info *vbki)
{
	bki_fini(&vbki->vbk_base);
}

void silofs_vbki_incref(struct silofs_vbk_info *vbki)
{
	if (likely(vbki != NULL)) {
		bki_incref(&vbki->vbk_base);
	}
}

void silofs_vbki_decref(struct silofs_vbk_info *vbki)
{
	if (likely(vbki != NULL)) {
		bki_decref(&vbki->vbk_base);
	}
}

static bool vbki_is_evictable(const struct silofs_vbk_info *vbki)
{
	return bki_is_evictable(&vbki->vbk_base);
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

void silofs_si_incref(struct silofs_snode_info *si)
{
	if (likely(si != NULL)) {
		si_incref(si);
	}
}

void silofs_si_decref(struct silofs_snode_info *si)
{
	if (likely(si != NULL)) {
		si_decref(si);
	}
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
	silofs_snode_del_fn del = si->s_del_hook;

	del(si, alloc);
}

static int visit_evictable_ti(struct silofs_cache_elem *ce, void *arg)
{
	struct silofs_cache_ctx *c_ctx = arg;
	struct silofs_snode_info *si = si_from_ce(ce);

	c_ctx->count++;
	if (silofs_test_evictable(si)) {
		c_ctx->si = si; /* found candidate for eviction */
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
	return silofs_test_evictable(&ui->u_si);
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

int silofs_vi_refcnt(const struct silofs_vnode_info *vi)
{
	return likely(vi != NULL) ? ce_refcnt(vi_to_ce(vi)) : 0;
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
	return silofs_test_evictable(&vi->v_si);
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

static void dqs_init(struct silofs_dirtyqs *dqs)
{
	dqs->dq_accum_nbytes_total = 0;
	for (size_t i = 0; i < ARRAY_SIZE(dqs->dq); ++i) {
		dq_init(&dqs->dq[i]);
	}
}

static void dqs_fini(struct silofs_dirtyqs *dqs)
{
	for (size_t i = 0; i < ARRAY_SIZE(dqs->dq); ++i) {
		dq_fini(&dqs->dq[i]);
	}
}

static const struct silofs_dirtyq *
dqs_dirtyq_of(const struct silofs_dirtyqs *dqs, silofs_dqid_t dqid)
{
	const size_t nqs = ARRAY_SIZE(dqs->dq);
	size_t qidx = 0;

	if ((dqid > 0) && (nqs > 1)) {
		qidx = (dqid % (nqs - 1)) + 1;
	}
	return &dqs->dq[qidx];
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_dirtyq *
cache_dirtyq_of(const struct silofs_cache *cache, silofs_dqid_t dqid)
{
	const struct silofs_dirtyq *dq = dqs_dirtyq_of(&cache->c_dqs, dqid);

	return unconst(dq);
}

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
	struct silofs_dirtyq *dq;
	size_t nb;

	if (!si->s_ce.ce_dirty) {
		nb = stype_size(si->s_stype);
		dq = cache_dirtyq_of(cache, si->s_dqid);
		dq_append(dq, &si->s_dq_lh, nb);
		cache->c_dqs.dq_accum_nbytes_total += nb;
		si->s_ce.ce_dirty = true;
	}
}

static void cache_dq_dec_si(struct silofs_cache *cache,
                            struct silofs_snode_info *si)
{
	struct silofs_dirtyq *dq;
	size_t nb;

	if (si->s_ce.ce_dirty) {
		nb = stype_size(si->s_stype);
		silofs_assert_ge(cache->c_dqs.dq_accum_nbytes_total, nb);
		dq = cache_dirtyq_of(cache, si->s_dqid);
		dq_remove(dq, &si->s_dq_lh, nb);
		cache->c_dqs.dq_accum_nbytes_total -= nb;
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
cache_dq_front_si(const struct silofs_cache *cache, silofs_dqid_t dqid)
{
	const struct silofs_dirtyq *dq = cache_dirtyq_of(cache, dqid);

	return dq_lh_to_si(dq_front(dq));
}

static struct silofs_snode_info *
cache_dq_next_si(const struct silofs_cache *cache,
                 const struct silofs_snode_info *si)
{
	const struct silofs_dirtyq *dq = cache_dirtyq_of(cache, si->s_dqid);

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

static struct silofs_blobf *
cache_new_blobf(struct silofs_cache *cache, const struct silofs_blobid *blobid)
{
	return silofs_blobf_new(cache->c_alloc, blobid);
}

static void cache_del_blobf(const struct silofs_cache *cache,
                            struct silofs_blobf *blobf)
{
	silofs_blobf_del(blobf, cache->c_alloc);
}

static int cache_init_blobf_lm(struct silofs_cache *cache, size_t cap)
{
	return lrumap_init(&cache->c_blobf_lm, cache->c_alloc, cap);
}

static void cache_fini_blobf_lm(struct silofs_cache *cache)
{
	lrumap_fini(&cache->c_blobf_lm, cache->c_alloc);
}

static struct silofs_blobf *
cache_find_blobf(const struct silofs_cache *cache,
                 const struct silofs_blobid *blobid)
{
	struct silofs_ckey ckey;
	struct silofs_cache_elem *ce;

	silofs_ckey_by_blobid(&ckey, blobid);
	ce = lrumap_find(&cache->c_blobf_lm, &ckey);
	return blobf_from_ce(ce);
}

static void cache_store_blobf(struct silofs_cache *cache,
                              struct silofs_blobf *blobf)
{
	lrumap_store(&cache->c_blobf_lm, blobf_to_ce(blobf));
}

static void cache_promote_lru_blobf(struct silofs_cache *cache,
                                    struct silofs_blobf *blobf, bool now)
{
	lrumap_promote_lru(&cache->c_blobf_lm, blobf_to_ce(blobf), now);
}

static void cache_evict_blobf(struct silofs_cache *cache,
                              struct silofs_blobf *blobf)
{
	silofs_assert(ce_is_evictable(blobf_to_ce(blobf)));

	lrumap_remove(&cache->c_blobf_lm, blobf_to_ce(blobf));
	cache_del_blobf(cache, blobf);
}

static struct silofs_blobf *
cache_spawn_blobf(struct silofs_cache *cache,
                  const struct silofs_blobid *blobid)
{
	struct silofs_blobf *blobf;

	blobf = cache_new_blobf(cache, blobid);
	if (blobf == NULL) {
		return NULL;
	}
	cache_store_blobf(cache, blobf);
	return blobf;
}

static struct silofs_blobf *
cache_find_relru_blobf(struct silofs_cache *cache,
                       const struct silofs_blobid *blobid)
{
	struct silofs_blobf *blobf;

	blobf = cache_find_blobf(cache, blobid);
	if (blobf != NULL) {
		cache_promote_lru_blobf(cache, blobf, false);
	}
	return blobf;
}

struct silofs_blobf *
silofs_cache_lookup_blob(struct silofs_cache *cache,
                         const struct silofs_blobid *blobid)
{
	struct silofs_blobf *blobf;

	cache_pre_op(cache);
	blobf = cache_find_relru_blobf(cache, blobid);
	cache_post_op(cache);
	return blobf;
}

static struct silofs_blobf *
cache_find_or_spawn_blobf(struct silofs_cache *cache,
                          const struct silofs_blobid *blobid)
{
	struct silofs_blobf *blobf;

	blobf = cache_find_relru_blobf(cache, blobid);
	if (blobf != NULL) {
		return blobf;
	}
	blobf = cache_spawn_blobf(cache, blobid);
	if (blobf == NULL) {
		return NULL; /* TODO: debug-trace */
	}
	return blobf;
}

static int visit_evictable_blobf(struct silofs_cache_elem *ce, void *arg)
{
	struct silofs_cache_ctx *c_ctx = arg;
	struct silofs_blobf *blobf = blobf_from_ce(ce);

	c_ctx->count++;
	if (blobf_is_evictable(blobf)) {
		c_ctx->blobf = blobf;
		return 1;
	}
	if (c_ctx->count >= c_ctx->limit) {
		return 1;
	}
	return 0;
}

static struct silofs_blobf *
cache_find_evictable_blobf(struct silofs_cache *cache)
{
	struct silofs_cache_ctx c_ctx = {
		.cache = cache,
		.blobf = NULL,
		.limit = 4
	};

	lrumap_foreach_backward(&cache->c_blobf_lm,
	                        visit_evictable_blobf, &c_ctx);
	return c_ctx.blobf;
}

static struct silofs_blobf *
cache_require_blobf(struct silofs_cache *cache,
                    const struct silofs_blobid *blobid)
{
	struct silofs_blobf *blobf = NULL;
	int retry = CACHE_RETRY;

	while (retry-- > 0) {
		blobf = cache_find_or_spawn_blobf(cache, blobid);
		if (blobid != NULL) {
			break;
		}
		cache_evict_some(cache);
	}
	return blobf;
}

struct silofs_blobf *
silofs_cache_spawn_blob(struct silofs_cache *cache,
                        const struct silofs_blobid *blobid)
{
	struct silofs_blobf *blobf;

	cache_pre_op(cache);
	blobf = cache_require_blobf(cache, blobid);
	cache_post_op(cache);
	return blobf;
}


static void cache_try_evict_blobf(struct silofs_cache *cache,
                                  struct silofs_blobf *blobf)
{
	if (blobf_is_evictable(blobf)) {
		cache_evict_blobf(cache, blobf);
	}
}

static void cache_evict_blob(struct silofs_cache *cache,
                             struct silofs_blobf *blobf, bool now)
{
	if (now) {
		cache_evict_blobf(cache, blobf);
	} else {
		cache_try_evict_blobf(cache, blobf);
	}
}

void silofs_cache_evict_blob(struct silofs_cache *cache,
                             struct silofs_blobf *blobf, bool now)
{
	cache_pre_op(cache);
	cache_evict_blob(cache, blobf, now);
	cache_post_op(cache);
}

static struct silofs_blobf *
cache_get_lru_blobf(struct silofs_cache *cache)
{
	struct silofs_cache_elem *ce;

	ce = lrumap_get_lru(&cache->c_blobf_lm);
	return blobf_from_ce(ce);
}

static int try_evict_blobf(struct silofs_cache_elem *ce, void *arg)
{
	struct silofs_cache_ctx *c_ctx = arg;
	struct silofs_blobf *blobf = blobf_from_ce(ce);

	cache_try_evict_blobf(c_ctx->cache, blobf);
	return 0;
}

static void cache_drop_evictable_blobfs(struct silofs_cache *cache)
{
	struct silofs_cache_ctx c_ctx = {
		.cache = cache
	};

	lrumap_foreach_backward(&cache->c_blobf_lm, try_evict_blobf, &c_ctx);
}

static bool cache_evict_or_relru_blobf(struct silofs_cache *cache,
                                       struct silofs_blobf *blobf)
{
	bool evicted;

	if (blobf_is_evictable(blobf)) {
		cache_evict_blobf(cache, blobf);
		evicted = true;
	} else {
		cache_promote_lru_blobf(cache, blobf, true);
		evicted = false;
	}
	return evicted;
}

static size_t
cache_shrink_or_relru_blobfs(struct silofs_cache *cache,
                             size_t cnt, bool force)
{
	struct silofs_blobf *blobf;
	const size_t n = min(cnt, cache->c_blobf_lm.lm_lru.sz);
	size_t evicted = 0;
	bool ok;

	for (size_t i = 0; i < n; ++i) {
		blobf = cache_get_lru_blobf(cache);
		if (blobf == NULL) {
			break;
		}
		ok = cache_evict_or_relru_blobf(cache, blobf);
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
	const size_t cur = cache->c_blobf_lm.lm_lru.sz;

	return (cur > bar) ? (cur - bar) : 0;
}

static bool cache_blobs_has_overflow(const struct silofs_cache *cache)
{
	return cache_blobs_overflow(cache) > 0;
}

void silofs_cache_relax_blobs(struct silofs_cache *cache)
{
	const size_t cnt = cache_blobs_overflow(cache);

	if (cnt > 0) {
		cache_pre_op(cache);
		cache_shrink_or_relru_blobfs(cache, cnt, true);
		cache_post_op(cache);
	}
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
	struct silofs_block *bk = ubki->ubk_base.bk;
	struct silofs_alloc *alloc = cache->c_alloc;

	ubki_detach(ubki);
	ubki_fini(ubki);
	ubki_free(ubki, alloc);
	bk_free(bk, alloc);
}

static int cache_init_ubki_lm(struct silofs_cache *cache, size_t cap)
{
	return lrumap_init(&cache->c_ubki_lm, cache->c_alloc, cap);
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
                                   struct silofs_ubk_info *ubki, bool now)
{
	lrumap_promote_lru(&cache->c_ubki_lm, ubki_to_ce(ubki), now);
}

static void cache_evict_ubki(struct silofs_cache *cache,
                             struct silofs_ubk_info *ubki)
{
	lrumap_remove(&cache->c_ubki_lm, ubki_to_ce(ubki));
	cache_del_ubki(cache, ubki);
}

static void cache_forget_ubk(struct silofs_cache *cache,
                             struct silofs_ubk_info *ubki)
{
	if (ubki_is_evictable(ubki)) {
		cache_evict_ubki(cache, ubki);
	}
}

void silofs_cache_forget_ubk(struct silofs_cache *cache,
                             struct silofs_ubk_info *ubki)
{
	cache_pre_op(cache);
	cache_forget_ubk(cache, ubki);
	cache_post_op(cache);
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
		cache_promote_lru_ubki(cache, ubki, false);
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
		cache_promote_lru_ubki(cache, ubki, true);
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
	struct silofs_ubk_info *ubki;

	cache_pre_op(cache);
	ubki = cache_find_relru_ubki(cache, bkaddr);
	cache_post_op(cache);
	return ubki;
}

struct silofs_ubk_info *
silofs_cache_spawn_ubk(struct silofs_cache *cache,
                       const struct silofs_bkaddr *bkaddr)
{
	struct silofs_ubk_info *ubki;

	cache_pre_op(cache);
	ubki = cache_require_ubki(cache, bkaddr);
	cache_post_op(cache);
	return ubki;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int cache_init_ui_lm(struct silofs_cache *cache, size_t cap)
{
	return lrumap_init(&cache->c_ui_lm, cache->c_alloc, cap);
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
                                 struct silofs_unode_info *ui, bool now)
{
	lrumap_promote_lru(&cache->c_ui_lm, ui_to_ce(ui), now);
}

static struct silofs_unode_info *
cache_find_relru_ui(struct silofs_cache *cache,
                    const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *ui;

	ui = cache_find_ui(cache, uaddr);
	if (ui != NULL) {
		cache_promote_lru_ui(cache, ui, false);
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
	struct silofs_snode_info *si = &ui->u_si;

	cache_remove_ui(cache, ui);
	ui_detach_bk(ui);
	si_delete(si, cache->c_alloc);
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
	struct silofs_snode_info *si = &ui->u_si;
	bool evicted;

	if (silofs_test_evictable(si)) {
		cache_evict_ui(cache, ui);
		evicted = true;
	} else {
		cache_promote_lru_ui(cache, ui, true);
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

static struct silofs_unode_info *
cache_lookup_ui(struct silofs_cache *cache, const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *ui;

	ui = cache_find_relru_ui(cache, uaddr);
	if (ui != NULL) {
		cache_track_uaddr_of(cache, ui);
	}
	return ui;
}

struct silofs_unode_info *
silofs_cache_lookup_ui(struct silofs_cache *cache,
                       const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *ui;

	cache_pre_op(cache);
	ui = cache_lookup_ui(cache, uaddr);
	cache_post_op(cache);
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

static struct silofs_unode_info *
cache_spawn_ui(struct silofs_cache *cache, const struct silofs_uaddr *uaddr)
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

struct silofs_unode_info *
silofs_cache_spawn_ui(struct silofs_cache *cache,
                      const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *ui;

	cache_pre_op(cache);
	ui = cache_spawn_ui(cache, uaddr);
	cache_post_op(cache);
	return ui;
}

static void
cache_forget_ui(struct silofs_cache *cache, struct silofs_unode_info *ui)
{
	cache_undirtify_ui(cache, ui);
	cache_forget_uaddr(cache, ui_uaddr(ui));
	cache_evict_ui(cache, ui);
}

void silofs_cache_forget_ui(struct silofs_cache *cache,
                            struct silofs_unode_info *ui)
{
	cache_pre_op(cache);
	cache_forget_ui(cache, ui);
	cache_post_op(cache);
}

static struct silofs_unode_info *
cache_find_ui_by(struct silofs_cache *cache, const struct silofs_uakey *uakey)
{
	const struct silofs_uaddr *uaddr;
	struct silofs_unode_info *ui = NULL;

	uaddr = cache_lookup_uaddr_by(cache, uakey);
	if (uaddr != NULL) {
		ui = cache_lookup_ui(cache, uaddr);
	}
	return ui;
}

struct silofs_unode_info *
silofs_cache_find_ui_by(struct silofs_cache *cache,
                        const struct silofs_uakey *uakey)
{
	struct silofs_unode_info *ui;

	cache_pre_op(cache);
	ui = cache_find_ui_by(cache, uakey);
	cache_post_op(cache);
	return ui;
}

void silofs_cache_forget_uaddrs(struct silofs_cache *cache)
{
	cache_pre_op(cache);
	cache_drop_uamap(cache);
	cache_post_op(cache);
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
	struct silofs_block *bk = vbki->vbk_base.bk;

	vbki_fini(vbki);
	bk_free(bk, cache->c_alloc);
	vbki_free(vbki, cache->c_alloc);
}

static int cache_init_vbki_lm(struct silofs_cache *cache, size_t cap)
{
	return lrumap_init(&cache->c_vbki_lm, cache->c_alloc, cap);
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
                                   struct silofs_vbk_info *vbki, bool now)
{
	lrumap_promote_lru(&cache->c_vbki_lm, vbki_to_ce(vbki), now);
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
	cache_pre_op(cache);
	cache_evict_vbki(cache, vbki);
	cache_post_op(cache);
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
		cache_promote_lru_vbki(cache, vbki, false);
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
		cache_promote_lru_vbki(cache, vbki, true);
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
	struct silofs_vbk_info *vbki;

	cache_pre_op(cache);
	vbki = cache_find_relru_vbki(cache, voff, vspace);
	cache_post_op(cache);
	return vbki;
}

struct silofs_vbk_info *
silofs_cache_spawn_vbk(struct silofs_cache *cache,
                       loff_t voff, enum silofs_stype vspace)
{
	struct silofs_vbk_info *vbki;

	cache_pre_op(cache);
	vbki = cache_require_vbki(cache, voff, vspace);
	cache_post_op(cache);
	return vbki;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int cache_init_vi_lm(struct silofs_cache *cache, size_t cap)
{
	return lrumap_init(&cache->c_vi_lm, cache->c_alloc, cap);
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
                                 struct silofs_vnode_info *vi, bool now)
{
	lrumap_promote_lru(&cache->c_vi_lm, vi_to_ce(vi), now);
}

static struct silofs_vnode_info *
cache_find_relru_vi(struct silofs_cache *cache,
                    const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi;

	vi = cache_find_vi(cache, vaddr);
	if (vi != NULL) {
		cache_promote_lru_vi(cache, vi, false);
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
	struct silofs_snode_info *si = &vi->v_si;

	cache_remove_vi(cache, vi);
	vi_detach_bk(vi);
	si_delete(si, cache->c_alloc);
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

	if (silofs_test_evictable(si)) {
		cache_evict_vi(cache, vi);
		evicted = true;
	} else {
		cache_promote_lru_vi(cache, vi, true);
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
silofs_cache_lookup_vi(struct silofs_cache *cache,
                       const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi;

	cache_pre_op(cache);
	vi = cache_find_relru_vi(cache, vaddr);
	cache_post_op(cache);
	return vi;
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

static void cache_forget_vi(struct silofs_cache *cache,
                            struct silofs_vnode_info *vi)
{
	cache_undirtify_vi(cache, vi);
	if (vi_refcnt(vi) > 0) {
		cache_unmap_vi(cache, vi);
		vi->v_si.s_ce.ce_forgot = true;
	} else {
		cache_evict_vi(cache, vi);
	}
}

void silofs_cache_forget_vi(struct silofs_cache *cache,
                            struct silofs_vnode_info *vi)
{
	cache_pre_op(cache);
	cache_forget_vi(cache, vi);
	cache_post_op(cache);
}

static struct silofs_vnode_info *
cache_spawn_vi(struct silofs_cache *cache, const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi;

	vi = cache_require_vi(cache, vaddr);
	if (vi != NULL) {
		si_set_cache(&vi->v_si, cache);
		cache_store_vi(cache, vi);
	}
	return vi;
}

struct silofs_vnode_info *
silofs_cache_spawn_vi(struct silofs_cache *cache,
                      const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi;

	cache_pre_op(cache);
	vi = cache_spawn_vi(cache, vaddr);
	cache_post_op(cache);
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

	count = lrumap_overpop(&cache->c_vbki_lm) + extra;
	actual += cache_shrink_or_relru_vbkis(cache, count, false);

	count = lrumap_overpop(&cache->c_ui_lm) + extra;
	actual += cache_shrink_or_relru_uis(cache, count, false);

	count = lrumap_overpop(&cache->c_ubki_lm) + extra;
	actual += cache_shrink_or_relru_ubkis(cache, count, false);

	count = lrumap_overpop(&cache->c_blobf_lm) + extra;
	actual += cache_shrink_or_relru_blobfs(cache, count, false);

	return actual;
}

static bool cache_lrumaps_has_overpop(const struct silofs_cache *cache)
{
	const struct silofs_lrumap *lms[] = {
		&cache->c_vi_lm,
		&cache->c_ui_lm,
		&cache->c_ubki_lm,
		&cache->c_vbki_lm,
		&cache->c_blobf_lm
	};
	bool has_overpop = false;

	for (size_t i = 0; i < ARRAY_SIZE(lms) && !has_overpop; ++i) {
		has_overpop = (lrumap_overpop(lms[i]) > 0);
	}
	return has_overpop;
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
	uint64_t mem_press;
	size_t niter = 0;

	if (cache_lrumaps_has_overpop(cache)) {
		niter += 1;
	}
	if (cache_blobs_has_overflow(cache)) {
		niter += 1;
	}
	mem_press = cache_memory_pressure(cache);
	if (flags & SILOFS_F_BRINGUP) {
		niter += silofs_popcount64(mem_press >> 3);
	}
	if (flags & SILOFS_F_IDLE) {
		niter += silofs_popcount64(mem_press >> 4);
	}
	if (flags & SILOFS_F_TIMEOUT) {
		niter += min(silofs_popcount64(mem_press >> 8), 1);
	}
	if (flags & (SILOFS_F_OPSTART | SILOFS_F_OPFINISH)) {
		niter += min(silofs_popcount64(mem_press >> 10), 2);
	}
	if (flags & SILOFS_F_NOW) {
		niter += min(silofs_popcount64(mem_press >> 12), 8);
	}
	if (flags & SILOFS_F_WALKFS) {
		niter += (mem_press & 7);
	}
	if (flags & SILOFS_F_URGENT) {
		niter += 4;
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
	size_t niter;

	niter = cache_calc_niter(cache, flags);
	if (niter > 0) {
		cache_relax_niter(cache, niter);
	}
}

void silofs_cache_shrink_once(struct silofs_cache *cache)
{
	const size_t bk_size = SILOFS_BK_SIZE;
	const size_t memsz_ubkis = bk_size * cache->c_ubki_lm.lm_htbl_sz;
	const size_t memsz_data = cache->c_mem_size_hint;

	if ((8 * memsz_ubkis) > memsz_data) {
		cache_pre_op(cache);
		cache_shrink_some(cache, 0);
		cache_post_op(cache);
	}
}

static size_t cache_lrumap_usage_sum(const struct silofs_cache *cache)
{
	return lrumap_usage(&cache->c_blobf_lm) +
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
	cache_drop_evictable_blobfs(cache);
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

static bool dqid_specific(silofs_dqid_t dqid)
{
	return (dqid != SILOFS_DQID_DFL) && (dqid != SILOFS_DQID_ALL);
}

static size_t flush_threshold_of(silofs_dqid_t dqid, int flags)
{
	size_t threshold;
	const size_t mega = SILOFS_UMEGA;
	const size_t factor = dqid_specific(dqid) ? 8 : 1;

	if (flags & SILOFS_F_NOW) {
		threshold = 0;
	} else if (flags & SILOFS_F_RELEASE) {
		threshold = mega;
	} else if (flags & SILOFS_F_FSYNC) {
		threshold = 2 * mega;
	} else if (flags & (SILOFS_F_IDLE)) {
		threshold = 8 * mega;
	} else if (flags & SILOFS_F_TIMEOUT) {
		threshold = 16 * mega;
	} else if (flags & (SILOFS_F_OPSTART | SILOFS_F_OPFINISH)) {
		threshold = 32 * mega;
	} else {
		threshold = 64 * mega;
	}
	return threshold / factor;
}

static size_t
cache_accum_ndirty_of(const struct silofs_cache *cache, silofs_dqid_t dqid)
{
	const struct silofs_dirtyq *dq = NULL;
	size_t accum_ndirty;

	if (dqid == SILOFS_DQID_ALL) {
		accum_ndirty = cache->c_dqs.dq_accum_nbytes_total;
	} else {
		dq = cache_dirtyq_of(cache, dqid);
		accum_ndirty = dq->dq_accum_nbytes;
	}
	return accum_ndirty;
}

size_t silofs_cache_accum_ndirty(const struct silofs_cache *cache)
{
	return cache->c_dqs.dq_accum_nbytes_total;
}

static bool cache_dq_need_flush(const struct silofs_cache *cache,
                                silofs_dqid_t dqid, int flags)
{
	const size_t mega = SILOFS_MEGA;
	size_t threshold = 0;
	size_t accum_ndirty;

	accum_ndirty = silofs_cache_accum_ndirty(cache);
	if (accum_ndirty > (8 * mega)) {
		return true;
	}
	accum_ndirty = cache_accum_ndirty_of(cache, dqid);
	if (!accum_ndirty) {
		return false;
	}
	threshold = flush_threshold_of(dqid, flags);
	if (accum_ndirty > threshold) {
		return true;
	}
	return false;
}

static bool cache_mem_press_need_flush(const struct silofs_cache *cache)
{
	const uint64_t mem_press_mask = cache_memory_pressure(cache);
	const uint32_t mem_press_level = silofs_popcount64(mem_press_mask);

	return (mem_press_level > 18);
}

bool silofs_cache_need_flush(const struct silofs_cache *cache,
                             silofs_dqid_t dqid, int flags)
{
	if (cache_blobs_overflow(cache)) {
		return true;
	}
	if (cache_dq_need_flush(cache, dqid, flags)) {
		return true;
	}
	if (cache_mem_press_need_flush(cache)) {
		return true;
	}
	return false;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool cache_evict_by_blobf(struct silofs_cache *cache,
                                 struct silofs_blobf *blobf)
{
	bool ret = false;

	if ((blobf != NULL) && blobf_is_evictable(blobf)) {
		cache_evict_blobf(cache, blobf);
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
	struct silofs_blobf *blobf = NULL;
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
	blobf = cache_find_evictable_blobf(cache);
	if (cache_evict_by_blobf(cache, blobf)) {
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

static void cache_fini_lrumaps(struct silofs_cache *cache)
{
	cache_fini_vi_lm(cache);
	cache_fini_ui_lm(cache);
	cache_fini_vbki_lm(cache);
	cache_fini_ubki_lm(cache);
	cache_fini_blobf_lm(cache);
}

static size_t cache_calc_htbl_cap(const struct silofs_cache *cache)
{
	const size_t mem_size = cache->c_mem_size_hint;
	const size_t cap_max = mem_size / sizeof(struct silofs_list_head);

	return silofs_max(cap_max / 256, 8192);
}

static int cache_init_lrumaps(struct silofs_cache *cache)
{
	const size_t cap = cache_calc_htbl_cap(cache);
	int err;

	err = cache_init_blobf_lm(cache, htbl_cap_as_prime(cap));
	if (err) {
		goto out_err;
	}
	err = cache_init_ubki_lm(cache, cap);
	if (err) {
		goto out_err;
	}
	err = cache_init_vbki_lm(cache, cap);
	if (err) {
		goto out_err;
	}
	err = cache_init_ui_lm(cache, cap);
	if (err) {
		goto out_err;
	}
	err = cache_init_vi_lm(cache, cap);
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
	cache->c_mem_size_hint = msz_hint;
	dqs_init(&cache->c_dqs);
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
	dqs_fini(&cache->c_dqs);
	cache_fini_lrumaps(cache);
	cache_fini_nil_bk(cache);
	cache_fini_uamap(cache);
	cache_fini_spamaps(cache);
	cache_fini_mdigest(cache);
	cache->c_alloc = NULL;
}

static void cache_pre_op(struct silofs_cache *cache)
{
	silofs_unused(cache);
}

static void cache_post_op(struct silofs_cache *cache)
{
	silofs_unused(cache);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_vi_dirtify(struct silofs_vnode_info *vi)
{
	if (likely(vi != NULL)) {
		cache_dirtify_vi(vi_cache(vi), vi);
	}
}

static void vi_undirtify(struct silofs_vnode_info *vi)
{
	cache_undirtify_vi(vi_cache(vi), vi);
}

void silofs_ii_dirtify(struct silofs_inode_info *ii)
{
	if (likely(ii != NULL)) {
		silofs_assert_gt(ii->i_vi.v_si.s_dqid, 0);
		silofs_vi_dirtify(ii_to_vi(ii));
	}
}

void silofs_ii_undirtify(struct silofs_inode_info *ii)
{
	if (likely(ii != NULL)) {
		vi_undirtify(ii_to_vi(ii));
	}
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_dset *
dset_of(struct silofs_dsets *dsets, enum silofs_stype stype)
{
	const size_t idx = (size_t)stype;

	return likely(idx < ARRAY_SIZE(dsets->dset)) ?
	       &dsets->dset[idx] : NULL;
}


static void
cache_fill_into_dsets_by(const struct silofs_cache *cache,
                         struct silofs_dsets *dsets, silofs_dqid_t dqid)
{
	struct silofs_dset *dset;
	struct silofs_snode_info *si = NULL;

	si = cache_dq_front_si(cache, dqid);
	while (si != NULL) {
		if (!si->s_noflush) {
			dset = dset_of(dsets, si->s_stype);
			if (likely(dset != NULL)) {
				dset->ds_add_fn(dset, si);
			}
		}
		si = cache_dq_next_si(cache, si);
	}
}

static void
cache_fill_into_dsets(const struct silofs_cache *cache,
                      struct silofs_dsets *dsets, silofs_dqid_t dqid)
{
	if (dqid == SILOFS_DQID_ALL) {
		for (size_t i = 0; i < ARRAY_SIZE(cache->c_dqs.dq); ++i) {
			cache_fill_into_dsets_by(cache, dsets, i);
		}
	} else if (dqid == SILOFS_DQID_DFL) {
		cache_fill_into_dsets_by(cache, dsets, SILOFS_DQID_DFL);
	} else {
		cache_fill_into_dsets_by(cache, dsets, dqid);
		cache_fill_into_dsets_by(cache, dsets, SILOFS_DQID_DFL);
	}
}

void silofs_cache_fill_dsets(struct silofs_cache *cache,
                             struct silofs_dsets *dsets,
                             silofs_dqid_t dqid)
{
	cache_pre_op(cache);
	cache_fill_into_dsets(cache, dsets, dqid);
	cache_post_op(cache);
}

static void cache_undirtify_by_dset(struct silofs_cache *cache,
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

void silofs_cache_undirtify_by_dset(struct silofs_cache *cache,
                                    const struct silofs_dset *dset)
{
	cache_pre_op(cache);
	cache_undirtify_by_dset(cache, dset);
	cache_post_op(cache);
}
