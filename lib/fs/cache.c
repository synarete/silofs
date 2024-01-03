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
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/fs.h>
#include <silofs/fs-private.h>
#include <limits.h>

#define LME_MAGIC       (0xDEFEC8EDBADDCAFE)
#define LRUMAP_ALL      (UINT32_MAX)
#define CACHE_RETRY     (4)


static void vi_do_undirtify(struct silofs_vnode_info *vi);
static void cache_post_op(struct silofs_cache *cache);
static void cache_drop_uamap(struct silofs_cache *cache);
static void cache_evict_some(struct silofs_cache *cache);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* prime-value for hash-table of n-elements */
static const unsigned int hcap_primes[] = {
	13, 53, 97, 193, 389, 769, 1543, 3079, 4093, 6151, 8191, 12289, 16381,
	24593, 32749, 49157, 65521, 98317, 131071, 147377, 196613, 294979,
	393241, 589933, 786433, 1572869, 3145739, 6291469, 12582917, 25165843,
	50331653, 100663319, 201326611, 402653189, 805306457, 1610612741,
	3221225473, 4294967291
};

static size_t htbl_cap_as_prime(size_t lim)
{
	size_t p = 11;

	for (size_t i = 0; i < ARRAY_SIZE(hcap_primes); ++i) {
		if (hcap_primes[i] > lim) {
			break;
		}
		p = hcap_primes[i];
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

static struct silofs_lblock *lbk_malloc(struct silofs_alloc *alloc, int flags)
{
	struct silofs_lblock *lbk;

	lbk = silofs_allocate(alloc, sizeof(*lbk), flags);
	return lbk;
}

static void lbk_free(struct silofs_lblock *lbk,
                     struct silofs_alloc *alloc, int flags)
{
	silofs_deallocate(alloc, lbk, sizeof(*lbk), flags);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint64_t hash_of_lsegid(const struct silofs_lsegid *lsegid)
{
	return silofs_lsegid_hash64(lsegid);
}

static uint64_t hash_of_vaddr(const struct silofs_vaddr *vaddr)
{
	const uint64_t off = (uint64_t)(vaddr->off);
	const uint64_t lz = silofs_clz64(off);
	uint64_t hval;

	hval = off;
	hval ^= (0x5D21C111ULL / (lz + 1)); /* M77232917 */
	hval ^= ((uint64_t)(vaddr->ltype) << 43);
	return twang_mix64(hval);
}

static uint64_t hash_of_uaddr(const struct silofs_uaddr *uaddr)
{
	uint64_t d[4];
	uint64_t seed;

	d[0] = hash_of_lsegid(&uaddr->laddr.lsegid);
	d[1] = uaddr->laddr.len;
	d[2] = 0x736f6d6570736575ULL - (uint64_t)(uaddr->laddr.pos);
	d[3] = (uint64_t)uaddr->voff;
	seed = 0x646f72616e646f6dULL / (uaddr->ltype + 1);

	return silofs_hash_xxh64(d, sizeof(d), seed);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void hkey_setup(struct silofs_hkey *hkey,
                       enum silofs_hkey_type type,
                       const void *key, unsigned long hash)
{
	hkey->keyu.key = key;
	hkey->hash = hash;
	hkey->type = type;
}

static void hkey_reset(struct silofs_hkey *hkey)
{
	hkey->keyu.key = NULL;
	hkey->hash = 0;
	hkey->type = SILOFS_HKEY_NONE;
}

static long hkey_compare_as_uaddr(const struct silofs_hkey *hkey1,
                                  const struct silofs_hkey *hkey2)
{
	return silofs_uaddr_compare(hkey1->keyu.uaddr, hkey2->keyu.uaddr);
}

static long hkey_compare_as_vaddr(const struct silofs_hkey *hkey1,
                                  const struct silofs_hkey *hkey2)
{
	return silofs_vaddr_compare(hkey1->keyu.vaddr, hkey2->keyu.vaddr);
}

long silofs_hkey_compare(const struct silofs_hkey *hkey1,
                         const struct silofs_hkey *hkey2)
{
	long cmp;

	cmp = (long)hkey2->type - (long)hkey1->type;
	if (cmp == 0) {
		switch (hkey1->type) {
		case SILOFS_HKEY_UADDR:
			cmp = hkey_compare_as_uaddr(hkey1, hkey2);
			break;
		case SILOFS_HKEY_VADDR:
			cmp = hkey_compare_as_vaddr(hkey1, hkey2);
			break;
		case SILOFS_HKEY_NONE:
		default:
			break;
		}
	}
	return cmp;
}

static bool hkey_isequal(const struct silofs_hkey *hkey1,
                         const struct silofs_hkey *hkey2)
{
	return (hkey1->type == hkey2->type) &&
	       (hkey1->hash == hkey2->hash) &&
	       !silofs_hkey_compare(hkey1, hkey2);
}

static void hkey_by_uaddr(struct silofs_hkey *hkey,
                          const struct silofs_uaddr *uaddr)
{
	hkey_setup(hkey, SILOFS_HKEY_UADDR, uaddr, hash_of_uaddr(uaddr));
}

static void hkey_by_vaddr(struct silofs_hkey *hkey,
                          const struct silofs_vaddr *vaddr)
{
	hkey_setup(hkey, SILOFS_HKEY_VADDR, vaddr, hash_of_vaddr(vaddr));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_lrumap_elem *
lme_from_htb_link(const struct silofs_list_head *lh)
{
	const struct silofs_lrumap_elem *lme;

	lme = container_of2(lh, struct silofs_lrumap_elem, lme_htb_lh);
	silofs_assert_eq(lme->lme_magic, LME_MAGIC);
	return unconst(lme);
}

static struct silofs_lrumap_elem *
lme_from_lru_link(const struct silofs_list_head *lh)
{
	const struct silofs_lrumap_elem *lme;

	lme = container_of2(lh, struct silofs_lrumap_elem, lme_lru_lh);
	silofs_assert_eq(lme->lme_magic, LME_MAGIC);
	return unconst(lme);
}

void silofs_lme_init(struct silofs_lrumap_elem *lme)
{
	hkey_reset(&lme->lme_key);
	list_head_init(&lme->lme_htb_lh);
	list_head_init(&lme->lme_lru_lh);
	lme->lme_magic = LME_MAGIC;
	lme->lme_refcnt = 0;
	lme->lme_htb_hitcnt = 0;
	lme->lme_lru_hitcnt = 0;
	lme->lme_dirty = false;
	lme->lme_mapped = false;
	lme->lme_forgot = false;
}

void silofs_lme_fini(struct silofs_lrumap_elem *lme)
{
	silofs_assert_eq(lme->lme_refcnt, 0);
	silofs_assert_eq(lme->lme_magic, LME_MAGIC);

	hkey_reset(&lme->lme_key);
	list_head_fini(&lme->lme_htb_lh);
	list_head_fini(&lme->lme_lru_lh);
	lme->lme_refcnt = INT_MIN;
	lme->lme_htb_hitcnt = -1;
	lme->lme_lru_hitcnt = -1;
	lme->lme_magic = ULONG_MAX;
}

static void lme_set_forgot(struct silofs_lrumap_elem *lme, bool forgot)
{
	lme->lme_forgot = forgot;
}

static void lme_hmap(struct silofs_lrumap_elem *lme,
                     struct silofs_list_head *hlst)
{
	list_push_front(hlst, &lme->lme_htb_lh);
	lme->lme_mapped = true;
}

static void lme_hunmap(struct silofs_lrumap_elem *lme)
{
	list_head_remove(&lme->lme_htb_lh);
	lme->lme_mapped = false;
}

static bool lme_need_promote_hmap(const struct silofs_lrumap_elem *lme,
                                  const struct silofs_list_head *hlst)
{
	const struct silofs_list_head *hlnk = &lme->lme_htb_lh;
	const struct silofs_list_head *next = hlst->next;
	const struct silofs_lrumap_elem *lme_next = NULL;
	bool ret = false;

	if ((next != hlnk) && (next->next != hlnk)) {
		lme_next = lme_from_htb_link(next);
		ret = (lme->lme_htb_hitcnt > (lme_next->lme_htb_hitcnt + 2));
	}
	return ret;
}

static void lme_promote_hmap(struct silofs_lrumap_elem *lme,
                             struct silofs_list_head *hlst)
{
	struct silofs_list_head *hlnk = &lme->lme_htb_lh;

	silofs_assert(lme->lme_mapped);

	list_head_remove(hlnk);
	list_push_front(hlst, hlnk);
}

static struct silofs_list_head *
lme_lru_link(struct silofs_lrumap_elem *lme)
{
	return &lme->lme_lru_lh;
}

static const struct silofs_list_head *
lme_lru_link2(const struct silofs_lrumap_elem *lme)
{
	return &lme->lme_lru_lh;
}

static void lme_lru(struct silofs_lrumap_elem *lme, struct silofs_listq *lru)
{
	listq_push_front(lru, lme_lru_link(lme));
}

static void lme_unlru(struct silofs_lrumap_elem *lme, struct silofs_listq *lru)
{
	listq_remove(lru, lme_lru_link(lme));
}

static bool lme_is_lru_front(const struct silofs_lrumap_elem *lme,
                             const struct silofs_listq *lru)
{
	const struct silofs_list_head *lru_front = listq_front(lru);
	const struct silofs_list_head *lme_lru_lnk = lme_lru_link2(lme);

	return (lru_front == lme_lru_lnk);
}

static bool lme_need_relru(const struct silofs_lrumap_elem *lme,
                           const struct silofs_listq *lru)
{
	const struct silofs_list_head *lru_front = listq_front(lru);
	const struct silofs_list_head *lme_lru_lnk = lme_lru_link2(lme);

	if (unlikely(lru_front == NULL)) {
		return false; /* make clang-scan happy */
	}
	if (lru_front == lme_lru_lnk) {
		return false; /* already first */
	}
	if (lru_front->next == lme_lru_lnk) {
		return false; /* second in line */
	}
	if (lru->sz < 16) {
		return false; /* don't bother in case of small LRU */
	}
	if (lme->lme_lru_hitcnt < 4) {
		return false; /* low hit count */
	}
	return true;
}

static void lme_relru(struct silofs_lrumap_elem *lme, struct silofs_listq *lru)
{
	lme_unlru(lme, lru);
	lme_lru(lme, lru);
}

static bool lme_is_dirty(const struct silofs_lrumap_elem *lme)
{
	return lme->lme_dirty;
}

static void lme_set_dirty(struct silofs_lrumap_elem *lme, bool dirty)
{
	lme->lme_dirty = dirty;
}

static int lme_refcnt_atomic(const struct silofs_lrumap_elem *lme)
{
	silofs_assert_ge(lme->lme_refcnt, 0);
	return silofs_atomic_get(&lme->lme_refcnt);
}

static void lme_incref_atomic(struct silofs_lrumap_elem *lme)
{
	silofs_atomic_add(&lme->lme_refcnt, 1);
}

static void lme_decref_atomic(struct silofs_lrumap_elem *lme)
{
	silofs_atomic_sub(&lme->lme_refcnt, 1);
}

static bool lme_is_evictable_atomic(const struct silofs_lrumap_elem *lme)
{
	return !lme_is_dirty(lme) && !lme_refcnt_atomic(lme);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int lrumap_init(struct silofs_lrumap *lrumap,
                       struct silofs_alloc *alloc, size_t cap)
{
	struct silofs_list_head *htbl;

	htbl = silofs_lista_new(alloc, cap);
	if (htbl == NULL) {
		return -SILOFS_ENOMEM;
	}
	listq_init(&lrumap->lm_lru);
	lrumap->lm_htbl = htbl;
	lrumap->lm_htbl_cap = cap;
	lrumap->lm_htbl_sz = 0;
	return 0;
}

static void lrumap_fini(struct silofs_lrumap *lrumap,
                        struct silofs_alloc *alloc)
{
	if (lrumap->lm_htbl != NULL) {
		silofs_lista_del(lrumap->lm_htbl, lrumap->lm_htbl_cap, alloc);
		listq_fini(&lrumap->lm_lru);
		lrumap->lm_htbl = NULL;
		lrumap->lm_htbl_cap = 0;
	}
}

static size_t lrumap_usage(const struct silofs_lrumap *lrumap)
{
	return lrumap->lm_htbl_sz;
}

static size_t lrumap_key_to_slot(const struct silofs_lrumap *lrumap,
                                 const struct silofs_hkey *hkey)
{
	const uint64_t hval = hkey->hash ^ (hkey->hash >> 32);

	return hval % lrumap->lm_htbl_cap;
}

static struct silofs_list_head *
lrumap_hlist_of(const struct silofs_lrumap *lrumap,
                const struct silofs_hkey *hkey)
{
	const size_t slot = lrumap_key_to_slot(lrumap, hkey);

	return &lrumap->lm_htbl[slot];
}

static void lrumap_store(struct silofs_lrumap *lrumap,
                         struct silofs_lrumap_elem *lme)
{
	struct silofs_listq *lru = &lrumap->lm_lru;
	struct silofs_list_head *hlst = lrumap_hlist_of(lrumap, &lme->lme_key);

	lme_lru(lme, lru);
	lme_hmap(lme, hlst);
	lrumap->lm_htbl_sz += 1;
}

static struct silofs_lrumap_elem *
lrumap_find(const struct silofs_lrumap *lrumap, const struct silofs_hkey *hkey)
{
	const struct silofs_list_head *hlst;
	const struct silofs_list_head *itr;
	const struct silofs_lrumap_elem *lme;

	hlst = lrumap_hlist_of(lrumap, hkey);
	itr = hlst->next;
	while (itr != hlst) {
		lme = lme_from_htb_link(itr);
		if (hkey_isequal(&lme->lme_key, hkey)) {
			return unconst(lme);
		}
		itr = itr->next;
	}
	return NULL;
}

static void lrumap_unmap(struct silofs_lrumap *lrumap,
                         struct silofs_lrumap_elem *lme)
{
	lme_hunmap(lme);
	lrumap->lm_htbl_sz -= 1;
}

static void lrumap_unlru(struct silofs_lrumap *lrumap,
                         struct silofs_lrumap_elem *lme)
{
	lme_unlru(lme, &lrumap->lm_lru);
}

static void lrumap_remove(struct silofs_lrumap *lrumap,
                          struct silofs_lrumap_elem *lme)
{
	lrumap_unmap(lrumap, lme);
	lrumap_unlru(lrumap, lme);
}

static void lrumap_promote_lru(struct silofs_lrumap *lrumap,
                               struct silofs_lrumap_elem *lme, bool now)
{
	struct silofs_listq *lru = &lrumap->lm_lru;
	const bool first = lme_is_lru_front(lme, lru);

	lme->lme_lru_hitcnt++;
	if (!first && (now || lme_need_relru(lme, lru))) {
		lme_relru(lme, &lrumap->lm_lru);
		lme->lme_lru_hitcnt = 0;
	}
}

static void lrumap_promote_hlnk(struct silofs_lrumap *lrumap,
                                struct silofs_lrumap_elem *lme, bool lookup)
{
	struct silofs_list_head *hlst = lrumap_hlist_of(lrumap, &lme->lme_key);

	lme->lme_htb_hitcnt++;
	if (lookup && lme_need_promote_hmap(lme, hlst)) {
		lme_promote_hmap(lme, hlst);
	}
}

static void lrumap_promote(struct silofs_lrumap *lrumap,
                           struct silofs_lrumap_elem *lme, bool now)
{
	lrumap_promote_lru(lrumap, lme, now);
	lrumap_promote_hlnk(lrumap, lme, !now);
}

static struct silofs_lrumap_elem *
lrumap_get_lru(const struct silofs_lrumap *lrumap)
{
	struct silofs_lrumap_elem *lme = NULL;

	if (lrumap->lm_lru.sz > 0) {
		lme = lme_from_lru_link(lrumap->lm_lru.ls.prev);
	}
	return lme;
}

typedef int (*silofs_lrumap_elem_fn)(struct silofs_lrumap_elem *, void *);

static void lrumap_riterate(struct silofs_lrumap *lrumap, size_t limit,
                            silofs_lrumap_elem_fn cb, void *arg)
{
	struct silofs_list_head *itr = NULL;
	struct silofs_lrumap_elem *lme = NULL;
	struct silofs_listq *lru = &lrumap->lm_lru;
	size_t count = min(limit, lru->sz);
	int ret = 0;

	itr = lru->ls.prev; /* backward iteration */
	while (!ret && count-- && (itr != &lru->ls)) {
		lme = lme_from_lru_link(itr);
		itr = itr->prev;
		ret = cb(lme, arg);
	}
}

static size_t lrumap_overpop(const struct silofs_lrumap *lrumap)
{
	const size_t fac = 4;
	size_t ovp = 0;

	if (lrumap->lm_htbl_sz > (fac * lrumap->lm_htbl_cap)) {
		ovp = (lrumap->lm_htbl_sz - (fac * lrumap->lm_htbl_cap));
	} else if (lrumap->lm_lru.sz > (fac * lrumap->lm_htbl_sz)) {
		ovp = (lrumap->lm_lru.sz - (fac * lrumap->lm_htbl_sz));
	}
	return ovp;
}

static size_t
lrumap_calc_search_evictable_max(const struct silofs_lrumap *lrumap)
{
	return clamp(lrumap->lm_htbl_sz / 4, 1, 16);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_dirtyq_init(struct silofs_dirtyq *dq)
{
	listq_init(&dq->dq);
	dq->dq_accum = 0;
}

void silofs_dirtyq_fini(struct silofs_dirtyq *dq)
{
	listq_fini(&dq->dq);
	dq->dq_accum = 0;
}

void silofs_dirtyq_append(struct silofs_dirtyq *dq,
                          struct silofs_list_head *lh, size_t len)
{
	listq_push_back(&dq->dq, lh);
	dq->dq_accum += len;
}

void silofs_dirtyq_remove(struct silofs_dirtyq *dq,
                          struct silofs_list_head *lh, size_t len)
{
	silofs_assert_ge(dq->dq_accum, len);

	listq_remove(&dq->dq, lh);
	dq->dq_accum -= len;
}

struct silofs_list_head *silofs_dirtyq_front(const struct silofs_dirtyq *dq)
{
	return listq_front(&dq->dq);
}

struct silofs_list_head *
silofs_dirtyq_next_of(const struct silofs_dirtyq *dq,
                      const struct silofs_list_head *lh)
{
	return listq_next(&dq->dq, lh);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void dirtyqs_init(struct silofs_dirtyqs *dqs)
{
	silofs_dirtyq_init(&dqs->dq_uis);
	silofs_dirtyq_init(&dqs->dq_iis);
	silofs_dirtyq_init(&dqs->dq_vis);
}

static void dirtyqs_fini(struct silofs_dirtyqs *dqs)
{
	silofs_dirtyq_fini(&dqs->dq_uis);
	silofs_dirtyq_fini(&dqs->dq_iis);
	silofs_dirtyq_fini(&dqs->dq_vis);
}

static struct silofs_dirtyq *
dirtyqs_get(struct silofs_dirtyqs *dqs, enum silofs_ltype ltype)
{
	struct silofs_dirtyq *dq;

	if (ltype_isinode(ltype)) {
		dq = &dqs->dq_iis;
	} else if (ltype_isvnode(ltype)) {
		dq = &dqs->dq_vis;
	} else {
		silofs_assert(ltype_isunode(ltype));
		dq = &dqs->dq_uis;
	}
	return dq;
}

static struct silofs_dirtyq *
dirtyqs_get_by(struct silofs_dirtyqs *dqs, const struct silofs_vaddr *vaddr)
{
	return dirtyqs_get(dqs, vaddr->ltype);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_lnode_info *
lni_from_lme(const struct silofs_lrumap_elem *lme)
{
	const struct silofs_lnode_info *lni = NULL;

	if (likely(lme != NULL)) {
		lni = container_of2(lme, struct silofs_lnode_info, l_lme);
	}
	return unconst(lni);
}

static struct silofs_lrumap_elem *lni_to_lme(const struct silofs_lnode_info
                *lni)
{
	const struct silofs_lrumap_elem *lme = &lni->l_lme;

	return unconst(lme);
}

bool silofs_lni_isevictable(const struct silofs_lnode_info *lni)
{
	bool ret = false;

	if (!(lni->l_flags & SILOFS_LNF_PINNED)) {
		ret = lme_is_evictable_atomic(lni_to_lme(lni));
	}
	return ret;
}

static size_t lni_view_len(const struct silofs_lnode_info *lni)
{
	return silofs_ltype_size(lni->l_ltype);
}

static void lni_incref(struct silofs_lnode_info *lni)
{
	lme_incref_atomic(&lni->l_lme);
}

static void lni_decref(struct silofs_lnode_info *lni)
{
	lme_decref_atomic(&lni->l_lme);
}

void silofs_lni_incref(struct silofs_lnode_info *lni)
{
	if (likely(lni != NULL)) {
		lni_incref(lni);
	}
}

void silofs_lni_decref(struct silofs_lnode_info *lni)
{
	if (likely(lni != NULL)) {
		lni_decref(lni);
	}
}

static void lni_remove_from_lrumap(struct silofs_lnode_info *lni,
                                   struct silofs_lrumap *lrumap)
{
	struct silofs_lrumap_elem *lme = lni_to_lme(lni);

	if (lme->lme_mapped) {
		lrumap_remove(lrumap, lme);
	} else {
		lrumap_unlru(lrumap, lme);
	}
}

static void lni_delete(struct silofs_lnode_info *lni,
                       struct silofs_alloc *alloc, int flags)
{
	silofs_lnode_del_fn del = lni->l_del_cb;

	del(lni, alloc, flags);
}

static int visit_evictable_lni(struct silofs_lrumap_elem *lme, void *arg)
{
	struct silofs_lnode_info *lni = lni_from_lme(lme);
	struct silofs_lnode_info **out_lni = arg;
	int ret = 0;

	if (silofs_test_evictable(lni)) {
		*out_lni = lni; /* found candidate for eviction */
		ret = 1;
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ui_set_dq(struct silofs_unode_info *ui, struct silofs_dirtyq *dq)
{
	silofs_assert_null(ui->u_dq);
	ui->u_dq = dq;
}

static bool ui_isdirty(const struct silofs_unode_info *ui)
{
	return lme_is_dirty(&ui->u_lni.l_lme);
}

static void ui_do_dirtify(struct silofs_unode_info *ui)
{
	if (!ui_isdirty(ui)) {
		silofs_dirtyq_append(ui->u_dq, &ui->u_dq_lh,
		                     lni_view_len(&ui->u_lni));
		lme_set_dirty(&ui->u_lni.l_lme, true);
	}
}

static void ui_do_undirtify(struct silofs_unode_info *ui)
{
	silofs_assert_not_null(ui->u_dq);

	if (ui_isdirty(ui)) {
		silofs_dirtyq_remove(ui->u_dq, &ui->u_dq_lh,
		                     lni_view_len(&ui->u_lni));
		lme_set_dirty(&ui->u_lni.l_lme, false);
	}
}

void silofs_ui_dirtify(struct silofs_unode_info *ui)
{
	if (likely(ui != NULL)) {
		ui_do_dirtify(ui);
	}
}

void silofs_ui_undirtify(struct silofs_unode_info *ui)
{
	if (likely(ui != NULL)) {
		ui_do_undirtify(ui);
	}
}

void silofs_ui_incref(struct silofs_unode_info *ui)
{
	if (likely(ui != NULL)) {
		lni_incref(&ui->u_lni);
	}
}

void silofs_ui_decref(struct silofs_unode_info *ui)
{
	if (likely(ui != NULL)) {
		lni_decref(&ui->u_lni);
	}
}

static struct silofs_unode_info *ui_from_lme(struct silofs_lrumap_elem *lme)
{
	struct silofs_unode_info *ui = NULL;

	if (lme != NULL) {
		ui = silofs_ui_from_lni(lni_from_lme(lme));
	}
	return ui;
}

static struct silofs_lrumap_elem *ui_to_lme(struct silofs_unode_info *ui)
{
	return lni_to_lme(&ui->u_lni);
}

static int visit_evictable_ui(struct silofs_lrumap_elem *lme, void *arg)
{
	return visit_evictable_lni(lme, arg);
}

static bool ui_is_evictable(const struct silofs_unode_info *ui)
{
	return silofs_test_evictable(&ui->u_lni);
}


static void ui_delete(struct silofs_unode_info *ui,
                      struct silofs_alloc *alloc, int flags)
{
	lni_delete(&ui->u_lni, alloc, flags);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_dirtyqs *vi_dirtyqs(const struct silofs_vnode_info *vi)
{
	const struct silofs_fsenv *fsenv = vi_fsenv(vi);

	return &fsenv->fse.cache->c_dqs;
}

static void vi_set_dq(struct silofs_vnode_info *vi, struct silofs_dirtyq *dq)
{
	vi->v_dq = dq;
}

static void vi_update_dq_by(struct silofs_vnode_info *vi,
                            struct silofs_inode_info *ii)
{
	struct silofs_dirtyq *dq;

	if (ii != NULL) {
		dq = &ii->i_dq_vis;
	} else {
		dq = dirtyqs_get_by(vi_dirtyqs(vi), vi_vaddr(vi));
	}
	vi_set_dq(vi, dq);
}

static struct silofs_vnode_info *vi_from_lme(struct silofs_lrumap_elem *lme)
{
	struct silofs_vnode_info *vi = NULL;

	if (lme != NULL) {
		vi = silofs_vi_from_lni(lni_from_lme(lme));
	}
	return vi;
}

static struct silofs_lrumap_elem *vi_to_lme(const struct silofs_vnode_info *vi)
{
	const struct silofs_lrumap_elem *lme = &vi->v_lni.l_lme;

	return unconst(lme);
}

static int visit_evictable_vi(struct silofs_lrumap_elem *lme, void *arg)
{
	return visit_evictable_lni(lme, arg);
}

int silofs_vi_refcnt(const struct silofs_vnode_info *vi)
{
	return likely(vi != NULL) ? lme_refcnt_atomic(vi_to_lme(vi)) : 0;
}

void silofs_vi_incref(struct silofs_vnode_info *vi)
{
	if (likely(vi != NULL)) {
		lni_incref(&vi->v_lni);
	}
}

void silofs_vi_decref(struct silofs_vnode_info *vi)
{
	if (likely(vi != NULL)) {
		lni_decref(&vi->v_lni);
	}
}

static bool vi_is_evictable(const struct silofs_vnode_info *vi)
{
	return silofs_test_evictable(&vi->v_lni);
}

static void vi_delete(struct silofs_vnode_info *vi,
                      struct silofs_alloc *alloc, int flags)
{
	lni_delete(&vi->v_lni, alloc, flags);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_dirtyq *
cache_dirtyq_by(struct silofs_cache *cache, enum silofs_ltype ltype)
{
	return dirtyqs_get(&cache->c_dqs, ltype);
}

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
	struct silofs_lnode_info *lni = NULL;
	struct silofs_lrumap *lrumap = &cache->c_ui_lm;
	const size_t limit = lrumap_calc_search_evictable_max(lrumap);

	lrumap_riterate(lrumap, limit, visit_evictable_ui, &lni);
	return silofs_ui_from_lni(lni);
}

static struct silofs_unode_info *
cache_find_ui(struct silofs_cache *cache, const struct silofs_uaddr *uaddr)
{
	struct silofs_hkey hkey;
	struct silofs_lrumap_elem *lme;

	hkey_by_uaddr(&hkey, uaddr);
	lme = lrumap_find(&cache->c_ui_lm, &hkey);
	return ui_from_lme(lme);
}

static void cache_promote_ui(struct silofs_cache *cache,
                             struct silofs_unode_info *ui, bool now)
{
	struct silofs_lrumap_elem *lme = ui_to_lme(ui);

	lrumap_promote(&cache->c_ui_lm, lme, now);
}

static struct silofs_unode_info *
cache_find_relru_ui(struct silofs_cache *cache,
                    const struct silofs_uaddr *uaddr)
{
	struct silofs_unode_info *ui;

	ui = cache_find_ui(cache, uaddr);
	if (ui != NULL) {
		cache_promote_ui(cache, ui, false);
	}
	return ui;
}

static void cache_remove_ui(struct silofs_cache *cache,
                            struct silofs_unode_info *ui)
{
	lni_remove_from_lrumap(&ui->u_lni, &cache->c_ui_lm);
}

static void cache_evict_ui(struct silofs_cache *cache,
                           struct silofs_unode_info *ui, int flags)
{
	ui_do_undirtify(ui);
	cache_remove_ui(cache, ui);
	ui_delete(ui, cache->c_alloc, flags);
}

static void cache_store_ui_lrumap(struct silofs_cache *cache,
                                  struct silofs_unode_info *ui)
{
	lrumap_store(&cache->c_ui_lm, ui_to_lme(ui));
}

static struct silofs_unode_info *cache_get_lru_ui(struct silofs_cache *cache)
{
	struct silofs_lrumap_elem *lme;

	lme = lrumap_get_lru(&cache->c_ui_lm);
	return (lme != NULL) ? ui_from_lme(lme) : NULL;
}

static bool cache_evict_or_relru_ui(struct silofs_cache *cache,
                                    struct silofs_unode_info *ui)
{
	bool evicted;

	if (ui_is_evictable(ui)) {
		cache_evict_ui(cache, ui, 0);
		evicted = true;
	} else {
		cache_promote_ui(cache, ui, true);
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

static int try_evict_ui(struct silofs_lrumap_elem *lme, void *arg)
{
	struct silofs_cache *cache = arg;
	struct silofs_unode_info *ui = ui_from_lme(lme);

	cache_evict_or_relru_ui(cache, ui);
	return 0;
}

static void cache_drop_evictable_uis(struct silofs_cache *cache)
{
	lrumap_riterate(&cache->c_ui_lm, LRUMAP_ALL, try_evict_ui, cache);
}

static struct silofs_unode_info *
cache_new_ui(const struct silofs_cache *cache,
             const struct silofs_ulink *ulink)
{
	return silofs_new_ui(cache->c_alloc, ulink);
}

static void cache_track_uaddr(struct silofs_cache *cache,
                              const struct silofs_uaddr *uaddr)
{
	silofs_uamap_insert(&cache->c_uamap, uaddr);
}

static void cache_forget_uaddr(struct silofs_cache *cache,
                               const struct silofs_uaddr *uaddr)
{
	struct silofs_uakey uakey;

	silofs_uakey_setup_by(&uakey, uaddr);
	silofs_uamap_remove(&cache->c_uamap, &uakey);
}

static const struct silofs_uaddr *
cache_lookup_uaddr_by(struct silofs_cache *cache,
                      const struct silofs_uakey *uakey)
{
	return silofs_uamap_lookup(&cache->c_uamap, uakey);
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

	ui = cache_lookup_ui(cache, uaddr);
	cache_post_op(cache);
	return ui;
}

static struct silofs_unode_info *
cache_require_ui(struct silofs_cache *cache, const struct silofs_ulink *ulink)
{
	struct silofs_unode_info *ui = NULL;
	int retry = CACHE_RETRY;

	while (retry-- > 0) {
		ui = cache_new_ui(cache, ulink);
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
	hkey_by_uaddr(&ui->u_lni.l_lme.lme_key, ui_uaddr(ui));
	cache_store_ui_lrumap(cache, ui);
}

static void cache_set_dq_of_ui(struct silofs_cache *cache,
                               struct silofs_unode_info *ui)
{
	const struct silofs_uaddr *uaddr = ui_uaddr(ui);
	struct silofs_dirtyq *dq;

	dq = cache_dirtyq_by(cache, uaddr->ltype);
	ui_set_dq(ui, dq);
}

static struct silofs_unode_info *
cache_create_ui(struct silofs_cache *cache, const struct silofs_ulink *ulink)
{
	struct silofs_unode_info *ui;

	ui = cache_require_ui(cache, ulink);
	if (ui != NULL) {
		cache_set_dq_of_ui(cache, ui);
		cache_store_ui(cache, ui);
		cache_track_uaddr(cache, ui_uaddr(ui));
	}
	return ui;
}

struct silofs_unode_info *
silofs_cache_create_ui(struct silofs_cache *cache,
                       const struct silofs_ulink *ulink)
{
	struct silofs_unode_info *ui;

	ui = cache_create_ui(cache, ulink);
	cache_post_op(cache);
	return ui;
}

static void
cache_forget_ui(struct silofs_cache *cache, struct silofs_unode_info *ui)
{
	cache_forget_uaddr(cache, ui_uaddr(ui));
	cache_evict_ui(cache, ui, 0);
}

void silofs_cache_forget_ui(struct silofs_cache *cache,
                            struct silofs_unode_info *ui)
{
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

	ui = cache_find_ui_by(cache, uakey);
	cache_post_op(cache);
	return ui;
}

void silofs_cache_drop_uamap(struct silofs_cache *cache)
{
	cache_drop_uamap(cache);
	cache_post_op(cache);
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
	struct silofs_lnode_info *lni = NULL;
	struct silofs_lrumap *lrumap = &cache->c_vi_lm;
	const size_t limit = lrumap_calc_search_evictable_max(lrumap);

	lrumap_riterate(lrumap, limit, visit_evictable_vi, &lni);
	return silofs_vi_from_lni(lni);
}

static struct silofs_vnode_info *
cache_find_vi(struct silofs_cache *cache, const struct silofs_vaddr *vaddr)
{
	struct silofs_hkey hkey;
	struct silofs_lrumap_elem *lme;

	hkey_by_vaddr(&hkey, vaddr);
	lme = lrumap_find(&cache->c_vi_lm, &hkey);
	return vi_from_lme(lme);
}

static void cache_promote_vi(struct silofs_cache *cache,
                             struct silofs_vnode_info *vi, bool now)
{
	lrumap_promote(&cache->c_vi_lm, vi_to_lme(vi), now);
}

static struct silofs_vnode_info *
cache_find_relru_vi(struct silofs_cache *cache,
                    const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi;

	vi = cache_find_vi(cache, vaddr);
	if (vi != NULL) {
		cache_promote_vi(cache, vi, false);
	}
	return vi;
}

static void cache_remove_vi(struct silofs_cache *cache,
                            struct silofs_vnode_info *vi)
{
	lni_remove_from_lrumap(&vi->v_lni, &cache->c_vi_lm);
	lme_set_forgot(&vi->v_lni.l_lme, false);
}

static void cache_evict_vi(struct silofs_cache *cache,
                           struct silofs_vnode_info *vi, int flags)
{
	cache_remove_vi(cache, vi);
	vi_delete(vi, cache->c_alloc, flags);
}

static void cache_store_vi_lrumap(struct silofs_cache *cache,
                                  struct silofs_vnode_info *vi)
{
	lrumap_store(&cache->c_vi_lm, vi_to_lme(vi));
}

static void cache_store_vi(struct silofs_cache *cache,
                           struct silofs_vnode_info *vi)
{
	hkey_by_vaddr(&vi->v_lni.l_lme.lme_key, &vi->v_vaddr);
	cache_store_vi_lrumap(cache, vi);
}

static struct silofs_vnode_info *cache_get_lru_vi(struct silofs_cache *cache)
{
	struct silofs_lrumap_elem *lme;

	lme = lrumap_get_lru(&cache->c_vi_lm);
	return (lme != NULL) ? vi_from_lme(lme) : NULL;
}

static bool cache_evict_or_relru_vi(struct silofs_cache *cache,
                                    struct silofs_vnode_info *vi)
{
	bool evicted;

	if (vi_is_evictable(vi)) {
		cache_evict_vi(cache, vi, 0);
		evicted = true;
	} else {
		cache_promote_vi(cache, vi, true);
		evicted = false;
	}
	return evicted;
}

static size_t
cache_shrink_or_relru_vis(struct silofs_cache *cache, size_t cnt, bool now)
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
		} else if (!now && (i || evicted)) {
			break;
		}
	}
	return evicted;
}

static int try_evict_vi(struct silofs_lrumap_elem *lme, void *arg)
{
	struct silofs_cache *cache = arg;
	struct silofs_vnode_info *vi = vi_from_lme(lme);

	cache_evict_or_relru_vi(cache, vi);
	return 0;
}

static void cache_drop_evictable_vis(struct silofs_cache *cache)
{
	lrumap_riterate(&cache->c_vi_lm, LRUMAP_ALL, try_evict_vi, cache);
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
	struct silofs_lrumap_elem *lme = vi_to_lme(vi);

	if (lme->lme_mapped) {
		lrumap_unmap(&cache->c_vi_lm, lme);
	}
}

static void cache_forget_vi(struct silofs_cache *cache,
                            struct silofs_vnode_info *vi)
{
	vi_do_undirtify(vi);
	if (vi_refcnt(vi) > 0) {
		cache_unmap_vi(cache, vi);
		lme_set_forgot(&vi->v_lni.l_lme, true);
	} else {
		cache_evict_vi(cache, vi, 0);
	}
}

void silofs_cache_forget_vi(struct silofs_cache *cache,
                            struct silofs_vnode_info *vi)
{
	cache_forget_vi(cache, vi);
	cache_post_op(cache);
}

static struct silofs_vnode_info *
cache_create_vi(struct silofs_cache *cache, const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi;

	vi = cache_require_vi(cache, vaddr);
	if (vi != NULL) {
		cache_store_vi(cache, vi);
	}
	return vi;
}

struct silofs_vnode_info *
silofs_cache_create_vi(struct silofs_cache *cache,
                       const struct silofs_vaddr *vaddr)
{
	struct silofs_vnode_info *vi;

	vi = cache_create_vi(cache, vaddr);
	cache_post_op(cache);
	return vi;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t
cache_shrink_some_vis(struct silofs_cache *cache, size_t count, bool now)
{
	return cache_shrink_or_relru_vis(cache, count, now);
}

static size_t
cache_shrink_some_uis(struct silofs_cache *cache, size_t count, bool now)
{
	return cache_shrink_or_relru_uis(cache, count, now);
}

static size_t
cache_shrink_some(struct silofs_cache *cache, size_t count, bool now)
{
	return cache_shrink_some_vis(cache, count, now) +
	       cache_shrink_some_uis(cache, count, now);
}

static void cache_evict_some(struct silofs_cache *cache)
{
	struct silofs_vnode_info *vi = NULL;
	struct silofs_unode_info *ui = NULL;
	bool evicted = false;

	vi = cache_find_evictable_vi(cache);
	if ((vi != NULL) && vi_is_evictable(vi)) {
		cache_evict_vi(cache, vi, 0);
		evicted = true;
	}
	ui = cache_find_evictable_ui(cache);
	if ((ui != NULL) && ui_is_evictable(ui)) {
		cache_evict_ui(cache, ui, 0);
		evicted = true;
	}
	if (!evicted) {
		cache_shrink_some(cache, 1, false);
	}
}

/* returns memory-pressure as percentage of total available memory */
static size_t cache_memory_pressure(const struct silofs_cache *cache)
{
	struct silofs_alloc_stat st;
	size_t mem_pres = 1;

	silofs_allocstat(cache->c_alloc, &st);
	if (likely(st.nbytes_max > 0)) {
		mem_pres = ((100UL * st.nbytes_use) / st.nbytes_max);
	}
	return mem_pres;
}

static size_t cache_calc_niter(const struct silofs_cache *cache, int flags)
{
	const size_t mem_pres = cache_memory_pressure(cache);
	const size_t niter_base = (flags & SILOFS_F_NOW) ? 2 : 0;
	size_t niter = 0;

	if (mem_pres > 60) {
		niter += mem_pres / 10;
	} else if (mem_pres > 20) {
		if (flags & SILOFS_F_OPSTART) {
			niter += mem_pres / 40;
		} else if (flags & SILOFS_F_OPFINISH) {
			niter += mem_pres / 25;
		} else if (flags & SILOFS_F_TIMEOUT) {
			niter += mem_pres / 10;
		}
	} else if (mem_pres > 0) {
		if (flags & SILOFS_F_TIMEOUT) {
			niter += mem_pres / 10;
		}
		if (flags & SILOFS_F_IDLE) {
			niter += 1;
		}
	}
	return niter + niter_base;
}

static size_t cache_nmapped_uis(const struct silofs_cache *cache)
{
	return cache->c_ui_lm.lm_htbl_sz;
}

static size_t cache_relax_by_niter(struct silofs_cache *cache,
                                   size_t niter, int flags)
{
	const size_t nmapped = cache_nmapped_uis(cache);
	size_t total = 0;
	size_t nvis;
	size_t nuis;
	size_t cnt;
	bool now;

	now = (flags & SILOFS_F_NOW) > 0;
	cnt = (now || (niter > 1)) ? 2 : 1;
	for (size_t i = 0; i < niter; ++i) {
		nvis = cache_shrink_some_vis(cache, i + 1, now);
		if (!nvis || now || (nmapped > 256)) {
			nuis = cache_shrink_some_uis(cache, cnt, now);
		} else {
			nuis = 0;
		}
		if (!nvis && !nuis) {
			break;
		}
		total += nvis + nuis;
	}
	return total;
}

static size_t cache_overpop_vis(const struct silofs_cache *cache)
{
	return lrumap_overpop(&cache->c_vi_lm);
}

static size_t cache_overpop_uis(const struct silofs_cache *cache)
{
	return lrumap_overpop(&cache->c_ui_lm);
}

static size_t cache_relax_by_overpop(struct silofs_cache *cache)
{
	size_t opop;
	size_t cnt = 0;

	opop = cache_overpop_vis(cache);
	if (opop > 0) {
		cnt += cache_shrink_some_vis(cache, min(opop, 8), true);
	}
	opop = cache_overpop_uis(cache);
	if (opop > 0) {
		cnt += cache_shrink_some_uis(cache, min(opop, 2), true);
	}
	return cnt;
}

static void cache_relax_uamap(struct silofs_cache *cache, int flags)
{
	if (flags & SILOFS_F_IDLE) {
		silofs_uamap_drop_lru(&cache->c_uamap);
	}
}

void silofs_cache_relax(struct silofs_cache *cache, int flags)
{
	size_t niter;
	size_t drop1;
	size_t drop2;

	niter = cache_calc_niter(cache, flags);
	drop1 = cache_relax_by_niter(cache, niter, flags);
	drop2 = cache_relax_by_overpop(cache);
	if (niter && !drop1 && !drop2 && (flags & SILOFS_F_IDLE)) {
		cache_relax_uamap(cache, flags);
	}
}

static size_t cache_lrumap_usage_sum(const struct silofs_cache *cache)
{
	return lrumap_usage(&cache->c_vi_lm) + lrumap_usage(&cache->c_ui_lm);
}

static void cache_drop_evictables_once(struct silofs_cache *cache)
{
	cache_drop_evictable_vis(cache);
	cache_drop_evictable_uis(cache);
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
	silofs_spamaps_drop(&cache->c_spams);
}

static void cache_drop_uamap(struct silofs_cache *cache)
{
	silofs_uamap_drop_all(&cache->c_uamap);
}

void silofs_cache_drop(struct silofs_cache *cache)
{
	cache_drop_evictables(cache);
	cache_drop_spcmaps(cache);
	cache_drop_uamap(cache);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int cache_init_nil_bk(struct silofs_cache *cache)
{
	struct silofs_lblock *lbk;

	lbk = lbk_malloc(cache->c_alloc, SILOFS_ALLOCF_BZERO);
	if (lbk == NULL) {
		return -SILOFS_ENOMEM;
	}
	cache->c_nil_lbk = lbk;
	return 0;
}

static void cache_fini_nil_bk(struct silofs_cache *cache)
{
	struct silofs_lblock *lbk = cache->c_nil_lbk;

	if (lbk != NULL) {
		lbk_free(lbk, cache->c_alloc, 0);
		cache->c_nil_lbk = NULL;
	}
}

static void cache_fini_lrumaps(struct silofs_cache *cache)
{
	cache_fini_vi_lm(cache);
	cache_fini_ui_lm(cache);
}

static size_t cache_calc_htbl_cap(const struct silofs_cache *cache)
{
	const size_t base = 64UL * SILOFS_KILO;
	const size_t mem_hint_ngigs = cache->c_mem_size_hint / SILOFS_GIGA;
	const size_t factor = clamp(mem_hint_ngigs, 1, 32);

	return base * factor;
}

static int cache_init_lrumaps(struct silofs_cache *cache)
{
	const size_t hcap = cache_calc_htbl_cap(cache);
	const size_t hcap_prime = htbl_cap_as_prime(hcap);
	int err;

	err = cache_init_ui_lm(cache, hcap);
	if (err) {
		goto out_err;
	}
	err = cache_init_vi_lm(cache, hcap_prime);
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
	return silofs_spamaps_init(&cache->c_spams, cache->c_alloc);
}

static void cache_fini_spamaps(struct silofs_cache *cache)
{
	silofs_spamaps_fini(&cache->c_spams);
}

static int cache_init_uamap(struct silofs_cache *cache)
{
	return silofs_uamap_init(&cache->c_uamap, cache->c_alloc);
}

static void cache_fini_uamap(struct silofs_cache *cache)
{
	silofs_uamap_fini(&cache->c_uamap);
}

int silofs_cache_init(struct silofs_cache *cache,
                      struct silofs_alloc *alloc)
{
	struct silofs_alloc_stat st;
	int err;

	silofs_allocstat(alloc, &st);

	cache->c_alloc = alloc;
	cache->c_nil_lbk = NULL;
	cache->c_mem_size_hint = st.nbytes_max;
	dirtyqs_init(&cache->c_dqs);
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
	dirtyqs_fini(&cache->c_dqs);
	cache_fini_lrumaps(cache);
	cache_fini_nil_bk(cache);
	cache_fini_uamap(cache);
	cache_fini_spamaps(cache);
	cache->c_alloc = NULL;
}

static void cache_post_op(struct silofs_cache *cache)
{
	silofs_unused(cache);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool vi_isdirty(const struct silofs_vnode_info *vi)
{
	return lme_is_dirty(&vi->v_lni.l_lme);
}

static void vi_set_dirty(struct silofs_vnode_info *vi, bool dirty)
{
	lme_set_dirty(&vi->v_lni.l_lme, dirty);
}

static void vi_do_dirtify(struct silofs_vnode_info *vi,
                          struct silofs_inode_info *ii)
{
	const struct silofs_vaddr *vaddr = vi_vaddr(vi);

	if (!vi_isdirty(vi)) {
		vi_update_dq_by(vi, ii);
		silofs_dirtyq_append(vi->v_dq, &vi->v_dq_lh, vaddr->len);
		vi_set_dirty(vi, true);
	}
}

static void vi_do_undirtify(struct silofs_vnode_info *vi)
{
	const struct silofs_vaddr *vaddr = vi_vaddr(vi);

	if (vi_isdirty(vi)) {
		silofs_dirtyq_remove(vi->v_dq, &vi->v_dq_lh, vaddr->len);
		vi_update_dq_by(vi, NULL);
		vi_set_dirty(vi, false);
	}
}

void silofs_vi_dirtify(struct silofs_vnode_info *vi,
                       struct silofs_inode_info *ii)
{
	if (likely(vi != NULL)) {
		vi_do_dirtify(vi, ii);
	}
}

void silofs_vi_undirtify(struct silofs_vnode_info *vi)
{
	if (likely(vi != NULL)) {
		vi_do_undirtify(vi);
	}
}

static void ii_do_dirtify(struct silofs_inode_info *ii)
{
	vi_do_dirtify(&ii->i_vi, NULL);
}

static void ii_do_undirtify(struct silofs_inode_info *ii)
{
	vi_do_undirtify(&ii->i_vi);
}

void silofs_ii_dirtify(struct silofs_inode_info *ii)
{
	if (likely(ii != NULL) && !ii_isloose(ii)) {
		ii_do_dirtify(ii);
	}
}

void silofs_ii_undirtify(struct silofs_inode_info *ii)
{
	if (likely(ii != NULL)) {
		ii_do_undirtify(ii);
	}
}

bool silofs_ii_isdirty(const struct silofs_inode_info *ii)
{
	bool ret = false;

	if (likely(ii != NULL)) {
		ret = vi_isdirty(&ii->i_vi);
	}
	return ret;
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

void silofs_ii_set_loose(struct silofs_inode_info *ii)
{
	ii->i_vi.v_lni.l_flags |= SILOFS_LNF_LOOSE;
}

bool silofs_ii_is_loose(const struct silofs_inode_info *ii)
{
	return (ii->i_vi.v_lni.l_flags & SILOFS_LNF_LOOSE) > 0;
}

