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
#include <silofs/addr.h>
#include <limits.h>

#define HMQE_MAGIC      (0xDEFEC8EDBADCAFE)

/* prime-value for hash-table of n-elements */
static const unsigned int htbl_primes[] = {
	13, 53, 97, 167, 193, 283, 389, 509, 1021, 2557, 3041, 3581, 3583,
	4093, 5107, 5119, 6143, 7159, 8191, 9209, 10141, 11257, 11261, 12281,
	13309, 14699, 15359, 16381, 17401, 18427, 20479, 24571, 27529, 28669,
	36857, 45053, 49207, 53233, 65521, 73727, 77291, 81919, 85237, 94207,
	106693, 131071, 160423, 172031, 203789, 241663, 245759, 253951, 266239,
	294911, 356351, 364289, 364543, 401407, 438271, 442367, 479231, 487423,
	499711, 524287, 528383, 565247, 585727, 602111, 626687, 671743, 675839,
	724991, 737279, 745471, 770047, 774143, 786431, 847871, 917503, 929791,
	942079, 954367, 991961, 995327, 1203793, 1572869, 1667321, 3704053,
	4792057,

};

static uint64_t htbl_prime_of(size_t nelems)
{
	uint64_t p = 11;

	for (size_t i = 0; i < ARRAY_SIZE(htbl_primes); ++i) {
		if (htbl_primes[i] > nelems) {
			break;
		}
		p = htbl_primes[i];
	}
	return p;
}

static uint64_t htbl_nslots_by_memsize(const struct silofs_alloc *alloc)
{
	struct silofs_alloc_stat al_st = { .nbytes_max = 0 };
	size_t memsize_ngigs;
	size_t nslots_factor;

	/* available memory as 1G units */
	silofs_memstat(alloc, &al_st);
	memsize_ngigs = al_st.nbytes_max / SILOFS_GIGA;

	/* derive slots (buckets) factor based on available memory size */
	nslots_factor = clamp(memsize_ngigs, 1, 64);

	/* 4K hash-buckets for each available 1G of memory */
	return (1UL << 12) * nslots_factor;
}

static size_t htbl_calc_nslots(const struct silofs_alloc *alloc, uint8_t fac)
{
	uint64_t nslots;

	/* derive htbl slots (buckets) count from available memory capacity */
	nslots = htbl_nslots_by_memsize(alloc);

	/* abd clamp it to prime value */
	nslots = htbl_prime_of(nslots * clamp(fac, 1, 10));

	return nslots;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static uint64_t hash_of_pvid(const struct silofs_pvid *pvid)
{
	return silofs_pvid_hash64(pvid);
}

static uint64_t hash_of_blobid(const struct silofs_blobid *blobid)
{
	return silofs_blobid_hash64(blobid);
}

static uint64_t hash_of_paddr(const struct silofs_paddr *paddr)
{
	const uint64_t uoff = (uint64_t)paddr->off;
	const uint64_t h1 = 0xc6a4a7935bd1e995ULL - paddr->len;
	const uint64_t h2 = hash_of_pvid(&paddr->pvid);

	return (uoff + paddr->index) ^ h1 ^ h2;
}

static uint64_t hash_of_lsegid(const struct silofs_lsegid *lsegid)
{
	return silofs_lsegid_hash64(lsegid);
}

static uint64_t hash_of_uaddr(const struct silofs_uaddr *uaddr)
{
	const uint64_t uoff = (uint64_t)uaddr->voff;
	const uint64_t upos = (uint64_t)uaddr->laddr.pos;
	const uint64_t h1 = 0x646f72616e646f6dULL - upos;
	const uint64_t h2 = hash_of_lsegid(&uaddr->laddr.lsid);

	return uoff ^ h1 ^ h2;
}

static uint64_t hash_of_vaddr(const struct silofs_vaddr *vaddr)
{
	const uint64_t uoff = (uint64_t)vaddr->off;

	return (uoff + vaddr->ltype) ^ 0x736f6d6570736575ULL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void hkey_setup(struct silofs_hkey *hkey,
                       enum silofs_hkey_type type,
                       const void *key, uint64_t hash)
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

static long hkey_compare_as_blobid(const struct silofs_hkey *hkey1,
                                   const struct silofs_hkey *hkey2)
{
	return silofs_blobid_compare(hkey1->keyu.blobid, hkey2->keyu.blobid);
}

static long hkey_compare_as_paddr(const struct silofs_hkey *hkey1,
                                  const struct silofs_hkey *hkey2)
{
	return silofs_paddr_compare(hkey1->keyu.paddr, hkey2->keyu.paddr);
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

static long hkey_compare_as(const struct silofs_hkey *hkey1,
                            const struct silofs_hkey *hkey2)
{
	long cmp;

	switch (hkey1->type) {
	case SILOFS_HKEY_BLOBID:
		cmp = hkey_compare_as_blobid(hkey1, hkey2);
		break;
	case SILOFS_HKEY_PADDR:
		cmp = hkey_compare_as_paddr(hkey1, hkey2);
		break;
	case SILOFS_HKEY_UADDR:
		cmp = hkey_compare_as_uaddr(hkey1, hkey2);
		break;
	case SILOFS_HKEY_VADDR:
		cmp = hkey_compare_as_vaddr(hkey1, hkey2);
		break;
	case SILOFS_HKEY_NONE:
	default:
		cmp = 0;
		break;
	}
	return cmp;
}

long silofs_hkey_compare(const struct silofs_hkey *hkey1,
                         const struct silofs_hkey *hkey2)
{
	long cmp;

	cmp = (long)hkey2->type - (long)hkey1->type;
	if (cmp == 0) {
		cmp = hkey_compare_as(hkey1, hkey2);
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

static uint64_t hkey_hash_of(enum silofs_hkey_type type, const void *key)
{
	uint64_t hash = 0;

	switch (type) {
	case SILOFS_HKEY_BLOBID:
		hash = hash_of_blobid(key);
		break;
	case SILOFS_HKEY_PADDR:
		hash = hash_of_paddr(key);
		break;
	case SILOFS_HKEY_UADDR:
		hash = hash_of_uaddr(key);
		break;
	case SILOFS_HKEY_VADDR:
		hash = hash_of_vaddr(key);
		break;
	case SILOFS_HKEY_NONE:
	default:
		hash = 0;
		break;
	}
	return hash;
}

static void hkey_setup_by(struct silofs_hkey *hkey,
                          enum silofs_hkey_type type, const void *key)
{
	hkey_setup(hkey, type, key, hkey_hash_of(type, key));
}

void silofs_hkey_by_blobid(struct silofs_hkey *hkey,
                           const struct silofs_blobid *blobid)
{
	hkey_setup_by(hkey, SILOFS_HKEY_BLOBID, blobid);
}

void silofs_hkey_by_paddr(struct silofs_hkey *hkey,
                          const struct silofs_paddr *paddr)
{
	hkey_setup_by(hkey, SILOFS_HKEY_PADDR, paddr);
}

void silofs_hkey_by_uaddr(struct silofs_hkey *hkey,
                          const struct silofs_uaddr *uaddr)
{
	hkey_setup_by(hkey, SILOFS_HKEY_UADDR, uaddr);
}

void silofs_hkey_by_vaddr(struct silofs_hkey *hkey,
                          const struct silofs_vaddr *vaddr)
{
	hkey_setup_by(hkey, SILOFS_HKEY_VADDR, vaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void hmqe_sanitize(const struct silofs_hmapq_elem *hmqe)
{
	if (unlikely(hmqe->hme_magic != HMQE_MAGIC) ||
	    unlikely(hmqe->hme_refcnt < 0)) {
		silofs_panic("illegal: hmqe=%p hme_key.type=%d "
		             "hme_refcnt=%d hme_dirty=%d hme_mapped=%d "
		             "hme_forgot=%d hme_magic=0x%lx", hmqe,
		             (int)hmqe->hme_key.type, hmqe->hme_refcnt,
		             (int)hmqe->hme_dirty, (int)hmqe->hme_mapped,
		             (int)hmqe->hme_forgot, hmqe->hme_magic);
	}
}

static struct silofs_hmapq_elem *
hmqe_unconst(const struct silofs_hmapq_elem *hmqe)
{
	union {
		const void *p;
		void *q;
	} u = {
		.p = hmqe
	};
	return u.q;
}

static struct silofs_hmapq_elem *
hmqe_from_htb_link(const struct silofs_list_head *htb_lh)
{
	const struct silofs_hmapq_elem *hmqe;

	hmqe = container_of2(htb_lh, struct silofs_hmapq_elem, hme_htb_lh);
	hmqe_sanitize(hmqe);
	return hmqe_unconst(hmqe);
}

static struct silofs_hmapq_elem *
hmqe_from_lru_link(const struct silofs_list_head *lru_lh)
{
	const struct silofs_hmapq_elem *hmqe;

	hmqe = container_of2(lru_lh, struct silofs_hmapq_elem, hme_lru_lh);
	hmqe_sanitize(hmqe);
	return hmqe_unconst(hmqe);
}

void silofs_hmqe_init(struct silofs_hmapq_elem *hmqe)
{
	hkey_reset(&hmqe->hme_key);
	list_head_init(&hmqe->hme_htb_lh);
	list_head_init(&hmqe->hme_lru_lh);
	hmqe->hme_magic = HMQE_MAGIC;
	hmqe->hme_refcnt = 0;
	hmqe->hme_htb_hitcnt = 0;
	hmqe->hme_lru_hitcnt = 0;
	hmqe->hme_dirty = false;
	hmqe->hme_mapped = false;
	hmqe->hme_forgot = false;
}

void silofs_hmqe_fini(struct silofs_hmapq_elem *hmqe)
{
	hmqe_sanitize(hmqe);
	silofs_assert_eq(hmqe->hme_refcnt, 0);

	hkey_reset(&hmqe->hme_key);
	list_head_fini(&hmqe->hme_htb_lh);
	list_head_fini(&hmqe->hme_lru_lh);
	hmqe->hme_refcnt = INT_MIN;
	hmqe->hme_htb_hitcnt = -1;
	hmqe->hme_lru_hitcnt = -1;
	hmqe->hme_magic = LONG_MIN;
}

static void hmqe_hmap(struct silofs_hmapq_elem *hmqe,
                      struct silofs_list_head *hlst)
{
	list_push_front(hlst, &hmqe->hme_htb_lh);
	hmqe->hme_mapped = true;
}

static void hmqe_hunmap(struct silofs_hmapq_elem *hmqe)
{
	list_head_remove(&hmqe->hme_htb_lh);
	hmqe->hme_mapped = false;
}

static bool hmqe_need_promote_hmap(const struct silofs_hmapq_elem *hmqe,
                                   const struct silofs_list_head *hlst)
{
	const struct silofs_list_head *hlnk = &hmqe->hme_htb_lh;
	const struct silofs_list_head *next = hlst->next;
	const struct silofs_hmapq_elem *lme_next = NULL;
	bool ret = false;

	if ((next != hlnk) && (next->next != hlnk)) {
		lme_next = hmqe_from_htb_link(next);
		ret = (hmqe->hme_htb_hitcnt > (lme_next->hme_htb_hitcnt + 2));
	}
	return ret;
}

static void hmqe_sanitize_mapped(const struct silofs_hmapq_elem *hmqe)
{
	hmqe_sanitize(hmqe);
	if (unlikely(!hmqe->hme_mapped)) {
		silofs_panic("unexpected non-mapped state: hmqe=%p "
		             "hme_key=%d hme_dirty=%d hme_refcnt=%d",
		             hmqe, (int)hmqe->hme_key.type,
		             (int)hmqe->hme_dirty, hmqe->hme_refcnt);
	}
}

static void hmqe_promote_hmap(struct silofs_hmapq_elem *hmqe,
                              struct silofs_list_head *hlst)
{
	struct silofs_list_head *hlnk = &hmqe->hme_htb_lh;

	hmqe_sanitize_mapped(hmqe);

	list_head_remove(hlnk);
	list_push_front(hlst, hlnk);
}

static struct silofs_list_head *
hmqe_lru_link(struct silofs_hmapq_elem *hmqe)
{
	return &hmqe->hme_lru_lh;
}

static const struct silofs_list_head *
hmqe_lru_link2(const struct silofs_hmapq_elem *hmqe)
{
	return &hmqe->hme_lru_lh;
}

static void hmqe_lru(struct silofs_hmapq_elem *hmqe,
                     struct silofs_listq *lru)
{
	listq_push_front(lru, hmqe_lru_link(hmqe));
}

static void hmqe_unlru(struct silofs_hmapq_elem *hmqe,
                       struct silofs_listq *lru)
{
	listq_remove(lru, hmqe_lru_link(hmqe));
}

static bool hmqe_is_lru_front(const struct silofs_hmapq_elem *hmqe,
                              const struct silofs_listq *lru)
{
	const struct silofs_list_head *lru_front = listq_front(lru);
	const struct silofs_list_head *lme_lru_lnk = hmqe_lru_link2(hmqe);

	return (lru_front == lme_lru_lnk);
}

static bool hmqe_need_relru(const struct silofs_hmapq_elem *hmqe,
                            const struct silofs_listq *lru)
{
	const struct silofs_list_head *lru_front = listq_front(lru);
	const struct silofs_list_head *lme_lru_lnk = hmqe_lru_link2(hmqe);

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
	if (hmqe->hme_lru_hitcnt < 4) {
		return false; /* low hit count */
	}
	return true;
}

static void hmqe_relru(struct silofs_hmapq_elem *hmqe,
                       struct silofs_listq *lru)
{
	hmqe_sanitize(hmqe);
	hmqe_unlru(hmqe, lru);
	hmqe_lru(hmqe, lru);
}

static int hmqe_refcnt_atomic(const struct silofs_hmapq_elem *hmqe)
{
	return silofs_atomic_get(&hmqe->hme_refcnt);
}

static void hmqe_incref_atomic(struct silofs_hmapq_elem *hmqe)
{
	silofs_atomic_add(&hmqe->hme_refcnt, 1);
}

static void hmqe_decref_atomic(struct silofs_hmapq_elem *hmqe)
{
	silofs_atomic_sub(&hmqe->hme_refcnt, 1);
}

static bool hmqe_is_evictable_atomic(const struct silofs_hmapq_elem *hmqe)
{
	return !hmqe->hme_dirty && !hmqe_refcnt_atomic(hmqe);
}

int silofs_hmqe_refcnt(const struct silofs_hmapq_elem *hmqe)
{
	hmqe_sanitize(hmqe);
	return hmqe_refcnt_atomic(hmqe);
}

void silofs_hmqe_incref(struct silofs_hmapq_elem *hmqe)
{
	hmqe_sanitize(hmqe);
	hmqe_incref_atomic(hmqe);
}

void silofs_hmqe_decref(struct silofs_hmapq_elem *hmqe)
{
	hmqe_sanitize(hmqe);
	hmqe_decref_atomic(hmqe);
}

bool silofs_hmqe_is_evictable(const struct silofs_hmapq_elem *hmqe)
{
	hmqe_sanitize(hmqe);
	return hmqe_is_evictable_atomic(hmqe);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_hmapq_nslots_by(const struct silofs_alloc *alloc, uint8_t fac)
{
	return htbl_calc_nslots(alloc, fac);
}

int silofs_hmapq_init(struct silofs_hmapq *hmapq,
                      struct silofs_alloc *alloc, size_t nslots)
{
	struct silofs_list_head *htbl = NULL;

	htbl = silofs_lista_new(alloc, nslots);
	if (htbl == NULL) {
		return -SILOFS_ENOMEM;
	}
	listq_init(&hmapq->hmq_lru);
	hmapq->hmq_htbl = htbl;
	hmapq->hmq_htbl_nslots = nslots;
	hmapq->hmq_htbl_size = 0;
	return 0;
}

void silofs_hmapq_fini(struct silofs_hmapq *hmapq, struct silofs_alloc *alloc)
{
	if (hmapq->hmq_htbl != NULL) {
		silofs_lista_del(hmapq->hmq_htbl,
		                 hmapq->hmq_htbl_nslots, alloc);
		listq_fini(&hmapq->hmq_lru);
		hmapq->hmq_htbl = NULL;
		hmapq->hmq_htbl_nslots = 0;
	}
}

size_t silofs_hmapq_usage(const struct silofs_hmapq *hmapq)
{
	return hmapq->hmq_htbl_size;
}

static size_t hmapq_key_to_slot(const struct silofs_hmapq *hmapq,
                                const struct silofs_hkey *hkey)
{
	const uint64_t hval = hkey->hash ^ (hkey->hash >> 32);

	return hval % hmapq->hmq_htbl_nslots;
}

static struct silofs_list_head *
hmapq_hlist_of(const struct silofs_hmapq *hmapq,
               const struct silofs_hkey *hkey)
{
	const size_t slot = hmapq_key_to_slot(hmapq, hkey);

	return &hmapq->hmq_htbl[slot];
}

void silofs_hmapq_store(struct silofs_hmapq *hmapq,
                        struct silofs_hmapq_elem *hmqe)
{
	struct silofs_listq *lru = &hmapq->hmq_lru;
	struct silofs_list_head *hlst = hmapq_hlist_of(hmapq, &hmqe->hme_key);

	hmqe_lru(hmqe, lru);
	hmqe_hmap(hmqe, hlst);
	hmapq->hmq_htbl_size += 1;
}

static const struct silofs_hmapq_elem *
hmapq_find(const struct silofs_hmapq *hmapq, const struct silofs_hkey *hkey)
{
	const struct silofs_list_head *hlst;
	const struct silofs_list_head *itr;
	const struct silofs_hmapq_elem *hmqe;

	hlst = hmapq_hlist_of(hmapq, hkey);
	itr = hlst->next;
	while (itr != hlst) {
		hmqe = hmqe_from_htb_link(itr);
		if (hkey_isequal(&hmqe->hme_key, hkey)) {
			return hmqe;
		}
		itr = itr->next;
	}
	return NULL;
}

struct silofs_hmapq_elem *
silofs_hmapq_lookup(const struct silofs_hmapq *hmapq,
                    const struct silofs_hkey *hkey)
{
	const struct silofs_hmapq_elem *hmqe;

	hmqe = hmapq_find(hmapq, hkey);
	if (hmqe != NULL) {
		hmqe_sanitize_mapped(hmqe);
	}
	return hmqe_unconst(hmqe);
}

static void hmapq_unmap(struct silofs_hmapq *hmapq,
                        struct silofs_hmapq_elem *hmqe)
{
	hmqe_hunmap(hmqe);
	hmapq->hmq_htbl_size -= 1;
}

static void hmapq_unlru(struct silofs_hmapq *hmapq,
                        struct silofs_hmapq_elem *hmqe)
{
	hmqe_unlru(hmqe, &hmapq->hmq_lru);
}

void silofs_hmapq_unmap(struct silofs_hmapq *hmapq,
                        struct silofs_hmapq_elem *hmqe)
{
	if (hmqe->hme_mapped) {
		hmapq_unmap(hmapq, hmqe);
	}
}

void silofs_hmapq_remove(struct silofs_hmapq *hmapq,
                         struct silofs_hmapq_elem *hmqe)
{
	if (hmqe->hme_mapped) {
		hmapq_unmap(hmapq, hmqe);
	}
	hmapq_unlru(hmapq, hmqe);
}

static void hmapq_promote_lru(struct silofs_hmapq *hmapq,
                              struct silofs_hmapq_elem *hmqe, bool now)
{
	struct silofs_listq *lru = &hmapq->hmq_lru;
	const bool first = hmqe_is_lru_front(hmqe, lru);

	hmqe->hme_lru_hitcnt++;
	if (!first && (now || hmqe_need_relru(hmqe, lru))) {
		hmqe_relru(hmqe, &hmapq->hmq_lru);
		hmqe->hme_lru_hitcnt = 0;
	}
}

static void hmapq_promote_hlnk(struct silofs_hmapq *hmapq,
                               struct silofs_hmapq_elem *hmqe)
{
	struct silofs_list_head *hlst = hmapq_hlist_of(hmapq, &hmqe->hme_key);

	hmqe->hme_htb_hitcnt++;
	if (hmqe_need_promote_hmap(hmqe, hlst)) {
		hmqe_promote_hmap(hmqe, hlst);
	}
}

void silofs_hmapq_promote(struct silofs_hmapq *hmapq,
                          struct silofs_hmapq_elem *hmqe, bool now)
{
	hmapq_promote_lru(hmapq, hmqe, now);
	if (hmqe->hme_mapped) {
		hmapq_promote_hlnk(hmapq, hmqe);
	}
}

struct silofs_hmapq_elem *
silofs_hmapq_get_lru(const struct silofs_hmapq *hmapq)
{
	struct silofs_hmapq_elem *hmqe = NULL;

	if (hmapq->hmq_lru.sz > 0) {
		hmqe = hmqe_from_lru_link(hmapq->hmq_lru.ls.prev);
	}
	return hmqe;
}

typedef int (*silofs_hmapq_elem_fn)(struct silofs_hmapq_elem *, void *);

void silofs_hmapq_riterate(struct silofs_hmapq *hmapq, size_t limit,
                           silofs_hmapq_elem_fn cb, void *arg)
{
	struct silofs_list_head *itr = NULL;
	struct silofs_hmapq_elem *hmqe = NULL;
	struct silofs_listq *lru = &hmapq->hmq_lru;
	size_t count = min(limit, lru->sz);
	int ret = 0;

	itr = lru->ls.prev; /* backward iteration */
	while (!ret && count-- && (itr != &lru->ls)) {
		hmqe = hmqe_from_lru_link(itr);
		itr = itr->prev;
		ret = cb(hmqe, arg);
	}
}

size_t silofs_hmapq_overpop(const struct silofs_hmapq *hmapq)
{
	size_t ovp = 0;

	if (hmapq->hmq_htbl_size > hmapq->hmq_htbl_nslots) {
		ovp = hmapq->hmq_htbl_size - hmapq->hmq_htbl_nslots;
	} else if (hmapq->hmq_lru.sz > (2 * hmapq->hmq_htbl_size)) {
		ovp = hmapq->hmq_lru.sz - (2 * hmapq->hmq_htbl_size);
	}
	return ovp;
}
