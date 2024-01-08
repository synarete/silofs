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

#define HMQE_MAGIC      (0xDEFEC8EDBADDCAFE)

/* prime-value for hash-table of n-elements */
static const unsigned int htbl_primes[] = {
	13, 53, 97, 193, 389, 769, 1543, 3079, 4093, 6151, 8191, 12289, 16381,
	24593, 32749, 49157, 65521, 98317, 131071, 147377, 196613, 294979,
	393241, 589933, 786433, 1572869, 3145739, 6291469, 12582917, 25165843,
	50331653, 100663319, 201326611, 402653189, 805306457, 1610612741,
	3221225473, 4294967291
};

static uint64_t htbl_prime_of(size_t nelems)
{
	uint64_t p = 4294967291;

	for (size_t i = ARRAY_SIZE(htbl_primes); i > 0; --i) {
		if (htbl_primes[i - 1] < (2 * nelems)) {
			break;
		}
		p = htbl_primes[i - 1];
	}
	return p;
}

static uint64_t htbl_nelems_by(const struct silofs_alloc *alloc)
{
	struct silofs_alloc_stat al_st = { .nbytes_max = 0 };
	size_t memsize_ng;
	size_t cap_factor;

	silofs_allocstat(alloc, &al_st);
	memsize_ng = al_st.nbytes_max / SILOFS_GIGA;
	cap_factor = clamp(memsize_ng, 1, 64);

	/* 64K-elems for each available 1G of memory */
	return (1UL << 16) * cap_factor;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

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

void silofs_hkey_by_uaddr(struct silofs_hkey *hkey,
                          const struct silofs_uaddr *uaddr)
{
	hkey_setup(hkey, SILOFS_HKEY_UADDR, uaddr, hash_of_uaddr(uaddr));
}

void silofs_hkey_by_vaddr(struct silofs_hkey *hkey,
                          const struct silofs_vaddr *vaddr)
{
	hkey_setup(hkey, SILOFS_HKEY_VADDR, vaddr, hash_of_vaddr(vaddr));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_hmapq_elem *
hmqe_from_htb_link(const struct silofs_list_head *lh)
{
	const struct silofs_hmapq_elem *hmqe;

	hmqe = container_of2(lh, struct silofs_hmapq_elem, hme_htb_lh);
	silofs_assert_eq(hmqe->hme_magic, HMQE_MAGIC);
	return unconst(hmqe);
}

static struct silofs_hmapq_elem *
hmqe_from_lru_link(const struct silofs_list_head *lh)
{
	const struct silofs_hmapq_elem *hmqe;

	hmqe = container_of2(lh, struct silofs_hmapq_elem, hme_lru_lh);
	silofs_assert_eq(hmqe->hme_magic, HMQE_MAGIC);
	return unconst(hmqe);
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
	silofs_assert_eq(hmqe->hme_refcnt, 0);
	silofs_assert_eq(hmqe->hme_magic, HMQE_MAGIC);

	hkey_reset(&hmqe->hme_key);
	list_head_fini(&hmqe->hme_htb_lh);
	list_head_fini(&hmqe->hme_lru_lh);
	hmqe->hme_refcnt = INT_MIN;
	hmqe->hme_htb_hitcnt = -1;
	hmqe->hme_lru_hitcnt = -1;
	hmqe->hme_magic = ULONG_MAX;
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

static void hmqe_promote_hmap(struct silofs_hmapq_elem *hmqe,
                              struct silofs_list_head *hlst)
{
	struct silofs_list_head *hlnk = &hmqe->hme_htb_lh;

	silofs_assert(hmqe->hme_mapped);

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
	silofs_assert_ge(hmqe->hme_refcnt, 0);
	return hmqe_refcnt_atomic(hmqe);
}

void silofs_hmqe_incref(struct silofs_hmapq_elem *hmqe)
{
	hmqe_incref_atomic(hmqe);
}

void silofs_hmqe_decref(struct silofs_hmapq_elem *hmqe)
{
	hmqe_decref_atomic(hmqe);
}

bool silofs_hmqe_is_evictable(const struct silofs_hmapq_elem *hmqe)
{
	return hmqe_is_evictable_atomic(hmqe);
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_hmapq_init(struct silofs_hmapq *hmapq, struct silofs_alloc *alloc)
{
	struct silofs_list_head *htbl = NULL;
	size_t nelems;

	nelems = htbl_nelems_by(alloc);
	htbl = silofs_lista_new(alloc, nelems);
	if (htbl == NULL) {
		return -SILOFS_ENOMEM;
	}
	listq_init(&hmapq->hmq_lru);
	hmapq->hmq_htbl = htbl;
	hmapq->hmq_htbl_nelems = nelems;
	hmapq->hmq_htbl_prime = htbl_prime_of(nelems);
	hmapq->hmq_htbl_sz = 0;
	return 0;
}

void silofs_hmapq_fini(struct silofs_hmapq *hmapq, struct silofs_alloc *alloc)
{
	if (hmapq->hmq_htbl != NULL) {
		silofs_lista_del(hmapq->hmq_htbl,
		                 hmapq->hmq_htbl_nelems, alloc);
		listq_fini(&hmapq->hmq_lru);
		hmapq->hmq_htbl = NULL;
		hmapq->hmq_htbl_nelems = 0;
	}
}

size_t silofs_hmapq_usage(const struct silofs_hmapq *hmapq)
{
	return hmapq->hmq_htbl_sz;
}

static size_t hmapq_key_to_slot(const struct silofs_hmapq *hmapq,
                                const struct silofs_hkey *hkey)
{
	const uint64_t hval = hkey->hash % hmapq->hmq_htbl_prime;

	return hval % hmapq->hmq_htbl_nelems;
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
	hmapq->hmq_htbl_sz += 1;
}

static struct silofs_hmapq_elem *
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
			return unconst(hmqe);
		}
		itr = itr->next;
	}
	return NULL;
}

struct silofs_hmapq_elem *
silofs_hmapq_lookup(const struct silofs_hmapq *hmapq,
                    const struct silofs_hkey *hkey)
{
	return hmapq_find(hmapq, hkey);
}

static void hmapq_unmap(struct silofs_hmapq *hmapq,
                        struct silofs_hmapq_elem *hmqe)
{
	hmqe_hunmap(hmqe);
	hmapq->hmq_htbl_sz -= 1;
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
	hmapq_promote_hlnk(hmapq, hmqe);
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
	const size_t fac = 4;
	size_t ovp = 0;

	if (hmapq->hmq_htbl_sz > (fac * hmapq->hmq_htbl_nelems)) {
		ovp = (hmapq->hmq_htbl_sz - (fac * hmapq->hmq_htbl_nelems));
	} else if (hmapq->hmq_lru.sz > (fac * hmapq->hmq_htbl_sz)) {
		ovp = (hmapq->hmq_lru.sz - (fac * hmapq->hmq_htbl_sz));
	}
	return ovp;
}
