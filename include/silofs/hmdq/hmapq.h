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
#ifndef SILOFS_HMAPQ_H_
#define SILOFS_HMAPQ_H_

#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/hmdq/dirtyq.h>

#define SILOFS_HMAPQ_ITERALL   (0xffffffffU)

/* elements' mapping hash-key types */
enum silofs_hkey_type {
	SILOFS_HKEY_NONE,
	SILOFS_HKEY_BLOBID,
	SILOFS_HKEY_PADDR,
	SILOFS_HKEY_UADDR,
	SILOFS_HKEY_VADDR,
};

/* addresses as mapping-key */
union silofs_hkey_u {
	const struct silofs_blobid  *blobid;
	const struct silofs_paddr   *paddr;
	const struct silofs_uaddr   *uaddr;
	const struct silofs_vaddr   *vaddr;
	const void                  *key;
};

struct silofs_hkey {
	union silofs_hkey_u     keyu;
	uint64_t                hash;
	enum silofs_hkey_type   type;
};

/* caching-elements */
struct silofs_hmapq_elem {
	struct silofs_list_head hme_htb_lh;
	int64_t                 hme_htb_hitcnt;
	struct silofs_list_head hme_lru_lh;
	int64_t                 hme_lru_hitcnt;
	struct silofs_hkey      hme_key;
	struct silofs_dq_elem   hme_dqe;
	bool                    hme_mapped;
	bool                    hme_forgot;
	int32_t                 hme_refcnt;
	int32_t                 hme_magic;
};

/* LRU + hash-map */
struct silofs_hmapq {
	struct silofs_listq      hmq_lru;
	struct silofs_list_head *hmq_htbl;
	size_t hmq_htbl_nslots;
	size_t hmq_htbl_size;
};

/* iteration call-back function */
typedef int (*silofs_hmapq_elem_fn)(struct silofs_hmapq_elem *, void *);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_hkey_by_blobid(struct silofs_hkey *hkey,
                           const struct silofs_blobid *blobid);

void silofs_hkey_by_paddr(struct silofs_hkey *hkey,
                          const struct silofs_paddr *paddr);

void silofs_hkey_by_uaddr(struct silofs_hkey *hkey,
                          const struct silofs_uaddr *uaddr);

void silofs_hkey_by_vaddr(struct silofs_hkey *hkey,
                          const struct silofs_vaddr *vaddr);


long silofs_hkey_compare(const struct silofs_hkey *hkey1,
                         const struct silofs_hkey *hkey2);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_hmqe_init(struct silofs_hmapq_elem *hmqe, size_t sz);

void silofs_hmqe_fini(struct silofs_hmapq_elem *hmqe);

int silofs_hmqe_refcnt(const struct silofs_hmapq_elem *hmqe);

void silofs_hmqe_incref(struct silofs_hmapq_elem *hmqe);

void silofs_hmqe_decref(struct silofs_hmapq_elem *hmqe);

bool silofs_hmqe_is_evictable(const struct silofs_hmapq_elem *hmqe);

const struct silofs_hmapq_elem *
silofs_hmqe_from_dqe(const struct silofs_dq_elem *dqe);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

size_t silofs_hmapq_nslots_by(const struct silofs_alloc *alloc, uint8_t fac);

int silofs_hmapq_init(struct silofs_hmapq *hmapq,
                      struct silofs_alloc *alloc, size_t nslots);

void silofs_hmapq_fini(struct silofs_hmapq *hmapq, struct silofs_alloc *alloc);

struct silofs_hmapq_elem *
silofs_hmapq_lookup(const struct silofs_hmapq *hmapq,
                    const struct silofs_hkey *hkey);

void silofs_hmapq_store(struct silofs_hmapq *hmapq,
                        struct silofs_hmapq_elem *hmqe);

void silofs_hmapq_promote(struct silofs_hmapq *hmapq,
                          struct silofs_hmapq_elem *hmqe, bool now);

void silofs_hmapq_unmap(struct silofs_hmapq *hmapq,
                        struct silofs_hmapq_elem *hmqe);

void silofs_hmapq_remove(struct silofs_hmapq *hmapq,
                         struct silofs_hmapq_elem *hmqe);

struct silofs_hmapq_elem *
silofs_hmapq_get_lru(const struct silofs_hmapq *hmapq);

void silofs_hmapq_riterate(struct silofs_hmapq *hmapq, size_t limit,
                           silofs_hmapq_elem_fn cb, void *arg);

size_t silofs_hmapq_overpop(const struct silofs_hmapq *hmapq);

size_t silofs_hmapq_usage(const struct silofs_hmapq *hmapq);

#endif /* SILOFS_HMAPQ_H_ */
