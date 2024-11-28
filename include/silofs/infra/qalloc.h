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
#ifndef SILOFS_QALLOC_H_
#define SILOFS_QALLOC_H_

#include <stdint.h>

struct silofs_iovec;

/* allocation flags */
enum silofs_allocf {
	SILOFS_ALLOCF_NONE     = 0x00,
	SILOFS_ALLOCF_BZERO    = 0x01,
	SILOFS_ALLOCF_TRYPUNCH = 0x02,
	SILOFS_ALLOCF_NOPUNCH  = 0x04,
};

/* allocator stats */
struct silofs_alloc_stat {
	size_t nbytes_max;
	size_t nbytes_use;
	size_t nbytes_ext;
};

/* allocator interface */
struct silofs_alloc {
	void *(*malloc_fn)(struct silofs_alloc *alloc, size_t size, int flags);
	void (*free_fn)(struct silofs_alloc *alloc, void *ptr, size_t size,
			int flags);
	void (*stat_fn)(const struct silofs_alloc *alloc,
			struct silofs_alloc_stat  *out_stat);
};

/* quick memory allocator */
enum silofs_qallocf {
	SILOFS_QALLOCF_NONE   = 0x0,
	SILOFS_QALLOCF_DEMASK = 0x1,
	SILOFS_QALLOCF_NOFAIL = 0x2,
};

struct silofs_memfd {
	void  *mem;
	size_t msz;
	int    fd;
};

struct silofs_qpool {
	struct silofs_list_head free_pgs;
	struct silofs_mutex     mutex;
	struct silofs_memfd     data;
	struct silofs_memfd     meta;
	size_t                  npgs_max;
	size_t                  npgs_use;
	uint32_t                unique_id;
	enum silofs_qallocf     flags;
};

struct silofs_slab {
	struct silofs_list_head free_list;
	struct silofs_qpool    *qpool;
	struct silofs_mutex     mutex;
	size_t                  nfree;
	size_t                  nused;
	uint32_t                elemsz;
	int32_t                 sindex;
};

struct silofs_qalloc {
	struct silofs_slab  slabs[12];
	struct silofs_qpool qpool;
	struct silofs_alloc alloc;
	size_t              nbytes_use;
	int64_t             magic;
};

/* allocator via standard C malloc/free */
struct silofs_calloc {
	struct silofs_alloc alloc;
	unsigned long       nbytes_max;
	unsigned long       nbytes_use;
};

/* memory allocation convenience wrappers */
void *silofs_memalloc(struct silofs_alloc *alloc, size_t size, int flags);

void silofs_memfree(struct silofs_alloc *alloc, void *ptr, size_t size,
		    int flags);

void silofs_memstat(const struct silofs_alloc *alloc,
		    struct silofs_alloc_stat  *out_stat);

/* standard C allocator */
int silofs_calloc_init(struct silofs_calloc *cal, size_t memsize);

int silofs_calloc_fini(struct silofs_calloc *cal);

/* quick allocator */
int silofs_qalloc_init(struct silofs_qalloc *qal, size_t memsize,
		       enum silofs_qallocf flags);

int silofs_qalloc_fini(struct silofs_qalloc *qal);

void *
silofs_qalloc_malloc(struct silofs_qalloc *qal, size_t nbytes, int flags);

void silofs_qalloc_free(struct silofs_qalloc *qal, void *ptr, size_t nbytes,
			int flags);

void silofs_qalloc_stat(const struct silofs_qalloc *qal,
			struct silofs_alloc_stat   *out_stat);

int silofs_qalloc_resolve(const struct silofs_qalloc *qal, void *ptr,
			  size_t len, struct silofs_iovec *iov);

int silofs_qalloc_mcheck(const struct silofs_qalloc *qal, const void *ptr,
			 size_t nbytes);

/* extra memory utilities */
void silofs_memzero(void *s, size_t n);

void silofs_memffff(void *s, size_t n);

int silofs_zmalloc(size_t sz, void **out_mem);

void silofs_zfree(void *mem, size_t sz);

int silofs_memory_limits(size_t *out_phy, size_t *out_as);

#endif /* SILOFS_QALLOC_H_ */
