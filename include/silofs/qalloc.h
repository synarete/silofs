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
#ifndef SILOFS_QALLOC_H_
#define SILOFS_QALLOC_H_

struct silofs_iovec;

/* allocator stats */
struct silofs_alloc_stat {
	size_t nbytes_max;
	size_t nbytes_use;
	size_t nbytes_ext;
};

/* allocator interface */
struct silofs_alloc {
	void *(*malloc_fn)(struct silofs_alloc *alloc, size_t size);
	void (*free_fn)(struct silofs_alloc *alloc, void *ptr, size_t size);
	void (*stat_fn)(const struct silofs_alloc *alloc,
	                struct silofs_alloc_stat *out_stat);
	int (*resolve_fn)(const struct silofs_alloc *alloc,
	                  void *ptr, size_t len, struct silofs_iovec *iov);
};

/* quick memory allocator */
struct silofs_slab {
	struct silofs_list_head free_list;
	size_t   nfree;
	size_t   nused;
	uint32_t sindex;
	uint32_t elemsz;
};

struct silofs_memfd {
	void   *mem;
	int     fd;
};

struct silofs_qalloc {
	struct silofs_slab      slabs[32];
	struct silofs_list_head free_pgs;
	struct silofs_alloc     alloc;
	struct silofs_mutex     mutex;
	struct silofs_memfd     data;
	struct silofs_memfd     meta;
	size_t                  page_size;
	size_t                  npages_data_max;
	size_t                  npages_data_use;
	size_t                  nbytes_data_max;
	size_t                  nbytes_data_use;
	size_t                  nbytes_meta_max;
	size_t                  nbytes_meta_use;
	int                     mode;
};

/* allocator via standard C malloc/free */
struct silofs_calloc {
	struct silofs_alloc     alloc;
	unsigned long           nbytes_max;
	unsigned long           nbytes_use;

};

/* allocation via interface */
void *silofs_allocate(struct silofs_alloc *alloc, size_t size);

void silofs_deallocate(struct silofs_alloc *alloc, void *ptr, size_t size);

void silofs_allocstat(const struct silofs_alloc *alloc,
                      struct silofs_alloc_stat *out_stat);

int silofs_allocresolve(const struct silofs_alloc *alloc, void *ptr,
                        size_t len, struct silofs_iovec *iov);

/* allocator via standard C malloc/free */
int silofs_calloc_init(struct silofs_calloc *cal, size_t memsize);

int silofs_calloc_fini(struct silofs_calloc *cal);

/* quick allocator */
int silofs_qalloc_init(struct silofs_qalloc *qal, size_t memsize, int mode);

int silofs_qalloc_fini(struct silofs_qalloc *qal);

void *silofs_qalloc_malloc(struct silofs_qalloc *qal, size_t nbytes);

void silofs_qalloc_free(struct silofs_qalloc *qal, void *ptr, size_t nbytes);

void silofs_qalloc_stat(const struct silofs_qalloc *qal,
                        struct silofs_alloc_stat *out_stat);

int silofs_qalloc_resolve(const struct silofs_qalloc *qal,
                          void *ptr, size_t len, struct silofs_iovec *iov);

int silofs_qalloc_mcheck(const struct silofs_qalloc *qal,
                         const void *ptr, size_t nbytes);


/* memory utilities */
void silofs_burnstackn(int n);

void silofs_burnstack(void);

void silofs_memzero(void *s, size_t n);

void silofs_memffff(void *s, size_t n);

int silofs_zmalloc(size_t sz, void **out_mem);

void silofs_zfree(void *mem, size_t sz);

int silofs_memory_limits(size_t *out_phy, size_t *out_as);


#endif /* SILOFS_QALLOC_H_ */
