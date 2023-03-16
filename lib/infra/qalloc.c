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
#include <silofs/consts.h>
#include <silofs/syscall.h>
#include <silofs/macros.h>
#include <silofs/list.h>
#include <silofs/utility.h>
#include <silofs/iovec.h>
#include <silofs/panic.h>
#include <silofs/logging.h>
#include <silofs/random.h>
#include <silofs/thread.h>
#include <silofs/atomic.h>
#include <silofs/qalloc.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>

#define QALLOC_MALLOC_SIZE_MAX  (64 * SILOFS_UMEGA)
#define QALLOC_PAGE_SIZE        (4 * SILOFS_KILO)

#define MPAGE_SIZE              QALLOC_PAGE_SIZE
#define MPAGE_NSEGS             (MPAGE_SIZE / MSLAB_SEG_SIZE)
#define MPAGES_LARGE_CHUNK      (16)

#define MSLAB_SEG_SIZE          (32)
#define MSLAB_SIZE_MIN          MSLAB_SEG_SIZE
#define MSLAB_SIZE_MAX          (QALLOC_PAGE_SIZE / 4)

#define MSLAB_INDEX_NONE        (0)

#define QALLOC_NSLABS           (MSLAB_SIZE_MAX / MSLAB_SIZE_MIN)

#define STATICASSERT_EQ(a_, b_) \
	SILOFS_STATICASSERT_EQ(a_, b_)

#define STATICASSERT_SIZEOF(t_, s_) \
	SILOFS_STATICASSERT_EQ(sizeof(t_), s_)

#define STATICASSERT_SIZEOF_GE(t_, s_) \
	SILOFS_STATICASSERT_GE(sizeof(t_), s_)

#define STATICASSERT_SIZEOF_LE(t_, s_) \
	SILOFS_STATICASSERT_LE(sizeof(t_), s_)


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* TODO: Use AVL instead of linked-list for free-chunks? */

struct silofs_slab_seg {
	struct silofs_list_head link;
	uint8_t pad[16];
} silofs_aligned32;


union silofs_page {
	struct silofs_slab_seg seg[MPAGE_NSEGS];
	uint8_t data[MPAGE_SIZE];
} silofs_packed_aligned64;


struct silofs_page_info {
	struct silofs_list_head  lh;
	struct silofs_page_info *prev;
	union silofs_page       *pg;
	size_t  pg_index;
	size_t  pg_count; /* num pages free/used */
	int     pg_free;
	int     slab_index;
	int     slab_nused;
	int     slab_nelems;
} __attribute__((__aligned__(SILOFS_CACHELINE_SIZE)));


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void static_assert_alloc_sizes(void)
{
	const struct silofs_qalloc *qal = NULL;

	STATICASSERT_SIZEOF(struct silofs_slab_seg, MSLAB_SEG_SIZE);
	STATICASSERT_SIZEOF(union silofs_page, MPAGE_SIZE);
	STATICASSERT_SIZEOF(struct silofs_page_info, 64);
	STATICASSERT_SIZEOF_LE(struct silofs_slab_seg, SILOFS_CACHELINE_SIZE);
	STATICASSERT_SIZEOF_GE(struct silofs_page_info, SILOFS_CACHELINE_SIZE);
	STATICASSERT_EQ(SILOFS_ARRAY_SIZE(qal->slabs), QALLOC_NSLABS);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_qalloc *alloc_to_qalloc(const struct silofs_alloc *alloc)
{
	const struct silofs_qalloc *qal;

	qal = silofs_container_of2(alloc, struct silofs_qalloc, alloc);
	return silofs_unconst(qal);
}

static void *qal_malloc(struct silofs_alloc *aif, size_t nbytes)
{
	struct silofs_qalloc *qal = alloc_to_qalloc(aif);

	return silofs_qalloc_malloc(qal, nbytes);
}

static void qal_free(struct silofs_alloc *aif, void *ptr, size_t nbytes)
{
	struct silofs_qalloc *qal = alloc_to_qalloc(aif);

	silofs_qalloc_free(qal, ptr, nbytes);
}

static void qal_stat(const struct silofs_alloc *alloc,
                     struct silofs_alloc_stat *out_stat)
{
	const struct silofs_qalloc *qal = alloc_to_qalloc(alloc);

	silofs_qalloc_stat(qal, out_stat);
}

static int qal_resolve(const struct silofs_alloc *alloc,
                       void *ptr, size_t len, struct silofs_iovec *iov)
{
	const struct silofs_qalloc *qal = alloc_to_qalloc(alloc);

	return silofs_qalloc_resolve(qal, ptr, len, iov);
}

void *silofs_allocate(struct silofs_alloc *alloc, size_t size)
{
	void *ptr;

	if (alloc->malloc_fn != NULL) {
		ptr = alloc->malloc_fn(alloc, size);
	} else {
		ptr = NULL;
	}
	return ptr;
}

void silofs_deallocate(struct silofs_alloc *alloc, void *ptr, size_t size)
{
	if ((ptr != NULL) && (size > 0) && (alloc->free_fn != NULL)) {
		alloc->free_fn(alloc, ptr, size);
	}
}

void silofs_allocstat(const struct silofs_alloc *alloc,
                      struct silofs_alloc_stat *out_stat)
{
	if (alloc->stat_fn != NULL) {
		alloc->stat_fn(alloc, out_stat);
	} else {
		memset(out_stat, 0, sizeof(*out_stat));
	}
}

int silofs_allocresolve(const struct silofs_alloc *alloc, void *ptr,
                        size_t len, struct silofs_iovec *iov)
{
	int ret = -ENOTSUP;

	if (alloc->resolve_fn != NULL) {
		ret = alloc->resolve_fn(alloc, ptr, len, iov);
	} else {
		memset(iov, 0, sizeof(*iov));
		iov->iov_fd = -1;
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_page_info *
pgi_from_lh(const struct silofs_list_head *lh)
{
	const struct silofs_page_info *pgi =
	        silofs_container_of2(lh, struct silofs_page_info, lh);

	return silofs_unconst(pgi);
}

static void pgi_update(struct silofs_page_info *pgi,
                       struct silofs_page_info *prev, size_t count)
{
	pgi->prev = prev;
	pgi->pg_count = count;
	pgi->pg_free = 1;
}

static void pgi_mute(struct silofs_page_info *pgi)
{
	pgi_update(pgi, NULL, 0);
}

static void pgi_init(struct silofs_page_info *pgi,
                     union silofs_page *pg, size_t pg_index)
{
	silofs_list_head_init(&pgi->lh);
	pgi_mute(pgi);
	pgi->pg = pg;
	pgi->pg_index = pg_index;
	pgi->slab_nused = 0;
	pgi->slab_index = MSLAB_INDEX_NONE;
}

static void pgi_push_head(struct silofs_page_info *pgi,
                          struct silofs_list_head *ls)
{
	silofs_list_push_front(ls, &pgi->lh);
}

static void pgi_push_tail(struct silofs_page_info *pgi,
                          struct silofs_list_head *ls)
{
	silofs_list_push_back(ls, &pgi->lh);
}

static void pgi_unlink(struct silofs_page_info *pgi)
{
	silofs_list_head_remove(&pgi->lh);
}

static void pgi_unlink_mute(struct silofs_page_info *pgi)
{
	pgi_unlink(pgi);
	pgi_mute(pgi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_slab_seg *
link_to_slab_seg(const struct silofs_list_head *link)
{
	const struct silofs_slab_seg *seg =
	        silofs_container_of2(link, struct silofs_slab_seg, link);

	return silofs_unconst(seg);
}

static struct silofs_list_head *slab_seg_to_link(struct silofs_slab_seg *seg)
{
	return &seg->link;
}

static bool slab_issize(size_t size)
{
	return ((size > 0) && (size <= MSLAB_SIZE_MAX));
}

static size_t slab_size_to_sindex(size_t size)
{
	silofs_assert(slab_issize(size));
	silofs_assert_gt(size, 0);

	return ((size - 1) / MSLAB_SEG_SIZE) + 1;
}

static void slab_init(struct silofs_slab *slab,
                      unsigned int sindex, unsigned int elemsz)
{
	silofs_list_init(&slab->free_list);
	slab->nfree = 0;
	slab->nused = 0;
	slab->elemsz = elemsz;
	slab->sindex = sindex;
}

static void slab_fini(struct silofs_slab *slab)
{
	silofs_list_init(&slab->free_list);
	slab->elemsz = 0;
	slab->nfree = 0;
	slab->nused = 0;
	slab->sindex = UINT_MAX;
}

static size_t slab_step_nsegs(const struct silofs_slab *slab)
{
	const struct silofs_slab_seg *seg = NULL;

	return SILOFS_DIV_ROUND_UP(slab->elemsz, sizeof(*seg));
}

static void slab_expand(struct silofs_slab *slab, struct silofs_page_info *pgi)
{
	struct silofs_slab_seg *seg;
	union silofs_page *pg = pgi->pg;
	const size_t step = slab_step_nsegs(slab);
	const size_t nsegs = SILOFS_ARRAY_SIZE(pg->seg);

	pgi->slab_index = (int)slab->sindex;
	pgi->slab_nelems = (int)(sizeof(*pg) / slab->elemsz);
	pgi->slab_nused = 0;
	for (size_t i = 0; (i + step) <= nsegs; i += step) {
		seg = &pg->seg[i];
		silofs_list_push_back(&slab->free_list, &seg->link);
		slab->nfree++;
	}
}

static void slab_shrink(struct silofs_slab *slab, struct silofs_page_info *pgi)
{
	struct silofs_slab_seg *seg;
	union silofs_page *pg = pgi->pg;
	const size_t step = slab_step_nsegs(slab);
	const size_t nsegs = SILOFS_ARRAY_SIZE(pg->seg);

	silofs_assert_eq(pgi->slab_index, slab->sindex);
	silofs_assert_eq(pgi->slab_nused, 0);

	for (size_t i = 0; (i + step) <= nsegs; i += step) {
		silofs_assert_gt(slab->nfree, 0);

		seg = &pg->seg[i];
		silofs_list_head_remove(&seg->link);
		slab->nfree--;
	}
	pgi->slab_index = MSLAB_INDEX_NONE;
	pgi->slab_nelems = 0;
}

static struct silofs_slab_seg *slab_alloc(struct silofs_slab *slab)
{
	struct silofs_list_head *lh;
	struct silofs_slab_seg *seg = NULL;

	lh = silofs_list_pop_front(&slab->free_list);
	if (lh == NULL) {
		return NULL;
	}
	silofs_list_head_init(lh);

	silofs_assert_gt(slab->nfree, 0);
	slab->nfree--;
	slab->nused++;

	seg = link_to_slab_seg(lh);
	return seg;
}

static void slab_free(struct silofs_slab *slab, struct silofs_slab_seg *seg)
{
	struct silofs_list_head *lh;

	lh = slab_seg_to_link(seg);
	silofs_list_push_front(&slab->free_list, lh);
	silofs_assert_gt(slab->nused, 0);
	slab->nused--;
	slab->nfree++;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int calc_mem_sizes(size_t npgs, size_t *msz_data, size_t *msz_meta)
{
	const size_t npgs_max = UINT_MAX; /* TODO: proper upper limit */

	if ((npgs == 0) || (npgs > npgs_max)) {
		return -EINVAL;
	}
	*msz_data = npgs * sizeof(union silofs_page);
	*msz_meta = npgs * sizeof(struct silofs_page_info);
	return 0;
}

static int memfd_setup(struct silofs_memfd *memfd,
                       const char *name, size_t size)
{
	void *mem = NULL;
	const int prot = PROT_READ | PROT_WRITE;
	const int flags = MAP_SHARED;
	int fd = -1;
	int err;

	err = silofs_sys_memfd_create(name, 0, &fd);
	if (err) {
		return err;
	}
	err = silofs_sys_ftruncate(fd, (loff_t)size);
	if (err) {
		silofs_sys_close(fd);
		return err;
	}
	err = silofs_sys_mmap(NULL, size, prot, flags, fd, 0, &mem);
	if (err) {
		silofs_sys_close(fd);
		return err;
	}
	memfd->fd = fd;
	memfd->mem = mem;
	return 0;
}

static int memfd_close(struct silofs_memfd *memfd, size_t memsz)
{
	int err;

	err = silofs_sys_munmap(memfd->mem, memsz);
	if (err) {
		return err;
	}
	err = silofs_sys_close(memfd->fd);
	if (err) {
		return err;
	}
	memfd->mem = NULL;
	memfd->fd = -1;
	return 0;
}

static uint32_t qalloc_unique_id(void)
{
	uint32_t rand;

	silofs_getentropy(&rand, sizeof(rand));
	return rand;
}

static int qalloc_setup_memsz_max(struct silofs_qalloc *qal, size_t npgs)
{
	return calc_mem_sizes(npgs, &qal->nbytes_data_max,
	                      &qal->nbytes_meta_max);
}

static int qalloc_init_memfd(struct silofs_qalloc *qal, size_t npgs)
{
	char name[256] = "";
	const pid_t pid = getpid();
	const uint32_t uniq = qalloc_unique_id();
	int err;

	err = qalloc_setup_memsz_max(qal, npgs);
	if (err) {
		return err;
	}
	snprintf(name, sizeof(name) - 1, "silofs-mem-data-%d-%08x", pid, uniq);
	err = memfd_setup(&qal->data, name, qal->nbytes_data_max);
	if (err) {
		return err;
	}
	snprintf(name, sizeof(name) - 1, "silofs-mem-meta-%d-%08x", pid, uniq);
	err = memfd_setup(&qal->meta, name, qal->nbytes_meta_max);
	if (err) {
		memfd_close(&qal->data, qal->nbytes_data_max);
		return err;
	}
	qal->nbytes_data_use = 0;
	qal->npages_data_max = npgs;
	return 0;
}

static int qalloc_fini_memfd(struct silofs_qalloc *qal)
{
	int err;

	if (!qal->npages_data_max) {
		return 0;
	}
	err = memfd_close(&qal->data, qal->nbytes_data_max);
	if (err) {
		return err;
	}
	err = memfd_close(&qal->meta, qal->nbytes_meta_max);
	if (err) {
		return err;
	}
	qal->nbytes_data_max = 0;
	qal->nbytes_meta_max = 0;
	return 0;
}

static void qalloc_init_slabs(struct silofs_qalloc *qal)
{
	unsigned int sindex;
	unsigned int elemsz;

	for (unsigned int i = 0; i < SILOFS_ARRAY_SIZE(qal->slabs); ++i) {
		sindex = i + 1;
		elemsz = sindex * MSLAB_SEG_SIZE;
		slab_init(&qal->slabs[i], sindex, elemsz);
	}
}

static void qalloc_fini_slabs(struct silofs_qalloc *qal)
{
	for (size_t i = 0; i < SILOFS_ARRAY_SIZE(qal->slabs); ++i) {
		slab_fini(&qal->slabs[i]);
	}
}

static void *qalloc_page_at(const struct silofs_qalloc *qal, size_t idx)
{
	union silofs_page *pg_arr = qal->data.mem;

	silofs_assert_lt(idx, qal->npages_data_max);

	return pg_arr + idx;
}

static struct silofs_page_info *
qalloc_page_info_at(const struct silofs_qalloc *qal, size_t idx)
{
	struct silofs_page_info *pgi_arr = qal->meta.mem;

	silofs_assert_lt(idx, qal->npages_data_max);

	return pgi_arr + idx;
}

static struct silofs_page_info *
qalloc_next(const struct silofs_qalloc *qal,
            const struct silofs_page_info *pgi, size_t npgs)
{
	const size_t idx_next = pgi->pg_index + npgs;
	struct silofs_page_info *pgi_next = NULL;

	if (idx_next < qal->npages_data_max) {
		pgi_next = qalloc_page_info_at(qal, idx_next);
	}
	return pgi_next;
}

static void qalloc_update(const struct silofs_qalloc *qal,
                          struct silofs_page_info *pgi, size_t npgs)
{
	struct silofs_page_info *pgi_next;

	pgi_next = qalloc_next(qal, pgi, npgs);
	if (pgi_next != NULL) {
		pgi_next->prev = pgi;
	}
}

static void qalloc_add_free(struct silofs_qalloc *qal,
                            struct silofs_page_info *pgi,
                            struct silofs_page_info *prev, size_t npgs)
{
	struct silofs_list_head *free_list = &qal->free_pgs;

	pgi_update(pgi, prev, npgs);
	qalloc_update(qal, pgi, npgs);
	if (npgs >= MPAGES_LARGE_CHUNK) {
		pgi_push_head(pgi, free_list);
	} else {
		pgi_push_tail(pgi, free_list);
	}
}

static void qalloc_init_pages(struct silofs_qalloc *qal)
{
	union silofs_page *pg;
	struct silofs_page_info *pgi;

	for (size_t i = 0; i < qal->npages_data_max; ++i) {
		pg = qalloc_page_at(qal, i);
		pgi = qalloc_page_info_at(qal, i);
		pgi_init(pgi, pg, i);
		qal->nbytes_meta_use += sizeof(*pgi);
	}

	silofs_list_init(&qal->free_pgs);
	pgi = qalloc_page_info_at(qal, 0);
	qalloc_add_free(qal, pgi, NULL, qal->npages_data_max);
}

static int check_memsize(size_t memsize)
{
	static_assert_alloc_sizes();

	if (memsize < (8 * SILOFS_UMEGA)) {
		return -EINVAL;
	}
	if (memsize > (64 * SILOFS_UGIGA)) {
		return -EINVAL;
	}
	return 0;
}

static void qalloc_init_interface(struct silofs_qalloc *qal)
{
	qal->alloc.malloc_fn = qal_malloc;
	qal->alloc.free_fn = qal_free;
	qal->alloc.stat_fn = qal_stat;
	qal->alloc.resolve_fn = qal_resolve;
}

static void qalloc_fini_interface(struct silofs_qalloc *qal)
{
	qal->alloc.malloc_fn = NULL;
	qal->alloc.free_fn = NULL;
	qal->alloc.stat_fn = NULL;
	qal->alloc.resolve_fn = NULL;
}

static int qalloc_init_mutex(struct silofs_qalloc *qal)
{
	return silofs_mutex_init(&qal->mutex);
}

static void qalloc_fini_mutex(struct silofs_qalloc *qal)
{
	silofs_mutex_fini(&qal->mutex);
}

int silofs_qalloc_init(struct silofs_qalloc *qal, size_t memsize, int mode)
{
	size_t npgs;
	int err;

	silofs_memzero(qal, sizeof(*qal));
	qal->page_size = MPAGE_SIZE;
	qal->mode = mode;

	err = check_memsize(memsize);
	if (err) {
		return err;
	}
	err = qalloc_init_mutex(qal);
	if (err) {
		return err;
	}
	npgs = memsize / qal->page_size;
	err = qalloc_init_memfd(qal, npgs);
	if (err) {
		qalloc_fini_mutex(qal);
		return err;
	}
	qalloc_init_pages(qal);
	qalloc_init_slabs(qal);
	qalloc_init_interface(qal);
	return 0;
}

int silofs_qalloc_fini(struct silofs_qalloc *qal)
{
	/* TODO: release all pending memory-elements in slabs */
	qalloc_fini_slabs(qal);
	qalloc_fini_interface(qal);
	qalloc_fini_mutex(qal);
	return qalloc_fini_memfd(qal);
}

static struct silofs_mutex *qalloc_mutex(const struct silofs_qalloc *qal)
{
	const struct silofs_mutex *mutex = &qal->mutex;

	return silofs_unconst(mutex);
}

static void qalloc_lock(const struct silofs_qalloc *qal)
{
	silofs_mutex_lock(qalloc_mutex(qal));
}

static void qalloc_unlock(const struct silofs_qalloc *qal)
{
	silofs_mutex_unlock(qalloc_mutex(qal));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t nbytes_to_npgs(size_t nbytes)
{
	return (nbytes + MPAGE_SIZE - 1) / MPAGE_SIZE;
}

static size_t npgs_to_nbytes(size_t npgs)
{
	return npgs * MPAGE_SIZE;
}

static loff_t qalloc_ptr_to_off(const struct silofs_qalloc *qal,
                                const void *ptr)
{
	return (const char *)ptr - (const char *)qal->data.mem;
}

static size_t qalloc_ptr_to_pgn(const struct silofs_qalloc *qal,
                                const void *ptr)
{
	const loff_t off = qalloc_ptr_to_off(qal, ptr);

	return (size_t)off / qal->page_size;
}

static bool qalloc_isinrange(const struct silofs_qalloc *qal,
                             const void *ptr, size_t nb)
{
	const loff_t off = qalloc_ptr_to_off(qal, ptr);
	const loff_t end = off + (loff_t)nb;

	return (off >= 0) && (end <= (loff_t)qal->nbytes_data_max);
}

static struct silofs_page_info *
qalloc_page_info_of(const struct silofs_qalloc *qal, const void *ptr)
{
	const size_t pgn = qalloc_ptr_to_pgn(qal, ptr);

	silofs_assert_lt(pgn, qal->npages_data_max);
	return qalloc_page_info_at(qal, pgn);
}

static struct silofs_slab_seg *
qalloc_slab_seg_of(const struct silofs_qalloc *qal, const void *ptr)
{
	loff_t off;
	size_t idx;
	struct silofs_slab_seg *seg = qal->data.mem;

	off = qalloc_ptr_to_off(qal, ptr);
	idx = (size_t)off / sizeof(*seg);

	return &seg[idx];
}

static struct silofs_page_info *
qalloc_search_free_from_tail(struct silofs_qalloc *qal, size_t npgs)
{
	struct silofs_page_info *pgi;
	struct silofs_list_head *itr;
	struct silofs_list_head *free_list = &qal->free_pgs;

	itr = free_list->prev;
	while (itr != free_list) {
		pgi = pgi_from_lh(itr);
		if (pgi->pg_count >= npgs) {
			return pgi;
		}
		itr = itr->prev;
	}
	return NULL;
}

static struct silofs_page_info *
qalloc_search_free_from_head(struct silofs_qalloc *qal, size_t npgs)
{
	struct silofs_page_info *pgi;
	struct silofs_list_head *itr;
	struct silofs_list_head *free_list = &qal->free_pgs;

	itr = free_list->next;
	while (itr != free_list) {
		pgi = pgi_from_lh(itr);
		if (pgi->pg_count >= npgs) {
			return pgi;
		}
		itr = itr->next;
	}
	return NULL;
}

static struct silofs_page_info *
qalloc_search_free_list(struct silofs_qalloc *qal, size_t npgs)
{
	struct silofs_page_info *pgi = NULL;

	if ((qal->npages_data_use + npgs) <= qal->npages_data_max) {
		if (npgs >= MPAGES_LARGE_CHUNK) {
			pgi = qalloc_search_free_from_head(qal, npgs);
		} else {
			pgi = qalloc_search_free_from_tail(qal, npgs);
		}
	}
	return pgi;
}

static struct silofs_page_info *
qalloc_alloc_npgs(struct silofs_qalloc *qal, size_t npgs)
{
	struct silofs_page_info *pgi;
	struct silofs_page_info *pgi_next = NULL;

	pgi = qalloc_search_free_list(qal, npgs);
	if (pgi == NULL) {
		return NULL;
	}

	pgi_unlink(pgi);
	pgi->pg_free = 0;
	if (pgi->pg_count > npgs) {
		pgi_next = qalloc_next(qal, pgi, npgs);
		qalloc_add_free(qal, pgi_next, pgi, pgi->pg_count - npgs);
		pgi->pg_count = npgs;
	}
	return pgi;
}

static size_t qalloc_slab_slot_of(const struct silofs_qalloc *qal, size_t size)
{
	const size_t sindex = slab_size_to_sindex(size);

	silofs_assert_le(sindex, SILOFS_ARRAY_SIZE(qal->slabs));
	silofs_assert_gt(sindex, 0);
	return sindex - 1;
}

static struct silofs_slab *
qalloc_slab_of(const struct silofs_qalloc *qal, size_t nbytes)
{
	const struct silofs_slab *slab = NULL;
	const size_t slot = qalloc_slab_slot_of(qal, nbytes);

	if (slot < SILOFS_ARRAY_SIZE(qal->slabs)) {
		slab = &qal->slabs[slot];
	}
	return silofs_unconst(slab);
}

static int qalloc_require_slab_space(struct silofs_qalloc *qal,
                                     struct silofs_slab *slab)
{
	struct silofs_page_info *pgi;

	if (slab->nfree > 0) {
		return 0;
	}
	pgi = qalloc_alloc_npgs(qal, 1);
	if (pgi == NULL) {
		return -ENOMEM;
	}
	slab_expand(slab, pgi);
	return 0;
}

static struct silofs_slab_seg *
qalloc_alloc_from_slab(struct silofs_qalloc *qal, struct silofs_slab *slab)
{
	struct silofs_slab_seg *seg;
	struct silofs_page_info *pgi;

	seg = slab_alloc(slab);
	if (seg == NULL) {
		return NULL;
	}
	pgi = qalloc_page_info_of(qal, seg);

	silofs_assert_lt(pgi->slab_nused, pgi->slab_nelems);
	pgi->slab_nused += 1;

	return seg;
}

static int qalloc_alloc_slab(struct silofs_qalloc *qal, size_t nbytes,
                             struct silofs_slab_seg **out_seg)
{
	struct silofs_slab *slab;
	struct silofs_slab_seg *seg;
	int err;

	slab = qalloc_slab_of(qal, nbytes);
	if (slab == NULL) {
		return -ENOMEM;
	}
	err = qalloc_require_slab_space(qal, slab);
	if (err) {
		return err;
	}
	seg = qalloc_alloc_from_slab(qal, slab);
	if (seg == NULL) {
		return -ENOMEM;
	}
	*out_seg = seg;
	return 0;
}

static int qalloc_check_alloc(const struct silofs_qalloc *qal, size_t nbytes)
{
	const size_t nbytes_max = QALLOC_MALLOC_SIZE_MAX;

	if (qal->data.mem == NULL) {
		return -ENOMEM;
	}
	if (nbytes > nbytes_max) {
		return -ENOMEM;
	}
	if (!nbytes) {
		return -EINVAL;
	}
	return 0;
}

static int qalloc_alloc_sub_pg(struct silofs_qalloc *qal,
                               size_t nbytes, void **out_ptr)
{
	struct silofs_slab_seg *seg;
	int err;

	err = qalloc_alloc_slab(qal, nbytes, &seg);
	if (err) {
		return err;
	}
	*out_ptr = seg;
	return 0;
}

static int qalloc_alloc_multi_pg(struct silofs_qalloc *qal,
                                 size_t nbytes, void **out_ptr)
{
	size_t npgs;
	struct silofs_page_info *pgi;

	npgs = nbytes_to_npgs(nbytes);
	pgi = qalloc_alloc_npgs(qal, npgs);
	if (pgi == NULL) {
		return -ENOMEM;
	}
	*out_ptr = pgi->pg->data;
	qal->npages_data_use += npgs;
	silofs_assert_ge(qal->npages_data_max, qal->npages_data_use);
	return 0;
}

static int qalloc_malloc(struct silofs_qalloc *qal,
                         size_t nbytes, void **out_ptr)
{
	int err;

	err = qalloc_check_alloc(qal, nbytes);
	if (err) {
		return err;
	}
	if (slab_issize(nbytes)) {
		err = qalloc_alloc_sub_pg(qal, nbytes, out_ptr);
	} else {
		err = qalloc_alloc_multi_pg(qal, nbytes, out_ptr);
	}
	if (err) {
		return err;
	}
	qal->nbytes_data_use += nbytes;
	return 0;
}

static void qalloc_require_malloc_ok(const struct silofs_qalloc *qal,
                                     size_t nbytes, int err)
{
	if (err) {
		silofs_log_debug("malloc failed: nbytes=%lu "
		                 "nbytes_data_max=%lu err=%d",
		                 nbytes, qal->nbytes_data_max, err);
	}
}

void *silofs_qalloc_malloc(struct silofs_qalloc *qal, size_t nbytes)
{
	void *ptr = NULL;
	int err;

	qalloc_lock(qal);
	err = qalloc_malloc(qal, nbytes, &ptr);
	qalloc_unlock(qal);
	qalloc_require_malloc_ok(qal, nbytes, err);
	return ptr;
}

static int qalloc_check_free(const struct silofs_qalloc *qal,
                             const void *ptr, size_t nbytes)
{
	if ((qal->data.mem == NULL) || (ptr == NULL)) {
		return -EINVAL;
	}
	if (!nbytes || (nbytes > QALLOC_MALLOC_SIZE_MAX)) {
		return -EINVAL;
	}
	if (!qalloc_isinrange(qal, ptr, nbytes)) {
		return -EINVAL;
	}
	return 0;
}

static void qalloc_punch_hole_at(const struct silofs_qalloc *qal,
                                 struct silofs_page_info *pgi, size_t npgs)
{
	loff_t off;
	ssize_t len;
	int mode;
	int err;

	off = (loff_t)npgs_to_nbytes(pgi->pg_index);
	len = (ssize_t)npgs_to_nbytes(npgs);
	mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;
	err = silofs_sys_fallocate(qal->data.fd, mode, off, len);
	if (err) {
		silofs_panic("failed to punch-hole in memory: off=%ld "
		             "len=%ld mode=0x%x err=%d", off, len, mode, err);
	}
}

static void qalloc_update_released(const struct silofs_qalloc *qal,
                                   struct silofs_page_info *pgi, size_t npgs)
{
	if (npgs >= (4 * MPAGES_LARGE_CHUNK)) {
		qalloc_punch_hole_at(qal, pgi, npgs);
	}
}

static int qalloc_free_npgs(struct silofs_qalloc *qal,
                            struct silofs_page_info *pgi, size_t npgs)
{
	struct silofs_page_info *pgi_next;
	struct silofs_page_info *pgi_prev;

	pgi_next = qalloc_next(qal, pgi, npgs);
	if (pgi_next && pgi_next->pg_free) {
		npgs += pgi_next->pg_count;
		pgi_unlink_mute(pgi_next);
	}
	pgi_prev = pgi->prev;
	if (pgi_prev && pgi_prev->pg_free) {
		npgs += pgi_prev->pg_count;
		pgi_mute(pgi);
		pgi = pgi_prev;
		pgi_prev = pgi_prev->prev;
		pgi_unlink_mute(pgi);
	}

	qalloc_update_released(qal, pgi, npgs);
	qalloc_add_free(qal, pgi, pgi_prev, npgs);
	return 0;
}

static void qalloc_free_to_slab(struct silofs_qalloc *qal,
                                struct silofs_slab *slab,
                                struct silofs_slab_seg *seg)
{
	struct silofs_page_info *pgi = qalloc_page_info_of(qal, seg);

	silofs_assert_eq(pgi->slab_index, slab->sindex);
	slab_free(slab, seg);

	silofs_assert_le(pgi->slab_nused, pgi->slab_nelems);
	silofs_assert_gt(pgi->slab_nused, 0);
	pgi->slab_nused -= 1;
	if (!pgi->slab_nused) {
		slab_shrink(slab, pgi);
		qalloc_free_npgs(qal, pgi, 1);
	}
}

static int qalloc_check_at_slab(const struct silofs_qalloc *qal,
                                const struct silofs_slab_seg *seg, size_t nb)
{
	const struct silofs_slab *slab;
	const struct silofs_page_info *pgi;
	const size_t seg_size = MSLAB_SEG_SIZE;

	slab = qalloc_slab_of(qal, nb);
	if (slab == NULL) {
		return -EINVAL;
	}
	if (!slab->nused) {
		return -EINVAL;
	}
	if (nb > slab->elemsz) {
		return -EINVAL;
	}
	if ((nb + seg_size) < slab->elemsz) {
		return -EINVAL;
	}
	pgi = qalloc_page_info_of(qal, seg);
	if (pgi->slab_index != ((int)slab->sindex)) {
		return -EINVAL;
	}
	if (pgi->slab_nused == 0) {
		return -EINVAL;
	}
	return 0;
}

static int qalloc_free_slab(struct silofs_qalloc *qal,
                            struct silofs_slab_seg *seg, size_t nbytes)
{
	struct silofs_slab *slab;
	int err;

	slab = qalloc_slab_of(qal, nbytes);
	if (slab == NULL) {
		return -EINVAL;
	}
	err = qalloc_check_at_slab(qal, seg, nbytes);
	if (err) {
		return err;
	}
	qalloc_free_to_slab(qal, slab, seg);
	return 0;
}

static int qalloc_free_sub_pg(struct silofs_qalloc *qal,
                              void *ptr, size_t nbytes)
{
	struct silofs_slab_seg *seg;

	seg = qalloc_slab_seg_of(qal, ptr);
	return qalloc_free_slab(qal, seg, nbytes);
}

static int qalloc_check_by_page(const struct silofs_qalloc *qal,
                                const void *ptr, size_t nbytes)
{
	size_t npgs;
	const struct silofs_page_info *pgi;

	npgs = nbytes_to_npgs(nbytes);
	if (qal->npages_data_use < npgs) {
		return -EINVAL;
	}
	pgi = qalloc_page_info_of(qal, ptr);
	if (pgi == NULL) {
		return -EINVAL;
	}
	if (pgi->pg_count != npgs) {
		return -EINVAL;
	}
	return 0;
}

static int qalloc_free_multi_pg(struct silofs_qalloc *qal,
                                void *ptr, size_t nbytes)
{
	struct silofs_page_info *pgi;
	size_t npgs;
	int err;

	err = qalloc_check_by_page(qal, ptr, nbytes);
	if (err) {
		return err;
	}
	npgs = nbytes_to_npgs(nbytes);
	pgi = qalloc_page_info_of(qal, ptr);
	qalloc_free_npgs(qal, pgi, npgs);
	qal->npages_data_use -= npgs;
	return 0;
}

static void *
qalloc_base_of(const struct silofs_qalloc *qal, void *ptr, size_t len)
{
	struct silofs_slab_seg *seg = NULL;
	const struct silofs_page_info *pgi = NULL;
	void *base = NULL;

	if (!qalloc_isinrange(qal, ptr, len)) {
		return NULL;
	}
	if (slab_issize(len)) {
		seg = qalloc_slab_seg_of(qal, ptr);
		if (seg != NULL) {
			base = seg;
		}
	} else {
		pgi = qalloc_page_info_of(qal, ptr);
		if (pgi != NULL) {
			base = pgi->pg;
		}
	}
	return base;
}

static void
qalloc_wreck_data(const struct silofs_qalloc *qal, void *ptr, size_t nbytes)
{
	silofs_assert_ge(qal->nbytes_data_use, nbytes);

	if (qal->mode && ptr) {
		memset(ptr, 0xF3, silofs_min(512, nbytes));
	}
}

static int qalloc_free(struct silofs_qalloc *qal, void *ptr, size_t nbytes)
{
	int err;

	if ((ptr == NULL) || (nbytes == 0)) {
		return 0;
	}
	err = qalloc_check_free(qal, ptr, nbytes);
	if (err) {
		return err;
	}
	qalloc_wreck_data(qal, ptr, nbytes);
	if (slab_issize(nbytes)) {
		err = qalloc_free_sub_pg(qal, ptr, nbytes);
	} else {
		err = qalloc_free_multi_pg(qal, ptr, nbytes);
	}
	if (err) {
		return err;
	}
	qal->nbytes_data_use -= nbytes;
	return err;
}

static void qalloc_require_free_ok(const struct silofs_qalloc *qal,
                                   const void *ptr, size_t nbytes, int err)
{
	if (err) {
		silofs_panic("free error: ptr=%p nbytes=%lu memsz_data=%lu "
		             "err=%d", ptr, nbytes, qal->nbytes_data_max, err);
	}
}

void silofs_qalloc_free(struct silofs_qalloc *qal, void *ptr, size_t nbytes)
{
	int err;

	qalloc_lock(qal);
	err = qalloc_free(qal, ptr, nbytes);
	qalloc_unlock(qal);
	qalloc_require_free_ok(qal, ptr, nbytes, err);
}

static int qalloc_check_by_slab(const struct silofs_qalloc *qal,
                                const void *ptr, size_t nbytes)
{
	const struct silofs_slab_seg *seg;
	int err = -EINVAL;

	seg = qalloc_slab_seg_of(qal, ptr);
	if (seg != NULL) {
		err = qalloc_check_at_slab(qal, seg, nbytes);
	}
	return err;
}

int silofs_qalloc_mcheck(const struct silofs_qalloc *qal,
                         const void *ptr, size_t nbytes)
{
	int err;

	if ((ptr == NULL) || (nbytes == 0)) {
		return 0;
	}
	err = qalloc_check_free(qal, ptr, nbytes);
	if (err) {
		return err;
	}
	if (slab_issize(nbytes)) {
		err = qalloc_check_by_slab(qal, ptr, nbytes);
	} else {
		err = qalloc_check_by_page(qal, ptr, nbytes);
	}
	return err;
}

/*
 * Do not use qalloc_lock/unlock for qalloc_resolve and qalloc_stat as those
 * operations need to be fast and are executed on the data-path. As such, it is
 * better to avoid the heavy locking involved with alloc/dealloc path.
 */
int silofs_qalloc_resolve(const struct silofs_qalloc *qal,
                          void *ptr, size_t len, struct silofs_iovec *iov)
{
	const void *base;

	base = qalloc_base_of(qal, ptr, len);
	if (silofs_unlikely(base == NULL)) {
		return -ERANGE;
	}
	if (silofs_unlikely(base > ptr)) {
		return -ERANGE;
	}
	iov->iov_off = qalloc_ptr_to_off(qal, ptr);
	iov->iov_len = len;
	iov->iov_base = ptr;
	iov->iov_fd = qal->data.fd;
	iov->iov_ref = NULL;
	return 0;
}

void silofs_qalloc_stat(const struct silofs_qalloc *qal,
                        struct silofs_alloc_stat *out_stat)
{
	out_stat->nbytes_max = qal->nbytes_meta_max + qal->nbytes_data_max;
	out_stat->nbytes_use = qal->nbytes_meta_use + qal->nbytes_data_use;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/
/* memory utilities */

void silofs_memzero(void *s, size_t n)
{
	memset(s, 0, n);
}

void silofs_memffff(void *s, size_t n)
{
	memset(s, 0xff, n);
}

static size_t alignment_of(size_t sz)
{
	const size_t al_min = 64;
	const size_t al_max = 65536;
	size_t al;

	if (sz <= al_min) {
		al = al_min;
	} else if (sz >= al_max) {
		al = al_max;
	} else {
		al = 1 << (64 - silofs_clz64(sz - 1));
	}
	return al;
}

static int cstd_memalign(size_t sz, void **out_mem)
{
	return posix_memalign(out_mem, alignment_of(sz), sz);
}

static void cstd_memfree(void *mem, size_t sz)
{
	if (mem && sz) {
		free(mem);
	}
}

int silofs_zmalloc(size_t sz, void **out_mem)
{
	int err;

	err = cstd_memalign(sz, out_mem);
	if (!err) {
		silofs_memzero(*out_mem, sz);
	}
	return err;
}

void silofs_zfree(void *mem, size_t sz)
{
	silofs_memzero(mem, sz);
	cstd_memfree(mem, sz);
}

static void burnstack_recursively(int depth, int nbytes)
{
	char buf[512];
	const int cnt = silofs_min32((int)sizeof(buf), nbytes);

	if (cnt > 0) {
		memset(buf, 0xF4 ^ depth, (size_t)cnt);
		burnstack_recursively(depth + 1, nbytes - cnt);
	}
}

void silofs_burnstackn(int n)
{
	burnstack_recursively(0, n);
}

void silofs_burnstack(void)
{
	silofs_burnstackn((int)silofs_sc_page_size());
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_calloc *
alloc_to_calloc(const struct silofs_alloc *alloc)
{
	const struct silofs_calloc *cal;

	cal = silofs_container_of2(alloc, struct silofs_calloc, alloc);
	return silofs_unconst(cal);
}

static void *calloc_malloc(struct silofs_calloc *cal, size_t size)
{
	void *mem = NULL;
	int err;

	err = cstd_memalign(size, &mem);
	if (err) {
		return NULL;
	}
	silofs_atomic_addul(&cal->nbytes_use, size);
	return mem;
}

static void calloc_free(struct silofs_calloc *cal,
                        void *ptr, size_t size)
{
	if ((ptr != NULL) && (size > 0)) {
		cstd_memfree(ptr, size);
		silofs_atomic_subul(&cal->nbytes_use, size);
	}
}

static int calloc_resolve(struct silofs_calloc *cal,
                          void *ptr, size_t len, struct silofs_iovec *iov)
{
	memset(iov, 0, sizeof(*iov));
	iov->iov_base = ptr;
	iov->iov_len = len;
	iov->iov_fd = -1;
	silofs_unused(cal);
	return 0;
}

static void calloc_stat(struct silofs_calloc *cal,
                        struct silofs_alloc_stat *out_stat)
{
	out_stat->nbytes_max = silofs_atomic_getul(&cal->nbytes_max);
	out_stat->nbytes_use = silofs_atomic_getul(&cal->nbytes_use);
}

static void *cal_malloc(struct silofs_alloc *alloc, size_t size)
{
	return calloc_malloc(alloc_to_calloc(alloc), size);
}

static void cal_free(struct silofs_alloc *alloc, void *ptr, size_t size)
{
	calloc_free(alloc_to_calloc(alloc), ptr, size);
}

static void cal_stat(const struct silofs_alloc *alloc,
                     struct silofs_alloc_stat *out_stat)
{
	calloc_stat(alloc_to_calloc(alloc), out_stat);
}

static int cal_resolve(const struct silofs_alloc *alloc, void *ptr,
                       size_t len, struct silofs_iovec *iov)
{
	return calloc_resolve(alloc_to_calloc(alloc), ptr, len, iov);
}

int silofs_calloc_init(struct silofs_calloc *cal, size_t memsize)
{
	silofs_memzero(cal, sizeof(*cal));
	cal->alloc.malloc_fn = cal_malloc;
	cal->alloc.free_fn = cal_free;
	cal->alloc.stat_fn = cal_stat;
	cal->alloc.resolve_fn = cal_resolve;
	cal->nbytes_max = memsize;
	return 0;
}

int silofs_calloc_fini(struct silofs_calloc *cal)
{
	silofs_memzero(cal, sizeof(*cal));
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int getmemlimit(size_t *out_lim)
{
	struct rlimit rlim = { .rlim_cur = 0 };
	int err;

	err = silofs_sys_getrlimit(RLIMIT_AS, &rlim);
	*out_lim = err ? 0 : rlim.rlim_cur;
	return err;
}

int silofs_memory_limits(size_t *out_phy, size_t *out_as)
{
	const long page_size = silofs_sc_page_size();
	const long phys_pages = silofs_sc_phys_pages();

	*out_phy = (size_t)(page_size * phys_pages);
	return getmemlimit(out_as);
}
