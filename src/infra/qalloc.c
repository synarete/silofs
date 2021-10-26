/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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
#include <silofs/infra/consts.h>
#include <silofs/infra/syscall.h>
#include <silofs/infra/macros.h>
#include <silofs/infra/list.h>
#include <silofs/infra/utility.h>
#include <silofs/infra/fiovec.h>
#include <silofs/infra/errors.h>
#include <silofs/infra/logging.h>
#include <silofs/infra/random.h>
#include <silofs/infra/qalloc.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <limits.h>

#define QALLOC_PAGE_SHIFT       SILOFS_PAGE_SHIFT
#define QALLOC_PAGE_SIZE        SILOFS_PAGE_SIZE
#define QALLOC_PAGE_SIZE_MAX    SILOFS_PAGE_SIZE_MAX

#define MPAGE_NSEGS             (QALLOC_PAGE_SIZE / MSLAB_SEG_SIZE)
#define MPAGES_IN_HOLE          (2 * (QALLOC_PAGE_SIZE_MAX / QALLOC_PAGE_SIZE))
#define MSLAB_SHIFT_MIN         (4)
#define MSLAB_SHIFT_MAX         (QALLOC_PAGE_SHIFT - 1)
#define MSLAB_SIZE_MIN          (1U << MSLAB_SHIFT_MIN)
#define MSLAB_SIZE_MAX          (1U << MSLAB_SHIFT_MAX)
#define MSLAB_SEG_SIZE          (MSLAB_SIZE_MIN)
#define MSLAB_INDEX_NONE        (-1)

#define QALLOC_MALLOC_SIZE_MAX  (64 * SILOFS_UMEGA)
#define QALLOC_CACHELINE_SIZE   SILOFS_CACHELINE_SIZE
#define QALLOC_NSLABS           (QALLOC_PAGE_SHIFT - MSLAB_SHIFT_MIN)

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
} silofs_aligned;


union silofs_page {
	struct silofs_slab_seg seg[MPAGE_NSEGS];
	uint8_t data[QALLOC_PAGE_SIZE];
} silofs_packed_aligned64;


struct silofs_page_info {
	struct silofs_page_info *prev;
	union silofs_page *pg;
	struct silofs_list_head link;
	size_t pg_index;
	size_t pg_count; /* num pages free/used */
	int pg_free;
	int slab_index;
	int slab_nused;
	int slab_nelems;
} __attribute__((__aligned__(SILOFS_CACHELINE_SIZE)));


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void static_assert_alloc_sizes(void)
{
	const struct silofs_qalloc *qal = NULL;

	STATICASSERT_SIZEOF(struct silofs_slab_seg, 16);
	STATICASSERT_SIZEOF(struct silofs_slab_seg, MSLAB_SEG_SIZE);
	STATICASSERT_SIZEOF(union silofs_page, QALLOC_PAGE_SIZE);
	STATICASSERT_SIZEOF(struct silofs_page_info, 64);
	STATICASSERT_SIZEOF_LE(struct silofs_slab_seg, QALLOC_CACHELINE_SIZE);
	STATICASSERT_SIZEOF_GE(struct silofs_page_info, QALLOC_CACHELINE_SIZE);
	STATICASSERT_EQ(SILOFS_ARRAY_SIZE(qal->slabs), QALLOC_NSLABS);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_qalloc *alif_to_qal(const struct silofs_alloc_if *alif)
{
	const struct silofs_qalloc *qal;

	qal = silofs_container_of2(alif, struct silofs_qalloc, alif);
	return silofs_unconst(qal);
}

static void *qal_malloc(struct silofs_alloc_if *aif, size_t nbytes)
{
	struct silofs_qalloc *qal = alif_to_qal(aif);

	return silofs_qalloc_malloc(qal, nbytes);
}

static void qal_free(struct silofs_alloc_if *aif, void *ptr, size_t nbytes)
{
	struct silofs_qalloc *qal = alif_to_qal(aif);

	silofs_qalloc_free(qal, ptr, nbytes);
}

static void qal_stat(const struct silofs_alloc_if *alif,
                     struct silofs_alloc_stat *out_stat)
{
	const struct silofs_qalloc *qal = alif_to_qal(alif);

	silofs_qalloc_stat(qal, out_stat);
}

static int qal_resolve(const struct silofs_alloc_if *alif, void *ptr,
                       size_t len, struct silofs_fiovec *fiov)
{
	const struct silofs_qalloc *qal = alif_to_qal(alif);

	return silofs_qalloc_resolve(qal, ptr, len, fiov);
}

void *silofs_allocate(struct silofs_alloc_if *alif, size_t size)
{
	return alif->malloc_fn(alif, size);
}

void silofs_deallocate(struct silofs_alloc_if *alif, void *ptr, size_t size)
{
	if ((ptr != NULL) && (size > 0)) {
		alif->free_fn(alif, ptr, size);
	}
}

void silofs_allocstat(const struct silofs_alloc_if *alif,
                      struct silofs_alloc_stat *out_stat)
{
	alif->stat_fn(alif, out_stat);
}

int silofs_allocresolve(const struct silofs_alloc_if *alif, void *ptr,
                        size_t len, struct silofs_fiovec *fiov)
{
	return alif->resolve_fn(alif, ptr, len, fiov);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_page_info *
link_to_page_info(const struct silofs_list_head *link)
{
	const struct silofs_page_info *pgi =
	        silofs_container_of2(link, struct silofs_page_info, link);

	return silofs_unconst(pgi);
}

static void page_info_update(struct silofs_page_info *pgi,
                             struct silofs_page_info *prev, size_t count)
{
	pgi->prev = prev;
	pgi->pg_count = count;
	pgi->pg_free = 1;
}

static void page_info_mute(struct silofs_page_info *pgi)
{
	page_info_update(pgi, NULL, 0);
}

static void page_info_init(struct silofs_page_info *pgi,
                           union silofs_page *pg, size_t pg_index)
{
	silofs_list_head_init(&pgi->link);
	page_info_mute(pgi);
	pgi->pg = pg;
	pgi->pg_index = pg_index;
	pgi->slab_nused = 0;
	pgi->slab_index = MSLAB_INDEX_NONE;
}

static void page_info_push_head(struct silofs_page_info *pgi,
                                struct silofs_list_head *ls)
{
	silofs_list_push_front(ls, &pgi->link);
}

static void page_info_push_tail(struct silofs_page_info *pgi,
                                struct silofs_list_head *ls)
{
	silofs_list_push_back(ls, &pgi->link);
}

static void page_info_unlink(struct silofs_page_info *pgi)
{
	silofs_list_head_remove(&pgi->link);
}

static void page_info_unlink_mute(struct silofs_page_info *pgi)
{
	page_info_unlink(pgi);
	page_info_mute(pgi);
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

static size_t slab_size_to_nlz(size_t size)
{
	const size_t shift = MSLAB_SHIFT_MIN;

	return silofs_clz32(((unsigned int)size - 1) >> shift);
}

static int slab_size_to_index(size_t size, size_t *out_index)
{
	size_t idx;
	size_t nlz;

	if (!slab_issize(size)) {
		return -EINVAL;
	}
	nlz = slab_size_to_nlz(size);
	if (!nlz || (nlz > 32)) {
		return -EINVAL;
	}
	idx = 32 - nlz;
	if (idx >= QALLOC_NSLABS) {
		return -EINVAL;
	}
	*out_index = idx;
	return 0;
}

static void slab_init(struct silofs_slab *slab, size_t sindex, size_t elemsz)
{
	int err;
	size_t index_by_elemsz = 0;

	err = slab_size_to_index(elemsz, &index_by_elemsz);
	if (err || (sindex != index_by_elemsz)) {
		silofs_panic("slab: index=%lu elemsz=%lu", sindex, elemsz);
	}
	silofs_list_init(&slab->free_list);
	slab->elemsz = elemsz;
	slab->nfree = 0;
	slab->nused = 0;
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

static void slab_expand(struct silofs_slab *slab, struct silofs_page_info *pgi)
{
	struct silofs_slab_seg *seg;
	union silofs_page *pg = pgi->pg;
	const size_t step = slab->elemsz / sizeof(*seg);

	pgi->slab_index = (int)slab->sindex;
	pgi->slab_nelems = (int)(sizeof(*pg) / slab->elemsz);
	pgi->slab_nused = 0;
	for (size_t i = 0; i < SILOFS_ARRAY_SIZE(pg->seg); i += step) {
		seg = &pg->seg[i];
		silofs_list_push_back(&slab->free_list, &seg->link);
		slab->nfree++;
	}
}

static void slab_shrink(struct silofs_slab *slab, struct silofs_page_info *pgi)
{
	struct silofs_slab_seg *seg;
	union silofs_page *pg = pgi->pg;
	const size_t step = slab->elemsz / sizeof(*seg);

	silofs_assert_eq(pgi->slab_index, slab->sindex);
	silofs_assert_eq(pgi->slab_nused, 0);

	for (size_t i = 0; i < SILOFS_ARRAY_SIZE(pg->seg); i += step) {
		silofs_assert_gt(slab->nfree, 0);

		seg = &pg->seg[i];
		silofs_list_head_remove(&seg->link);
		slab->nfree--;
	}
	pgi->slab_index = -1;
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

static int resolve_mem_sizes(size_t npgs, size_t *msz_data, size_t *msz_meta)
{
	const size_t npgs_max = UINT_MAX; /* TODO: proper upper limit */

	if ((npgs == 0) || (npgs > npgs_max)) {
		return -EINVAL;
	}
	*msz_data = npgs * sizeof(union silofs_page);
	*msz_meta = npgs * sizeof(struct silofs_page_info);
	return 0;
}

static int memfd_setup(const char *name, size_t size,
                       int *out_fd, void **out_mem)
{
	int err;
	int fd = -1;
	void *mem = NULL;
	const int prot = PROT_READ | PROT_WRITE;
	const int flags = MAP_SHARED;

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
	*out_fd = fd;
	*out_mem = mem;
	return 0;
}

static int memfd_close(int fd, void *mem, size_t memsz)
{
	int err;

	err = silofs_sys_munmap(mem, memsz);
	if (err) {
		return err;
	}
	err = silofs_sys_close(fd);
	if (err) {
		return err;
	}
	return 0;
}

static uint32_t qalloc_unique_id(void)
{
	uint32_t rand;

	silofs_getentropy(&rand, sizeof(rand));
	return rand;
}

static int qalloc_init_memfd(struct silofs_qalloc *qal, size_t npgs)
{
	int err;
	char name[256] = "";
	const pid_t pid = getpid();
	const uint32_t uniq = qalloc_unique_id();

	err = resolve_mem_sizes(npgs, &qal->st.memsz_data,
	                        &qal->st.memsz_meta);
	if (err) {
		return err;
	}
	snprintf(name, sizeof(name) - 1, "silofs-mem-data-%d-%08x", pid, uniq);
	err = memfd_setup(name, qal->st.memsz_data,
	                  &qal->memfd_data, &qal->mem_data);
	if (err) {
		return err;
	}
	snprintf(name, sizeof(name) - 1, "silofs-mem-meta-%d-%08x", pid, uniq);
	err = memfd_setup(name, qal->st.memsz_meta,
	                  &qal->memfd_meta, &qal->mem_meta);
	if (err) {
		memfd_close(qal->memfd_data,
		            qal->mem_data, qal->st.memsz_data);
		return err;
	}
	qal->st.nbytes_used = 0;
	qal->st.npages_tota = npgs;
	return 0;
}

static int qalloc_fini_memfd(struct silofs_qalloc *qal)
{
	int err;

	if (!qal->st.npages_tota) {
		return 0;
	}
	err = memfd_close(qal->memfd_data, qal->mem_data,
	                  qal->st.memsz_data);
	if (err) {
		return err;
	}
	err = memfd_close(qal->memfd_meta, qal->mem_meta,
	                  qal->st.memsz_meta);
	if (err) {
		return err;
	}
	qal->memfd_data = -1;
	qal->memfd_meta = -1;
	qal->mem_data = NULL;
	qal->mem_meta = NULL;
	qal->st.memsz_data = 0;
	qal->st.memsz_meta = 0;
	return 0;
}

static void qalloc_init_slabs(struct silofs_qalloc *qal)
{
	size_t elemsz;
	struct silofs_slab *slab;
	const size_t shift_base = MSLAB_SHIFT_MIN;

	for (size_t i = 0; i < SILOFS_ARRAY_SIZE(qal->slabs); ++i) {
		elemsz = 1U << (shift_base + i);
		slab = &qal->slabs[i];
		slab_init(slab, i, elemsz);
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
	union silofs_page *pg_arr = qal->mem_data;

	silofs_assert_lt(idx, qal->st.npages_tota);

	return pg_arr + idx;
}

static struct silofs_page_info *
qalloc_page_info_at(const struct silofs_qalloc *qal, size_t idx)
{
	struct silofs_page_info *pgi_arr = qal->mem_meta;

	silofs_assert_lt(idx, qal->st.npages_tota);

	return pgi_arr + idx;
}

static struct silofs_page_info *
qalloc_next(const struct silofs_qalloc *qal,
            const struct silofs_page_info *pgi, size_t npgs)
{
	const size_t idx_next = pgi->pg_index + npgs;
	struct silofs_page_info *pgi_next = NULL;

	if (idx_next < qal->st.npages_tota) {
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
	const size_t threshold = MPAGES_IN_HOLE;
	struct silofs_list_head *free_list = &qal->free_list;

	page_info_update(pgi, prev, npgs);
	qalloc_update(qal, pgi, npgs);
	if (npgs >= threshold) {
		page_info_push_head(pgi, free_list);
	} else {
		page_info_push_tail(pgi, free_list);
	}
}

static void qalloc_init_pages(struct silofs_qalloc *qal)
{
	union silofs_page *pg;
	struct silofs_page_info *pgi;

	for (size_t i = 0; i < qal->st.npages_tota; ++i) {
		pg = qalloc_page_at(qal, i);
		pgi = qalloc_page_info_at(qal, i);
		page_info_init(pgi, pg, i);
	}

	silofs_list_init(&qal->free_list);
	pgi = qalloc_page_info_at(qal, 0);
	qalloc_add_free(qal, pgi, NULL, qal->st.npages_tota);
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
	qal->alif.malloc_fn = qal_malloc;
	qal->alif.free_fn = qal_free;
	qal->alif.stat_fn = qal_stat;
	qal->alif.resolve_fn = qal_resolve;
}

static void qalloc_fini_interface(struct silofs_qalloc *qal)
{
	qal->alif.malloc_fn = NULL;
	qal->alif.free_fn = NULL;
	qal->alif.stat_fn = NULL;
	qal->alif.resolve_fn = NULL;
}

int silofs_qalloc_init(struct silofs_qalloc *qal, size_t memsize, int mode)
{
	int err;
	size_t npgs;

	err = check_memsize(memsize);
	if (err) {
		return err;
	}
	qal->st.page_size = QALLOC_PAGE_SIZE;
	qal->st.npages_used = 0;
	qal->st.nbytes_used = 0;
	qal->mode = false;

	npgs = memsize / qal->st.page_size;
	err = qalloc_init_memfd(qal, npgs);
	if (err) {
		return err;
	}
	qalloc_init_pages(qal);
	qalloc_init_slabs(qal);
	qalloc_init_interface(qal);
	qal->mode = mode;
	return 0;
}

int silofs_qalloc_fini(struct silofs_qalloc *qal)
{
	/* TODO: release all pending memory-elements in slabs */
	qalloc_fini_slabs(qal);
	qalloc_fini_interface(qal);
	return qalloc_fini_memfd(qal);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t nbytes_to_npgs(size_t nbytes)
{
	return (nbytes + QALLOC_PAGE_SIZE - 1) / QALLOC_PAGE_SIZE;
}

static size_t npgs_to_nbytes(size_t npgs)
{
	return npgs * QALLOC_PAGE_SIZE;
}

static loff_t qalloc_ptr_to_off(const struct silofs_qalloc *qal,
                                const void *ptr)
{
	return (const char *)ptr - (const char *)qal->mem_data;
}

static size_t qalloc_ptr_to_pgn(const struct silofs_qalloc *qal,
                                const void *ptr)
{
	const loff_t off = qalloc_ptr_to_off(qal, ptr);

	return (size_t)off / qal->st.page_size;
}

static bool qalloc_isinrange(const struct silofs_qalloc *qal,
                             const void *ptr, size_t nb)
{
	const loff_t off = qalloc_ptr_to_off(qal, ptr);
	const loff_t end = off + (loff_t)nb;

	return (off >= 0) && (end <= (loff_t)qal->st.memsz_data);
}

static struct silofs_page_info *
qalloc_page_info_of(const struct silofs_qalloc *qal, const void *ptr)
{
	const size_t pgn = qalloc_ptr_to_pgn(qal, ptr);

	silofs_assert_lt(pgn, qal->st.npages_tota);
	return qalloc_page_info_at(qal, pgn);
}

static struct silofs_slab_seg *
qalloc_slab_seg_of(const struct silofs_qalloc *qal, const void *ptr)
{
	loff_t off;
	size_t idx;
	struct silofs_slab_seg *seg = qal->mem_data;

	off = qalloc_ptr_to_off(qal, ptr);
	idx = (size_t)off / sizeof(*seg);

	return &seg[idx];
}

static struct silofs_page_info *
qalloc_search_free_from_tail(struct silofs_qalloc *qal, size_t npgs)
{
	struct silofs_page_info *pgi;
	struct silofs_list_head *itr;
	struct silofs_list_head *free_list = &qal->free_list;

	itr = free_list->prev;
	while (itr != free_list) {
		pgi = link_to_page_info(itr);
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
	struct silofs_list_head *free_list = &qal->free_list;

	itr = free_list->next;
	while (itr != free_list) {
		pgi = link_to_page_info(itr);
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
	const size_t threshold = MPAGES_IN_HOLE;

	if ((qal->st.npages_used + npgs) <= qal->st.npages_tota) {
		if (npgs >= threshold) {
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
	silofs_assert_eq(pgi->slab_index, MSLAB_INDEX_NONE);
	silofs_assert_ge(pgi->pg_count, npgs);

	page_info_unlink(pgi);
	pgi->pg_free = 0;
	if (pgi->pg_count == npgs) {
		return pgi;
	}
	pgi_next = qalloc_next(qal, pgi, npgs);
	silofs_assert_not_null(pgi_next);
	silofs_assert_eq(pgi_next->slab_index, MSLAB_INDEX_NONE);
	silofs_assert_eq(pgi_next->pg_count, 0);
	silofs_assert_eq(pgi_next->pg_free, 1);
	qalloc_add_free(qal, pgi_next, pgi, pgi->pg_count - npgs);

	pgi->pg_count = npgs;
	return pgi;
}

static struct silofs_slab *
qalloc_slab_of(const struct silofs_qalloc *qal, size_t nbytes)
{
	int err;
	size_t sindex;
	const struct silofs_slab *slab = NULL;

	err = slab_size_to_index(nbytes, &sindex);
	if (!err && (sindex < SILOFS_ARRAY_SIZE(qal->slabs))) {
		slab = &qal->slabs[sindex];
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
	int err;
	struct silofs_slab *slab;
	struct silofs_slab_seg *seg;

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

	if (qal->mem_data == NULL) {
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
	int err;
	struct silofs_slab_seg *seg;

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
	qal->st.npages_used += npgs;
	silofs_assert_ge(qal->st.npages_tota, qal->st.npages_used);
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
	qal->st.nbytes_used += nbytes;
	return 0;
}

void *silofs_qalloc_malloc(struct silofs_qalloc *qal, size_t nbytes)
{
	int err;
	void *ptr = NULL;

	err = qalloc_malloc(qal, nbytes, &ptr);
	if (err) {
		silofs_log_debug("malloc failed: nbytes=%lu err=%d",
		                 nbytes, err);
	}
	return ptr;
}

void *silofs_qalloc_zmalloc(struct silofs_qalloc *qal, size_t nbytes)
{
	void *ptr;

	ptr = silofs_qalloc_malloc(qal, nbytes);
	if (ptr != NULL) {
		memset(ptr, 0, nbytes);
	}
	return ptr;
}

static int qalloc_check_free(const struct silofs_qalloc *qal,
                             const void *ptr, size_t nbytes)
{
	if ((qal->mem_data == NULL) || (ptr == NULL)) {
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

static void
qalloc_punch_hole_at(const struct silofs_qalloc *qal,
                     const struct silofs_page_info *pgi, size_t npgs)
{
	int err;
	size_t off;
	size_t len;
	const int mode = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;

	off = npgs_to_nbytes(pgi->pg_index);
	len = npgs_to_nbytes(npgs);
	err = silofs_sys_fallocate(qal->memfd_data, mode,
	                           (loff_t)off, (loff_t)len);
	silofs_assert_ok(err);
	if (err) {
		silofs_panic("failed to punch-hole in memory: "
		             "off=0x%lx len=%lu err=%d", off, len, err);
	}
}

static void
qalloc_release_npgs(const struct silofs_qalloc *qal,
                    const struct silofs_page_info *pgi, size_t npgs)
{
	const size_t threshold = MPAGES_IN_HOLE;

	if (npgs >= threshold) {
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
		silofs_assert_gt(pgi_next->pg_count, 0);
		npgs += pgi_next->pg_count;
		page_info_unlink_mute(pgi_next);
	}
	pgi_prev = pgi->prev;
	if (pgi_prev && pgi_prev->pg_free) {
		silofs_assert_gt(pgi_prev->pg_count, 0);
		npgs += pgi_prev->pg_count;
		page_info_mute(pgi);
		pgi = pgi_prev;
		pgi_prev = pgi_prev->prev;
		page_info_unlink_mute(pgi);
	}

	qalloc_release_npgs(qal, pgi, npgs);
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
	if (slab->sindex && (nb <= (slab->elemsz / 2))) {
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
	int err;
	struct silofs_slab *slab;

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
	if (qal->st.npages_used < npgs) {
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
	int err;
	size_t npgs;
	struct silofs_page_info *pgi;

	err = qalloc_check_by_page(qal, ptr, nbytes);
	if (err) {
		return err;
	}
	npgs = nbytes_to_npgs(nbytes);
	pgi = qalloc_page_info_of(qal, ptr);
	qalloc_free_npgs(qal, pgi, npgs);
	qal->st.npages_used -= npgs;
	return 0;
}

static void *
qalloc_base_of(const struct silofs_qalloc *qal, void *ptr, size_t len)
{
	void *base = NULL;
	struct silofs_slab_seg *seg;
	struct silofs_page_info *pgi;

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
	silofs_assert_ge(qal->st.nbytes_used, nbytes);

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
	qal->st.nbytes_used -= nbytes;
	return err;
}

void silofs_qalloc_free(struct silofs_qalloc *qal, void *ptr, size_t nbytes)
{
	int err;

	err = qalloc_free(qal, ptr, nbytes);
	if (err) {
		silofs_panic("free error: ptr=%p nbytes=%lu err=%d",
		             ptr, nbytes, err);
	}
}

void silofs_qalloc_zfree(struct silofs_qalloc *qal, void *ptr, size_t nbytes)
{
	if (ptr != NULL) {
		memset(ptr, 0, nbytes);
		silofs_qalloc_free(qal, ptr, nbytes);
	}
}

static int qalloc_check_by_slab(const struct silofs_qalloc *qal,
                                const void *ptr, size_t nbytes)
{
	int err = -EINVAL;
	const struct silofs_slab_seg *seg;

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

int silofs_qalloc_resolve(const struct silofs_qalloc *qal,
                          void *ptr, size_t len, struct silofs_fiovec *fiov)
{
	const void *base;

	base = qalloc_base_of(qal, ptr, len);
	if ((base == NULL) || (base > ptr)) {
		return -ERANGE;
	}
	fiov->fv_off = qalloc_ptr_to_off(qal, ptr);
	fiov->fv_len = len;
	fiov->fv_base = ptr;
	fiov->fv_fd = qal->memfd_data;
	fiov->fv_ref = NULL;
	return 0;
}

void silofs_qalloc_stat(const struct silofs_qalloc *qal,
                        struct silofs_alloc_stat *out_stat)
{
	memcpy(out_stat, &qal->st, sizeof(*out_stat));
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
	size_t al;

	if (sz <= 512) {
		al = 512;
	} else if (sz <= 1024) {
		al = 1024;
	} else if (sz <= 2048) {
		al = 2048;
	} else {
		al = (size_t)silofs_sc_page_size();
	}
	return al;
}

int silofs_zmalloc(size_t sz, void **out_mem)
{
	int err;

	err = posix_memalign(out_mem, alignment_of(sz), sz);
	if (!err) {
		silofs_memzero(*out_mem, sz);
	}
	return err;
}

void silofs_zfree(void *mem, size_t sz)
{
	silofs_memzero(mem, sz);
	free(mem);
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

