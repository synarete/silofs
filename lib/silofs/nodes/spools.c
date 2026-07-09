/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#include <silofs/nodes.h>

static uint32_t ltype_size(enum silofs_ltype ltype)
{
	const size_t size = silofs_ltype_size(ltype);

	silofs_assert_gt(size, 0);
	silofs_assert_lt(size, UINT32_MAX);

	return (uint32_t)size;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void lspan_reset(struct silofs_lspan *lspan)
{
	lspan->off = 0;
	lspan->len = 0;
}

static void lspan_init(struct silofs_lspan *lspan, off_t off, size_t len)
{
	lspan->off = off;
	lspan->len = len;
}

static void lspan_fini(struct silofs_lspan *lspan)
{
	lspan->off = SILOFS_OFF_NULL;
	lspan->len = 0;
}

static void
lspan_assign(struct silofs_lspan *lspan, const struct silofs_lspan *other)
{
	lspan->off = other->off;
	lspan->len = other->len;
}

static off_t lspan_end(const struct silofs_lspan *lspan)
{
	return silofs_off_end(lspan->off, lspan->len);
}

static void
lspan_range(const struct silofs_lspan *lspan, off_t *out_beg, off_t *out_end)
{
	*out_beg = lspan->off;
	*out_end = lspan_end(lspan);
}

static void lspan_expand_head(struct silofs_lspan *lspan, size_t len)
{
	silofs_assert_ge(lspan->off, len);
	lspan->off -= (ssize_t)len;
	lspan->len += len;
}

static void lspan_expand_tail(struct silofs_lspan *lspan, size_t len)
{
	lspan->len += len;
}

static void lspan_trim_head(struct silofs_lspan *lspan, size_t len)
{
	silofs_assert_gt(lspan->len, len);
	silofs_assert_ne(lspan->off, SILOFS_OFF_NULL);

	lspan->off = silofs_off_end(lspan->off, len);
	lspan->len -= len;
}

static void lspan_merge_with(struct silofs_lspan *lspan,
                             const struct silofs_lspan *lspan_next)
{
	const off_t end = lspan_end(lspan);

	silofs_assert_eq(end, lspan_next->off);

	lspan->len += lspan_next->len;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void lspq_clear(struct silofs_lspoolq *lspq)
{
	for (size_t i = 0; i < ARRAY_SIZE(lspq->lspan); ++i) {
		lspan_reset(&lspq->lspan[i]);
	}
	lspq->count = 0;
}

static void lspq_init(struct silofs_lspoolq *lspq, uint32_t objsz)
{
	lspq_clear(lspq);
	lspq->objsz = objsz;
}

static void lspq_fini(struct silofs_lspoolq *lspq)
{
	lspq_clear(lspq);
	lspq->objsz = 0;
}

static size_t lspq_lower_bound(const struct silofs_lspoolq *lspq, off_t off)
{
	size_t left = 0, right = lspq->count;

	while (left < right) {
		const size_t mid = left + (right - left) / 2;

		if (lspq->lspan[mid].off > off) {
			left = mid + 1;
		} else {
			right = mid;
		}
	}
	return left;
}

static void lspq_shift_right(struct silofs_lspoolq *lspq, size_t pos)
{
	silofs_assert_lt(pos, lspq->count);
	silofs_assert_lt(lspq->count, ARRAY_SIZE(lspq->lspan));

	for (size_t i = lspq->count; i > pos; --i) {
		lspan_assign(&lspq->lspan[i], &lspq->lspan[i - 1]);
	}
}

static void lspq_shift_left(struct silofs_lspoolq *lspq, size_t pos)
{
	silofs_assert_lt(pos, lspq->count);

	for (size_t i = pos; i < lspq->count - 1; ++i) {
		lspan_assign(&lspq->lspan[i], &lspq->lspan[i + 1]);
	}
	lspan_reset(&lspq->lspan[lspq->count - 1]);
}

static void
lspq_insert_at(struct silofs_lspoolq *lspq, size_t pos, off_t off, size_t len)
{
	silofs_assert_le(pos, lspq->count);
	silofs_assert_lt(lspq->count, ARRAY_SIZE(lspq->lspan));

	if (pos != lspq->count) {
		lspq_shift_right(lspq, pos);
	}
	lspan_init(&lspq->lspan[pos], off, len);
	lspq->count++;
}

static void lspq_remove_at(struct silofs_lspoolq *lspq, size_t pos)
{
	silofs_assert_lt(pos, lspq->count);
	silofs_assert_gt(lspq->count, 0);

	lspq_shift_left(lspq, pos);
	lspq->count--;
}

static bool lspq_try_merge_prev(struct silofs_lspoolq *lspq, size_t pos,
                                off_t off, size_t len)
{
	struct silofs_lspan *lspan_prev;

	if (pos == 0) {
		return false;
	}
	lspan_prev = &lspq->lspan[pos - 1];
	if (off + (off_t)len != lspan_prev->off) {
		return false;
	}
	lspan_expand_head(lspan_prev, len);
	return true;
}

static bool lspq_try_merge_next(struct silofs_lspoolq *lspq, size_t pos,
                                off_t off, size_t len)
{
	struct silofs_lspan *lspan_next;

	if (pos >= lspq->count) {
		return false;
	}
	lspan_next = &lspq->lspan[pos];
	if (lspan_next->off + (off_t)lspan_next->len != off) {
		return false;
	}
	lspan_expand_tail(lspan_next, len);
	return true;
}

static bool lspq_try_merge_both(struct silofs_lspoolq *lspq, size_t pos)
{
	struct silofs_lspan *lspan_prev;
	struct silofs_lspan *lspan_next;

	if (pos == 0 || pos >= lspq->count) {
		return false;
	}
	lspan_prev = &lspq->lspan[pos - 1];
	lspan_next = &lspq->lspan[pos];
	if (lspan_next->off + (off_t)lspan_next->len != lspan_prev->off) {
		return false;
	}
	lspan_merge_with(lspan_next, lspan_prev);
	lspq_remove_at(lspq, pos - 1);
	return true;
}

static void
lspq_do_pop(struct silofs_lspoolq *lspq, size_t len, off_t *out_off)
{
	struct silofs_lspan *lspan = &lspq->lspan[lspq->count - 1];

	*out_off = lspan->off;

	if (lspan->len > len) {
		/* partial pop: chop in-place */
		lspan_trim_head(lspan, len);
	} else {
		/* full pop */
		silofs_assert_eq(lspan->len, len);
		lspan_reset(lspan);
		lspq->count--;
	}
}

static int lspq_pop(struct silofs_lspoolq *lspq, size_t len, off_t *out_off)
{
	if (lspq->objsz != len) {
		return -SILOFS_EINVAL;
	}
	if (!lspq->count) {
		return -SILOFS_ENOENT;
	}

	lspq_do_pop(lspq, len, out_off);
	return 0;
}

static bool lspq_try_merge(struct silofs_lspoolq *lspq, off_t off, size_t len)
{
	const size_t pos = lspq_lower_bound(lspq, off);
	bool merged;

	merged = lspq_try_merge_prev(lspq, pos, off, len);
	if (merged) {
		lspq_try_merge_both(lspq, pos);
		goto out;
	}
	merged = lspq_try_merge_next(lspq, pos, off, len);
out:
	return merged;
}

static void lspq_insert(struct silofs_lspoolq *lspq, off_t off, size_t len)
{
	const size_t pos = lspq_lower_bound(lspq, off);

	lspq_insert_at(lspq, pos, off, len);
}

static bool lspq_cap_insert(const struct silofs_lspoolq *lspq)
{
	constexpr size_t size_max = ARRAY_SIZE(lspq->lspan);

	return (lspq->count < size_max);
}

static int lspq_push(struct silofs_lspoolq *lspq, off_t off, size_t len)
{
	bool merged;

	if (lspq->objsz != len) {
		return -SILOFS_EINVAL;
	}
	merged = lspq_try_merge(lspq, off, len);
	if (merged) {
		return 0;
	}
	if (!lspq_cap_insert(lspq)) {
		return -SILOFS_ENOSPC;
	}
	lspq_insert(lspq, off, len);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static long off_compare(const void *x, const void *y)
{
	const off_t *off_x = x;
	const off_t *off_y = y;

	return *off_y - *off_x;
}

static struct silofs_lsp_entry *
avl_node_to_lspe(const struct silofs_avl_node *an)
{
	const struct silofs_lsp_entry *lspe = nullptr;

	if (an != nullptr) {
		lspe = container_of(an, struct silofs_lsp_entry, avl_node);
	}
	return silofs_unconst(lspe);
}

static const void *lspe_getkey(const struct silofs_avl_node *an)
{
	const struct silofs_lsp_entry *lspe = avl_node_to_lspe(an);

	return &lspe->lspan.off;
}

static void lspe_init(struct silofs_lsp_entry *lspe, off_t off, size_t len)
{
	silofs_avl_node_init(&lspe->avl_node);
	lspan_init(&lspe->lspan, off, len);
}

static void lspe_fini(struct silofs_lsp_entry *lspe)
{
	silofs_avl_node_fini(&lspe->avl_node);
	lspan_fini(&lspe->lspan);
}

static off_t lspe_end(const struct silofs_lsp_entry *lspe)
{
	return lspan_end(&lspe->lspan);
}

static void lspe_trim_head(struct silofs_lsp_entry *lspe, size_t len)
{
	lspan_trim_head(&lspe->lspan, len);
}

static struct silofs_lsp_entry *
lspe_new(off_t off, size_t len, struct silofs_alloc *alloc)
{
	struct silofs_lsp_entry *lspe;

	lspe = silofs_memalloc(alloc, sizeof(*lspe), 0);
	if (lspe != nullptr) {
		lspe_init(lspe, off, len);
	}
	return lspe;
}

static void lspe_del(struct silofs_lsp_entry *lspe, struct silofs_alloc *alloc)
{
	if (lspe != nullptr) { /* make gcc-analyzer happy */
		lspe_fini(lspe);
		silofs_memfree(alloc, lspe, sizeof(*lspe), 0);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_lsp_entry *
lspool_new_lspe(struct silofs_lspool *lspool, off_t off, size_t len)
{
	struct silofs_lsp_entry *lspe;

	lspe = lspe_new(off, len, lspool->alloc);
	return lspe;
}

static void
lspool_delete_lspe(struct silofs_lspool *lspool, struct silofs_lsp_entry *lspe)
{
	lspe_del(lspe, lspool->alloc);
}

static struct silofs_lsp_entry *
lspool_minimal_lspe(const struct silofs_lspool *lspool)
{
	struct silofs_avl_node *an;
	const struct silofs_avl *avl = &lspool->avl;

	if (avl->size == 0) {
		return nullptr;
	}
	an = silofs_avl_begin(avl);
	return avl_node_to_lspe(an);
}

static struct silofs_lsp_entry *
lspool_maximal_lspe(const struct silofs_lspool *lspool)
{
	struct silofs_avl_node *an   = nullptr;
	const struct silofs_avl *avl = &lspool->avl;

	if (avl->size == 0) {
		return nullptr;
	}
	an = silofs_avl_rbegin(avl);
	return avl_node_to_lspe(an);
}

static struct silofs_lsp_entry *
lspool_lower_bound_lspe(const struct silofs_lspool *lspool, off_t off)
{
	const struct silofs_avl_node *an;
	const struct silofs_avl *avl = &lspool->avl;

	an = silofs_avl_lower_bound(avl, &off);
	return avl_node_to_lspe(an);
}

static struct silofs_lsp_entry *
lspool_prev_of(const struct silofs_lspool *lspool,
               const struct silofs_lsp_entry *lspe)
{
	const struct silofs_avl_node *an_prev;
	const struct silofs_avl *avl = &lspool->avl;

	an_prev = silofs_avl_prev(avl, &lspe->avl_node);
	if (an_prev == silofs_avl_end(avl)) {
		return nullptr;
	}
	return avl_node_to_lspe(an_prev);
}

static void
lspool_find_next_prev(const struct silofs_lspool *lspool, off_t off,
                      struct silofs_lsp_entry **out_lspe_prev,
                      struct silofs_lsp_entry **out_lspe_next)
{
	struct silofs_lsp_entry *lspe_next, *lspe_prev;

	lspe_next = lspool_lower_bound_lspe(lspool, off);
	if (lspe_next != nullptr) {
		lspe_prev = lspool_prev_of(lspool, lspe_next);
	} else {
		lspe_prev = lspool_maximal_lspe(lspool);
	}
	*out_lspe_prev = lspe_prev;
	*out_lspe_next = lspe_next;
}

static void
lspool_insert_lspe(struct silofs_lspool *lspool, struct silofs_lsp_entry *lspe)
{
	silofs_avl_insert(&lspool->avl, &lspe->avl_node);
}

static void
lspool_remove_lspe(struct silofs_lspool *lspool, struct silofs_lsp_entry *lspe)
{
	silofs_avl_remove(&lspool->avl, &lspe->avl_node);
}

static void
lspool_evict_lspe(struct silofs_lspool *lspool, struct silofs_lsp_entry *lspe)
{
	lspool_remove_lspe(lspool, lspe);
	lspool_delete_lspe(lspool, lspe);
}

static bool lspool_check_cap_add(const struct silofs_lspool *lspool)
{
	return (lspool->avl.size < 1024);
}

static int
lspool_pull(struct silofs_lspool *lspool, size_t len, off_t *out_off)
{
	struct silofs_lsp_entry *lspe;
	int err;

	err = lspq_pop(&lspool->lspq, len, out_off);
	if (!err) {
		return 0;
	}
	lspe = lspool_minimal_lspe(lspool);
	if (lspe == nullptr) {
		return -SILOFS_ENOSPC;
	}
	if (len > lspe->lspan.len) {
		return -SILOFS_ENOSPC;
	}
	*out_off = lspe->lspan.off;
	if (len < lspe->lspan.len) {
		/* its ok to modify in-place and avoid the costly remove-insert
		 * into the tree, as this is already the minimal element */
		lspe_trim_head(lspe, len);
	} else {
		lspool_evict_lspe(lspool, lspe);
	}
	return 0;
}

static size_t length_of(off_t beg, off_t end)
{
	ssize_t len;

	silofs_assert_le(beg, end);
	len = (end - beg);
	silofs_assert_lt(len, INT64_MAX >> 12);
	return (size_t)len;
}

static int lspool_merge(struct silofs_lspool *lspool, off_t off, size_t len)
{
	struct silofs_lsp_entry *lspe = nullptr;
	struct silofs_lsp_entry *lspe_prev, *lspe_next;
	off_t end;
	int ret = -SILOFS_ENOENT;

	end = silofs_off_end(off, len);
	lspool_find_next_prev(lspool, off, &lspe_prev, &lspe_next);

	if (lspe_prev && (lspe_end(lspe_prev) == off)) {
		/* merge range into prev */
		lspe = lspe_prev;
		lspan_expand_tail(&lspe->lspan, len);
		lspan_range(&lspe->lspan, &off, &end);
		ret = 0;
	}
	if (lspe_next == nullptr) {
		/* no next to append with */
		return ret;
	}
	if (end != lspe_next->lspan.off) {
		/* can not merge with next */
		return ret;
	}
	end = lspe_end(lspe_next);
	if (lspe == nullptr) {
		const size_t new_len = length_of(off, end);

		/* merge with next only */
		lspool_evict_lspe(lspool, lspe_next);
		lspe = lspool_new_lspe(lspool, off, new_len);
		if (lspe == nullptr) {
			return -SILOFS_ENOMEM;
		}
		lspool_insert_lspe(lspool, lspe);
	} else {
		/* full merge (prev + next ) */
		lspan_merge_with(&lspe->lspan, &lspe_next->lspan);
		lspool_evict_lspe(lspool, lspe_next);
	}
	return 0;
}

static int lspool_insert(struct silofs_lspool *lspool, off_t off, size_t len)
{
	struct silofs_lsp_entry *lspe;

	lspe = lspool_new_lspe(lspool, off, len);
	if (lspe == nullptr) {
		return -SILOFS_ENOMEM;
	}
	lspool_insert_lspe(lspool, lspe);
	return 0;
}

static int lspool_add(struct silofs_lspool *lspool, off_t off, size_t len)
{
	int err;
	bool cap_add;

	err = lspq_push(&lspool->lspq, off, len);
	if (!err) {
		return 0;
	}
	err = lspool_merge(lspool, off, len);
	if (err != -SILOFS_ENOENT) {
		return err;
	}
	cap_add = lspool_check_cap_add(lspool);
	if (!cap_add) {
		return -SILOFS_ENOMEM;
	}
	err = lspool_insert(lspool, off, len);
	if (err) {
		return err;
	}
	return 0;
}

static void lspool_avl_node_delete_cb(struct silofs_avl_node *an, void *p)
{
	struct silofs_lspool *lspool  = p;
	struct silofs_lsp_entry *lspe = avl_node_to_lspe(an);

	lspool_delete_lspe(lspool, lspe);
}

static void lspool_clear(struct silofs_lspool *lspool)
{
	const struct silofs_avl_node_functor fn = {
		.fn  = lspool_avl_node_delete_cb,
		.ctx = lspool,
	};

	silofs_avl_clear(&lspool->avl, &fn);
	lspq_clear(&lspool->lspq);
}

static void lspool_init(struct silofs_lspool *lspool, uint32_t objsz,
                        struct silofs_alloc *alloc)
{
	lspq_init(&lspool->lspq, objsz);
	silofs_avl_init(&lspool->avl, lspe_getkey, off_compare, lspool);
	lspool->alloc = alloc;
}

static void lspool_fini(struct silofs_lspool *lspool)
{
	lspool_clear(lspool);
	lspq_fini(&lspool->lspq);
	silofs_avl_fini(&lspool->avl);
	lspool->alloc = nullptr;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t lspools_ltype_to_slot(enum silofs_ltype ltype)
{
	return (size_t)(ltype - 1);
}

static enum silofs_ltype lspools_slot_to_ltype(size_t slot)
{
	return (enum silofs_ltype)(slot + 1);
}

static struct silofs_lspool *
lspools_mut_sub(struct silofs_lspools *lspools, enum silofs_ltype ltype)
{
	constexpr size_t nslots = ARRAY_SIZE(lspools->lspool);
	const size_t slot       = lspools_ltype_to_slot(ltype);

	return (slot < nslots) ? &lspools->lspool[slot] : nullptr;
}

int silofs_lspools_push(struct silofs_lspools *lspools,
                        const struct silofs_laddr *laddr)
{
	struct silofs_lspool *lspool;
	size_t len;

	lspool = lspools_mut_sub(lspools, laddr->ltype);
	if (unlikely(lspool == nullptr)) {
		return -SILOFS_EINVAL;
	}
	len = ltype_size(laddr->ltype);
	return lspool_add(lspool, laddr->off, len);
}

int silofs_lspools_pull(struct silofs_lspools *lspools,
                        enum silofs_ltype ltype,
                        struct silofs_laddr *out_laddr)
{
	struct silofs_lspool *lspool;
	size_t len;
	off_t off;
	int err;

	lspool = lspools_mut_sub(lspools, ltype);
	if (unlikely(lspool == nullptr)) {
		return -SILOFS_EINVAL;
	}
	len = ltype_size(ltype);
	err = lspool_pull(lspool, len, &off);
	if (err) {
		return err;
	}
	silofs_laddr_setup(out_laddr, ltype, off);
	return 0;
}

void silofs_lspools_drop(struct silofs_lspools *lspools)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(lspools->lspool); ++slot) {
		lspool_clear(&lspools->lspool[slot]);
	}
}

int silofs_lspools_init(struct silofs_lspools *lspools,
                        struct silofs_alloc *alloc)
{
	enum silofs_ltype ltype;

	for (size_t slot = 0; slot < ARRAY_SIZE(lspools->lspool); ++slot) {
		ltype = lspools_slot_to_ltype(slot);
		lspool_init(&lspools->lspool[slot], ltype_size(ltype), alloc);
	}
	return 0;
}

void silofs_lspools_fini(struct silofs_lspools *lspools)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(lspools->lspool); ++slot) {
		lspool_fini(&lspools->lspool[slot]);
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_pspool_entry *pspe_from_lh(struct silofs_list_head *lh)
{
	return mut_container_of(lh, struct silofs_pspool_entry, lh);
}

static struct silofs_pspool_entry *pspe_malloc(struct silofs_alloc *alloc)
{
	struct silofs_pspool_entry *pspe = nullptr;

	pspe = silofs_memalloc(alloc, sizeof(*pspe), 0);
	return pspe;
}

static void
pspe_free(struct silofs_pspool_entry *pspe, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, pspe, sizeof(*pspe), 0);
}

static void
pspe_init(struct silofs_pspool_entry *pspe, const struct silofs_paddr *paddr)
{
	silofs_list_head_init(&pspe->lh);
	silofs_paddr_assign(&pspe->paddr, paddr);
}

static void pspe_fini(struct silofs_pspool_entry *pspe)
{
	silofs_list_head_fini(&pspe->lh);
	silofs_paddr_reset(&pspe->paddr);
}

static struct silofs_pspool_entry *
pspe_new(const struct silofs_paddr *paddr, struct silofs_alloc *alloc)
{
	struct silofs_pspool_entry *pspe;

	pspe = pspe_malloc(alloc);
	if (pspe != nullptr) {
		pspe_init(pspe, paddr);
	}
	return pspe;
}

static void
pspe_del(struct silofs_pspool_entry *pspe, struct silofs_alloc *alloc)
{
	pspe_fini(pspe);
	pspe_free(pspe, alloc);
}

static void pspe_paddr(const struct silofs_pspool_entry *pspe,
                       struct silofs_paddr *out_paddr)
{
	silofs_paddr_assign(out_paddr, &pspe->paddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
pspool_init(struct silofs_pspool *pspool, struct silofs_alloc *alloc)
{
	silofs_listq_init(&pspool->listq);
	pspool->alloc = alloc;
}

static void pspool_fini(struct silofs_pspool *pspool)
{
	silofs_listq_init(&pspool->listq);
	pspool->alloc = nullptr;
}

static bool pspool_cap_push(const struct silofs_pspool *pspool)
{
	const size_t sz = silofs_listq_size(&pspool->listq);

	return (sz < 1024);
}

static int
pspool_push(struct silofs_pspool *pspool, const struct silofs_paddr *paddr)
{
	struct silofs_pspool_entry *pspe;

	if (!pspool_cap_push(pspool)) {
		return -SILOFS_ENOSPC;
	}
	pspe = pspe_new(paddr, pspool->alloc);
	if (pspe == nullptr) {
		return -SILOFS_ENOMEM;
	}
	silofs_listq_push_back(&pspool->listq, &pspe->lh);
	return 0;
}

static struct silofs_pspool_entry *
pspool_pop_front(struct silofs_pspool *pspool)
{
	struct silofs_list_head *lh;
	struct silofs_pspool_entry *pspe = nullptr;

	lh = silofs_listq_pop_front(&pspool->listq);
	if (lh != nullptr) {
		pspe = pspe_from_lh(lh);
	}
	return pspe;
}

static int
pspool_pop(struct silofs_pspool *pspool, struct silofs_paddr *out_paddr)
{
	struct silofs_pspool_entry *pspe;

	pspe = pspool_pop_front(pspool);
	if (pspe == nullptr) {
		return -SILOFS_ENOENT;
	}
	pspe_paddr(pspe, out_paddr);
	pspe_del(pspe, pspool->alloc);
	return 0;
}

static void pspool_clear(struct silofs_pspool *pspool)
{
	struct silofs_pspool_entry *pspe;

	pspe = pspool_pop_front(pspool);
	while (pspe != nullptr) {
		pspe_del(pspe, pspool->alloc);
		pspe = pspool_pop_front(pspool);
	}
}

static void pspool_clear_fini(struct silofs_pspool *pspool)
{
	pspool_clear(pspool);
	pspool_fini(pspool);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_pspools_init(struct silofs_pspools *pspools,
                         struct silofs_alloc *alloc)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(pspools->bn); ++slot) {
		pspool_init(&pspools->bn[slot], alloc);
	}
	for (size_t slot = 0; slot < ARRAY_SIZE(pspools->vn); ++slot) {
		pspool_init(&pspools->vn[slot], alloc);
	}
}

void silofs_pspools_fini(struct silofs_pspools *pspools)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(pspools->bn); ++slot) {
		pspool_clear_fini(&pspools->bn[slot]);
	}
	for (size_t slot = 0; slot < ARRAY_SIZE(pspools->vn); ++slot) {
		pspool_clear_fini(&pspools->vn[slot]);
	}
}

void silofs_pspools_drop(struct silofs_pspools *pspools)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(pspools->bn); ++slot) {
		pspool_clear(&pspools->bn[slot]);
	}
	for (size_t slot = 0; slot < ARRAY_SIZE(pspools->vn); ++slot) {
		pspool_clear(&pspools->vn[slot]);
	}
}

static size_t pspool_ltype_to_slot(enum silofs_ltype ltype)
{
	return (size_t)(ltype - 1);
}

static struct silofs_pspool *pspools_mut_sub(struct silofs_pspools *pspools,
                                             const struct silofs_stype *stype)
{
	struct silofs_pspool *pspool = nullptr;
	size_t slot;

	if (stype->ptype == SILOFS_PTYPE_BTNODE) {
		slot = pspool_ltype_to_slot(stype->ltype);
		if (slot < ARRAY_SIZE(pspools->bn)) {
			pspool = &pspools->bn[slot];
		}
	} else if (stype->ptype == SILOFS_PTYPE_LNODE) {
		slot = pspool_ltype_to_slot(stype->ltype);
		if (slot < ARRAY_SIZE(pspools->vn)) {
			pspool = &pspools->vn[slot];
		}
	}
	return pspool;
}

static const struct silofs_stype *stype_of(const struct silofs_paddr *paddr)
{
	return &paddr->blobid.stype;
}

int silofs_pspools_push(struct silofs_pspools *pspools,
                        const struct silofs_paddr *paddr)
{
	struct silofs_pspool *pspool;
	int ret = -SILOFS_ENOENT;

	pspool = pspools_mut_sub(pspools, stype_of(paddr));
	if (pspool != nullptr) {
		ret = pspool_push(pspool, paddr);
	}
	return ret;
}

int silofs_pspools_pull(struct silofs_pspools *pspools,
                        const struct silofs_stype *stype,
                        struct silofs_paddr *out_paddr)
{
	struct silofs_pspool *pspool;
	int ret = -SILOFS_ENOENT;

	pspool = pspools_mut_sub(pspools, stype);
	if (pspool != nullptr) {
		ret = pspool_pop(pspool, out_paddr);
	}
	return ret;
}
