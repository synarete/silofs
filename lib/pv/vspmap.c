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

#include <silofs/base.h>
#include <silofs/addr.h>
#include <silofs/pv.h>

static uint32_t vtype_size(enum silofs_vtype vtype)
{
	const size_t size = silofs_vtype_size(vtype);

	silofs_assert_gt(size, 0);
	silofs_assert_lt(size, UINT32_MAX);

	return (uint32_t)size;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vspan_reset(struct silofs_vspan *vspan)
{
	vspan->off = 0;
	vspan->len = 0;
}

static void vspan_init(struct silofs_vspan *vspan, off_t off, size_t len)
{
	vspan->off = off;
	vspan->len = len;
}

static void vspan_fini(struct silofs_vspan *vspan)
{
	vspan->off = SILOFS_OFF_NULL;
	vspan->len = 0;
}

static void
vspan_assign(struct silofs_vspan *vspan, const struct silofs_vspan *other)
{
	vspan->off = other->off;
	vspan->len = other->len;
}

static off_t vspan_end(const struct silofs_vspan *vspan)
{
	return silofs_off_end(vspan->off, vspan->len);
}

static void
vspan_range(const struct silofs_vspan *vspan, off_t *out_beg, off_t *out_end)
{
	*out_beg = vspan->off;
	*out_end = vspan_end(vspan);
}

static void vspan_expand_head(struct silofs_vspan *vspan, size_t len)
{
	silofs_assert_ge(vspan->off, len);
	vspan->off -= (ssize_t)len;
	vspan->len += len;
}

static void vspan_expand_tail(struct silofs_vspan *vspan, size_t len)
{
	vspan->len += len;
}

static void vspan_trim_head(struct silofs_vspan *vspan, size_t len)
{
	silofs_assert_gt(vspan->len, len);
	silofs_assert_ne(vspan->off, SILOFS_OFF_NULL);

	vspan->off = silofs_off_end(vspan->off, len);
	vspan->len -= len;
}

static void vspan_merge_with(struct silofs_vspan *vspan,
                             const struct silofs_vspan *vspan_next)
{
	const off_t end = vspan_end(vspan);

	silofs_assert_eq(end, vspan_next->off);

	vspan->len += vspan_next->len;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void vspq_clear(struct silofs_vsp_queue *vspq)
{
	for (size_t i = 0; i < ARRAY_SIZE(vspq->vsq); ++i) {
		vspan_reset(&vspq->vsq[i]);
	}
	vspq->vsq_count = 0;
}

static void vspq_init(struct silofs_vsp_queue *vspq, uint32_t objsz)
{
	vspq_clear(vspq);
	vspq->vsq_objsz = objsz;
}

static void vspq_fini(struct silofs_vsp_queue *vspq)
{
	vspq_clear(vspq);
}

static size_t vspq_lower_bound(const struct silofs_vsp_queue *vspq, off_t off)
{
	size_t left = 0, right = vspq->vsq_count;

	while (left < right) {
		const size_t mid = left + (right - left) / 2;

		if (vspq->vsq[mid].off > off) {
			left = mid + 1;
		} else {
			right = mid;
		}
	}
	return left;
}

static void vspq_shift_right(struct silofs_vsp_queue *vspq, size_t pos)
{
	silofs_assert_lt(pos, vspq->vsq_count);
	silofs_assert_lt(vspq->vsq_count, ARRAY_SIZE(vspq->vsq));

	for (size_t i = vspq->vsq_count; i > pos; --i) {
		vspan_assign(&vspq->vsq[i], &vspq->vsq[i - 1]);
	}
}

static void vspq_shift_left(struct silofs_vsp_queue *vspq, size_t pos)
{
	silofs_assert_lt(pos, vspq->vsq_count);

	for (size_t i = pos; i < vspq->vsq_count - 1; ++i) {
		vspan_assign(&vspq->vsq[i], &vspq->vsq[i + 1]);
	}
	vspan_reset(&vspq->vsq[vspq->vsq_count - 1]);
}

static void vspq_insert_at(struct silofs_vsp_queue *vspq, size_t pos,
                           off_t off, size_t len)
{
	silofs_assert_le(pos, vspq->vsq_count);
	silofs_assert_lt(vspq->vsq_count, ARRAY_SIZE(vspq->vsq));

	if (pos != vspq->vsq_count) {
		vspq_shift_right(vspq, pos);
	}
	vspan_init(&vspq->vsq[pos], off, len);
	vspq->vsq_count++;
}

static void vspq_remove_at(struct silofs_vsp_queue *vspq, size_t pos)
{
	silofs_assert_lt(pos, vspq->vsq_count);
	silofs_assert_gt(vspq->vsq_count, 0);

	vspq_shift_left(vspq, pos);
	vspq->vsq_count--;
}

static bool vspq_try_merge_prev(struct silofs_vsp_queue *vspq, size_t pos,
                                off_t off, size_t len)
{
	struct silofs_vspan *vspan_prev;

	if (pos == 0) {
		return false;
	}
	vspan_prev = &vspq->vsq[pos - 1];
	if (off + (off_t)len != vspan_prev->off) {
		return false;
	}
	vspan_expand_head(vspan_prev, len);
	return true;
}

static bool vspq_try_merge_next(struct silofs_vsp_queue *vspq, size_t pos,
                                off_t off, size_t len)
{
	struct silofs_vspan *vspan_next;

	if (pos >= vspq->vsq_count) {
		return false;
	}
	vspan_next = &vspq->vsq[pos];
	if (vspan_next->off + (off_t)vspan_next->len != off) {
		return false;
	}
	vspan_expand_tail(vspan_next, len);
	return true;
}

static bool vspq_try_merge_both(struct silofs_vsp_queue *vspq, size_t pos)
{
	struct silofs_vspan *vspan_prev;
	struct silofs_vspan *vspan_next;

	if (pos == 0 || pos >= vspq->vsq_count) {
		return false;
	}
	vspan_prev = &vspq->vsq[pos - 1];
	vspan_next = &vspq->vsq[pos];
	if (vspan_next->off + (off_t)vspan_next->len != vspan_prev->off) {
		return false;
	}
	vspan_merge_with(vspan_next, vspan_prev);
	vspq_remove_at(vspq, pos - 1);
	return true;
}

static void
vspq_do_pop(struct silofs_vsp_queue *vspq, size_t len, off_t *out_off)
{
	struct silofs_vspan *vspan = &vspq->vsq[vspq->vsq_count - 1];

	*out_off = vspan->off;

	if (vspan->len > len) {
		/* partial pop: chop in-place */
		vspan_trim_head(vspan, len);
	} else {
		/* full pop */
		silofs_assert_eq(vspan->len, len);
		vspan_reset(vspan);
		vspq->vsq_count--;
	}
}

static int vspq_pop(struct silofs_vsp_queue *vspq, size_t len, off_t *out_off)
{
	if (vspq->vsq_objsz != len) {
		return -SILOFS_EINVAL;
	}
	if (!vspq->vsq_count) {
		return -SILOFS_ENOENT;
	}

	vspq_do_pop(vspq, len, out_off);
	return 0;
}

static bool
vspq_try_merge(struct silofs_vsp_queue *vspq, off_t off, size_t len)
{
	const size_t pos = vspq_lower_bound(vspq, off);
	bool merged;

	merged = vspq_try_merge_prev(vspq, pos, off, len);
	if (merged) {
		vspq_try_merge_both(vspq, pos);
		goto out;
	}
	merged = vspq_try_merge_next(vspq, pos, off, len);
out:
	return merged;
}

static void vspq_insert(struct silofs_vsp_queue *vspq, off_t off, size_t len)
{
	const size_t pos = vspq_lower_bound(vspq, off);

	vspq_insert_at(vspq, pos, off, len);
}

static bool vspq_cap_insert(const struct silofs_vsp_queue *vspq)
{
	constexpr size_t size_max = ARRAY_SIZE(vspq->vsq);

	return (vspq->vsq_count < size_max);
}

static int vspq_push(struct silofs_vsp_queue *vspq, off_t off, size_t len)
{
	bool merged;

	if (vspq->vsq_objsz != len) {
		return -SILOFS_EINVAL;
	}
	merged = vspq_try_merge(vspq, off, len);
	if (merged) {
		return 0;
	}
	if (!vspq_cap_insert(vspq)) {
		return -SILOFS_ENOSPC;
	}
	vspq_insert(vspq, off, len);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static long off_compare(const void *x, const void *y)
{
	const off_t *off_x = x;
	const off_t *off_y = y;

	return *off_y - *off_x;
}

static struct silofs_vsp_entry *
avl_node_to_vspe(const struct silofs_avl_node *an)
{
	const struct silofs_vsp_entry *vspe = nullptr;

	if (an != nullptr) {
		vspe = container_of2(an, struct silofs_vsp_entry, vspe_an);
	}
	return silofs_unconst(vspe);
}

static const void *vspe_getkey(const struct silofs_avl_node *an)
{
	const struct silofs_vsp_entry *vspe = avl_node_to_vspe(an);

	return &vspe->vspe_span.off;
}

static void vspe_init(struct silofs_vsp_entry *vspe, off_t off, size_t len)
{
	silofs_avl_node_init(&vspe->vspe_an);
	vspan_init(&vspe->vspe_span, off, len);
}

static void vspe_fini(struct silofs_vsp_entry *vspe)
{
	silofs_avl_node_fini(&vspe->vspe_an);
	vspan_fini(&vspe->vspe_span);
}

static off_t vspe_end(const struct silofs_vsp_entry *vspe)
{
	return vspan_end(&vspe->vspe_span);
}

static void vspe_trim_head(struct silofs_vsp_entry *vspe, size_t len)
{
	vspan_trim_head(&vspe->vspe_span, len);
}

static struct silofs_vsp_entry *
vspe_new(off_t off, size_t len, struct silofs_alloc *alloc)
{
	struct silofs_vsp_entry *vspe;

	vspe = silofs_memalloc(alloc, sizeof(*vspe), 0);
	if (vspe != nullptr) {
		vspe_init(vspe, off, len);
	}
	return vspe;
}

static void vspe_del(struct silofs_vsp_entry *vspe, struct silofs_alloc *alloc)
{
	if (vspe != nullptr) { /* make gcc-analyzer happy */
		vspe_fini(vspe);
		silofs_memfree(alloc, vspe, sizeof(*vspe), 0);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_vsp_entry *
vspmap_new_vspe(struct silofs_vspmap *vspm, off_t off, size_t len)
{
	struct silofs_vsp_entry *vspe;

	vspe = vspe_new(off, len, vspm->alloc);
	return vspe;
}

static void
vspmap_delete_vspe(struct silofs_vspmap *vspm, struct silofs_vsp_entry *vspe)
{
	vspe_del(vspe, vspm->alloc);
}

static struct silofs_vsp_entry *
vspmap_minimal_vspe(const struct silofs_vspmap *vspm)
{
	struct silofs_avl_node *an;
	const struct silofs_avl *avl = &vspm->avl;

	if (avl->size == 0) {
		return nullptr;
	}
	an = silofs_avl_begin(avl);
	return avl_node_to_vspe(an);
}

static struct silofs_vsp_entry *
vspmap_maximal_vspe(const struct silofs_vspmap *vspm)
{
	struct silofs_avl_node *an   = nullptr;
	const struct silofs_avl *avl = &vspm->avl;

	if (avl->size == 0) {
		return nullptr;
	}
	an = silofs_avl_rbegin(avl);
	return avl_node_to_vspe(an);
}

static struct silofs_vsp_entry *
vspmap_lower_bound_vspe(const struct silofs_vspmap *vspm, off_t off)
{
	const struct silofs_avl_node *an;
	const struct silofs_avl *avl = &vspm->avl;

	an = silofs_avl_lower_bound(avl, &off);
	return avl_node_to_vspe(an);
}

static struct silofs_vsp_entry *
vspmap_prev_of(const struct silofs_vspmap *vspm,
               const struct silofs_vsp_entry *vspe)
{
	const struct silofs_avl_node *an_prev;
	const struct silofs_avl *avl = &vspm->avl;

	an_prev = silofs_avl_prev(avl, &vspe->vspe_an);
	if (an_prev == silofs_avl_end(avl)) {
		return nullptr;
	}
	return avl_node_to_vspe(an_prev);
}

static void vspmap_find_next_prev(const struct silofs_vspmap *vspm, off_t off,
                                  struct silofs_vsp_entry **out_vspe_prev,
                                  struct silofs_vsp_entry **out_vspe_next)
{
	struct silofs_vsp_entry *vspe_next, *vspe_prev;

	vspe_next = vspmap_lower_bound_vspe(vspm, off);
	if (vspe_next != nullptr) {
		vspe_prev = vspmap_prev_of(vspm, vspe_next);
	} else {
		vspe_prev = vspmap_maximal_vspe(vspm);
	}
	*out_vspe_prev = vspe_prev;
	*out_vspe_next = vspe_next;
}

static void
vspmap_insert_vspe(struct silofs_vspmap *vspm, struct silofs_vsp_entry *vspe)
{
	struct silofs_avl_node *an = &vspe->vspe_an;
	struct silofs_avl *avl     = &vspm->avl;

	silofs_avl_insert(avl, an);
}

static void
vspmap_remove_vspe(struct silofs_vspmap *vspm, struct silofs_vsp_entry *vspe)
{
	struct silofs_avl_node *an = &vspe->vspe_an;
	struct silofs_avl *avl     = &vspm->avl;

	silofs_avl_remove(avl, an);
}

static void
vspmap_evict_vspe(struct silofs_vspmap *vspm, struct silofs_vsp_entry *vspe)
{
	vspmap_remove_vspe(vspm, vspe);
	vspmap_delete_vspe(vspm, vspe);
}

static bool vspmap_check_cap_add(const struct silofs_vspmap *vspm)
{
	const size_t size = vspm->avl.size;

	return (size < 1024);
}

static int vspmap_pull(struct silofs_vspmap *vspm, size_t len, off_t *out_off)
{
	struct silofs_vsp_entry *vspe;
	int err;

	err = vspq_pop(&vspm->vspq, len, out_off);
	if (!err) {
		return 0;
	}
	vspe = vspmap_minimal_vspe(vspm);
	if (vspe == nullptr) {
		return -SILOFS_ENOSPC;
	}
	if (len > vspe->vspe_span.len) {
		return -SILOFS_ENOSPC;
	}
	*out_off = vspe->vspe_span.off;
	if (len < vspe->vspe_span.len) {
		/* its ok to modify in-place and avoid the costly remove-insert
		 * into the tree, as this is already the minimal element */
		vspe_trim_head(vspe, len);
	} else {
		vspmap_evict_vspe(vspm, vspe);
	}
	return 0;
}

static int vspmap_merge(struct silofs_vspmap *vspm, off_t off, size_t len)
{
	struct silofs_vsp_entry *vspe = nullptr;
	struct silofs_vsp_entry *vspe_prev, *vspe_next;
	off_t end;
	int ret = -SILOFS_ENOENT;

	end = silofs_off_end(off, len);
	vspmap_find_next_prev(vspm, off, &vspe_prev, &vspe_next);

	if (vspe_prev && (vspe_end(vspe_prev) == off)) {
		/* merge range into prev */
		vspe = vspe_prev;
		vspan_expand_tail(&vspe->vspe_span, len);
		vspan_range(&vspe->vspe_span, &off, &end);
		ret = 0;
	}
	if (vspe_next == nullptr) {
		/* no next to append with */
		return ret;
	}
	if (end != vspe_next->vspe_span.off) {
		/* can not merge with next */
		return ret;
	}
	end = vspe_end(vspe_next);
	if (vspe == nullptr) {
		const size_t new_len = silofs_off_ulen(off, end);

		/* merge with next only */
		vspmap_evict_vspe(vspm, vspe_next);
		vspe = vspmap_new_vspe(vspm, off, new_len);
		if (vspe == nullptr) {
			return -SILOFS_ENOMEM;
		}
		vspmap_insert_vspe(vspm, vspe);
	} else {
		/* full merge (prev + next ) */
		vspan_merge_with(&vspe->vspe_span, &vspe_next->vspe_span);
		vspmap_evict_vspe(vspm, vspe_next);
	}
	return 0;
}

static int vspmap_insert(struct silofs_vspmap *vspm, off_t off, size_t len)
{
	struct silofs_vsp_entry *vspe;

	vspe = vspmap_new_vspe(vspm, off, len);
	if (vspe == nullptr) {
		return -SILOFS_ENOMEM;
	}
	vspmap_insert_vspe(vspm, vspe);
	return 0;
}

static int vspmap_add(struct silofs_vspmap *vspm, off_t off, size_t len)
{
	int err;
	bool cap_add;

	err = vspq_push(&vspm->vspq, off, len);
	if (!err) {
		return 0;
	}
	err = vspmap_merge(vspm, off, len);
	if (err != -SILOFS_ENOENT) {
		return err;
	}
	cap_add = vspmap_check_cap_add(vspm);
	if (!cap_add) {
		return -SILOFS_ENOMEM;
	}
	err = vspmap_insert(vspm, off, len);
	if (err) {
		return err;
	}
	return 0;
}

static void vspmap_avl_node_delete_cb(struct silofs_avl_node *an, void *p)
{
	struct silofs_vspmap *vspm    = p;
	struct silofs_vsp_entry *vspe = avl_node_to_vspe(an);

	vspmap_delete_vspe(vspm, vspe);
}

static void vspmap_clear(struct silofs_vspmap *vspm)
{
	const struct silofs_avl_node_functor fn = {
		.fn  = vspmap_avl_node_delete_cb,
		.ctx = vspm,
	};

	silofs_avl_clear(&vspm->avl, &fn);
	vspq_clear(&vspm->vspq);
}

static void vspmap_init(struct silofs_vspmap *vspm, uint32_t objsz,
                        struct silofs_alloc *alloc)
{
	vspq_init(&vspm->vspq, objsz);
	silofs_avl_init(&vspm->avl, vspe_getkey, off_compare, vspm);
	vspm->alloc = alloc;
}

static void vspmap_fini(struct silofs_vspmap *vspm)
{
	vspmap_clear(vspm);
	vspq_fini(&vspm->vspq);
	silofs_avl_fini(&vspm->avl);
	vspm->alloc = nullptr;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t vspmaps_vtype_to_slot(enum silofs_vtype vtype)
{
	return (size_t)(vtype - 1);
}

static enum silofs_vtype vspmaps_slot_to_vtype(size_t slot)
{
	return (enum silofs_vtype)(slot + 1);
}

static struct silofs_vspmap *
vspmaps_mut_sub(struct silofs_vspmaps *vspms, enum silofs_vtype vtype)
{
	constexpr size_t nslots = ARRAY_SIZE(vspms->vspm);
	const size_t slot       = vspmaps_vtype_to_slot(vtype);

	return (slot < nslots) ? &vspms->vspm[slot] : nullptr;
}

int silofs_vspmaps_push(struct silofs_vspmaps *vspms,
                        const struct silofs_vaddr *vaddr)
{
	struct silofs_vspmap *vspm;
	size_t len;

	vspm = vspmaps_mut_sub(vspms, vaddr->vtype);
	if (unlikely(vspm == nullptr)) {
		return -SILOFS_EINVAL;
	}
	len = vtype_size(vaddr->vtype);
	return vspmap_add(vspm, vaddr->off, len);
}

int silofs_vspmaps_pull(struct silofs_vspmaps *vspms, enum silofs_vtype vtype,
                        struct silofs_vaddr *out_vaddr)
{
	struct silofs_vspmap *vspm;
	size_t len;
	off_t off;
	int err;

	vspm = vspmaps_mut_sub(vspms, vtype);
	if (unlikely(vspm == nullptr)) {
		return -SILOFS_EINVAL;
	}
	len = vtype_size(vtype);
	err = vspmap_pull(vspm, len, &off);
	if (err) {
		return err;
	}
	silofs_vaddr_setup(out_vaddr, vtype, off);
	return 0;
}

void silofs_vspmaps_drop(struct silofs_vspmaps *vspms)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(vspms->vspm); ++slot) {
		vspmap_clear(&vspms->vspm[slot]);
	}
}

int silofs_vspmaps_init(struct silofs_vspmaps *vspms,
                        struct silofs_alloc *alloc)
{
	enum silofs_vtype vtype;

	for (size_t slot = 0; slot < ARRAY_SIZE(vspms->vspm); ++slot) {
		vtype = vspmaps_slot_to_vtype(slot);
		vspmap_init(&vspms->vspm[slot], vtype_size(vtype), alloc);
	}
	return 0;
}

void silofs_vspmaps_fini(struct silofs_vspmaps *vspms)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(vspms->vspm); ++slot) {
		vspmap_fini(&vspms->vspm[slot]);
	}
}
