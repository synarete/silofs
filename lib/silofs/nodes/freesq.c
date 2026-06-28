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
#include <silofs/nodes.h>

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

static void fvsa_clear(struct silofs_freevs_arr *fvsa)
{
	for (size_t i = 0; i < ARRAY_SIZE(fvsa->fva); ++i) {
		vspan_reset(&fvsa->fva[i]);
	}
	fvsa->fva_count = 0;
}

static void fvsa_init(struct silofs_freevs_arr *fvsa, uint32_t objsz)
{
	fvsa_clear(fvsa);
	fvsa->fva_objsz = objsz;
}

static void fvsa_fini(struct silofs_freevs_arr *fvsa)
{
	fvsa_clear(fvsa);
	fvsa->fva_objsz = 0;
}

static size_t fvsa_lower_bound(const struct silofs_freevs_arr *fvsa, off_t off)
{
	size_t left = 0, right = fvsa->fva_count;

	while (left < right) {
		const size_t mid = left + (right - left) / 2;

		if (fvsa->fva[mid].off > off) {
			left = mid + 1;
		} else {
			right = mid;
		}
	}
	return left;
}

static void fvsa_shift_right(struct silofs_freevs_arr *fvsa, size_t pos)
{
	silofs_assert_lt(pos, fvsa->fva_count);
	silofs_assert_lt(fvsa->fva_count, ARRAY_SIZE(fvsa->fva));

	for (size_t i = fvsa->fva_count; i > pos; --i) {
		vspan_assign(&fvsa->fva[i], &fvsa->fva[i - 1]);
	}
}

static void fvsa_shift_left(struct silofs_freevs_arr *fvsa, size_t pos)
{
	silofs_assert_lt(pos, fvsa->fva_count);

	for (size_t i = pos; i < fvsa->fva_count - 1; ++i) {
		vspan_assign(&fvsa->fva[i], &fvsa->fva[i + 1]);
	}
	vspan_reset(&fvsa->fva[fvsa->fva_count - 1]);
}

static void fvsa_insert_at(struct silofs_freevs_arr *fvsa, size_t pos,
                           off_t off, size_t len)
{
	silofs_assert_le(pos, fvsa->fva_count);
	silofs_assert_lt(fvsa->fva_count, ARRAY_SIZE(fvsa->fva));

	if (pos != fvsa->fva_count) {
		fvsa_shift_right(fvsa, pos);
	}
	vspan_init(&fvsa->fva[pos], off, len);
	fvsa->fva_count++;
}

static void fvsa_remove_at(struct silofs_freevs_arr *fvsa, size_t pos)
{
	silofs_assert_lt(pos, fvsa->fva_count);
	silofs_assert_gt(fvsa->fva_count, 0);

	fvsa_shift_left(fvsa, pos);
	fvsa->fva_count--;
}

static bool fvsa_try_merge_prev(struct silofs_freevs_arr *fvsa, size_t pos,
                                off_t off, size_t len)
{
	struct silofs_vspan *vspan_prev;

	if (pos == 0) {
		return false;
	}
	vspan_prev = &fvsa->fva[pos - 1];
	if (off + (off_t)len != vspan_prev->off) {
		return false;
	}
	vspan_expand_head(vspan_prev, len);
	return true;
}

static bool fvsa_try_merge_next(struct silofs_freevs_arr *fvsa, size_t pos,
                                off_t off, size_t len)
{
	struct silofs_vspan *vspan_next;

	if (pos >= fvsa->fva_count) {
		return false;
	}
	vspan_next = &fvsa->fva[pos];
	if (vspan_next->off + (off_t)vspan_next->len != off) {
		return false;
	}
	vspan_expand_tail(vspan_next, len);
	return true;
}

static bool fvsa_try_merge_both(struct silofs_freevs_arr *fvsa, size_t pos)
{
	struct silofs_vspan *vspan_prev;
	struct silofs_vspan *vspan_next;

	if (pos == 0 || pos >= fvsa->fva_count) {
		return false;
	}
	vspan_prev = &fvsa->fva[pos - 1];
	vspan_next = &fvsa->fva[pos];
	if (vspan_next->off + (off_t)vspan_next->len != vspan_prev->off) {
		return false;
	}
	vspan_merge_with(vspan_next, vspan_prev);
	fvsa_remove_at(fvsa, pos - 1);
	return true;
}

static void
fvsa_do_pop(struct silofs_freevs_arr *fvsa, size_t len, off_t *out_off)
{
	struct silofs_vspan *vspan = &fvsa->fva[fvsa->fva_count - 1];

	*out_off = vspan->off;

	if (vspan->len > len) {
		/* partial pop: chop in-place */
		vspan_trim_head(vspan, len);
	} else {
		/* full pop */
		silofs_assert_eq(vspan->len, len);
		vspan_reset(vspan);
		fvsa->fva_count--;
	}
}

static int fvsa_pop(struct silofs_freevs_arr *fvsa, size_t len, off_t *out_off)
{
	if (fvsa->fva_objsz != len) {
		return -SILOFS_EINVAL;
	}
	if (!fvsa->fva_count) {
		return -SILOFS_ENOENT;
	}

	fvsa_do_pop(fvsa, len, out_off);
	return 0;
}

static bool
fvsa_try_merge(struct silofs_freevs_arr *fvsa, off_t off, size_t len)
{
	const size_t pos = fvsa_lower_bound(fvsa, off);
	bool merged;

	merged = fvsa_try_merge_prev(fvsa, pos, off, len);
	if (merged) {
		fvsa_try_merge_both(fvsa, pos);
		goto out;
	}
	merged = fvsa_try_merge_next(fvsa, pos, off, len);
out:
	return merged;
}

static void fvsa_insert(struct silofs_freevs_arr *fvsa, off_t off, size_t len)
{
	const size_t pos = fvsa_lower_bound(fvsa, off);

	fvsa_insert_at(fvsa, pos, off, len);
}

static bool fvsa_cap_insert(const struct silofs_freevs_arr *fvsa)
{
	constexpr size_t size_max = ARRAY_SIZE(fvsa->fva);

	return (fvsa->fva_count < size_max);
}

static int fvsa_push(struct silofs_freevs_arr *fvsa, off_t off, size_t len)
{
	bool merged;

	if (fvsa->fva_objsz != len) {
		return -SILOFS_EINVAL;
	}
	merged = fvsa_try_merge(fvsa, off, len);
	if (merged) {
		return 0;
	}
	if (!fvsa_cap_insert(fvsa)) {
		return -SILOFS_ENOSPC;
	}
	fvsa_insert(fvsa, off, len);
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
		vspe = container_of(an, struct silofs_vsp_entry, vspe_an);
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
fvsq_new_vspe(struct silofs_freevsq *fvsq, off_t off, size_t len)
{
	struct silofs_vsp_entry *vspe;

	vspe = vspe_new(off, len, fvsq->fvs_alloc);
	return vspe;
}

static void
fvsq_delete_vspe(struct silofs_freevsq *fvsq, struct silofs_vsp_entry *vspe)
{
	vspe_del(vspe, fvsq->fvs_alloc);
}

static struct silofs_vsp_entry *
fvsq_minimal_vspe(const struct silofs_freevsq *fvsq)
{
	struct silofs_avl_node *an;
	const struct silofs_avl *avl = &fvsq->fvs_avl;

	if (avl->size == 0) {
		return nullptr;
	}
	an = silofs_avl_begin(avl);
	return avl_node_to_vspe(an);
}

static struct silofs_vsp_entry *
fvsq_maximal_vspe(const struct silofs_freevsq *fvsq)
{
	struct silofs_avl_node *an   = nullptr;
	const struct silofs_avl *avl = &fvsq->fvs_avl;

	if (avl->size == 0) {
		return nullptr;
	}
	an = silofs_avl_rbegin(avl);
	return avl_node_to_vspe(an);
}

static struct silofs_vsp_entry *
fvsq_lower_bound_vspe(const struct silofs_freevsq *fvsq, off_t off)
{
	const struct silofs_avl_node *an;
	const struct silofs_avl *avl = &fvsq->fvs_avl;

	an = silofs_avl_lower_bound(avl, &off);
	return avl_node_to_vspe(an);
}

static struct silofs_vsp_entry *
fvsq_prev_of(const struct silofs_freevsq *fvsq,
             const struct silofs_vsp_entry *vspe)
{
	const struct silofs_avl_node *an_prev;
	const struct silofs_avl *avl = &fvsq->fvs_avl;

	an_prev = silofs_avl_prev(avl, &vspe->vspe_an);
	if (an_prev == silofs_avl_end(avl)) {
		return nullptr;
	}
	return avl_node_to_vspe(an_prev);
}

static void fvsq_find_next_prev(const struct silofs_freevsq *fvsq, off_t off,
                                struct silofs_vsp_entry **out_vspe_prev,
                                struct silofs_vsp_entry **out_vspe_next)
{
	struct silofs_vsp_entry *vspe_next, *vspe_prev;

	vspe_next = fvsq_lower_bound_vspe(fvsq, off);
	if (vspe_next != nullptr) {
		vspe_prev = fvsq_prev_of(fvsq, vspe_next);
	} else {
		vspe_prev = fvsq_maximal_vspe(fvsq);
	}
	*out_vspe_prev = vspe_prev;
	*out_vspe_next = vspe_next;
}

static void
fvsq_insert_vspe(struct silofs_freevsq *fvsq, struct silofs_vsp_entry *vspe)
{
	struct silofs_avl_node *an = &vspe->vspe_an;
	struct silofs_avl *avl     = &fvsq->fvs_avl;

	silofs_avl_insert(avl, an);
}

static void
fvsq_remove_vspe(struct silofs_freevsq *fvsq, struct silofs_vsp_entry *vspe)
{
	struct silofs_avl_node *an = &vspe->vspe_an;
	struct silofs_avl *avl     = &fvsq->fvs_avl;

	silofs_avl_remove(avl, an);
}

static void
fvsq_evict_vspe(struct silofs_freevsq *fvsq, struct silofs_vsp_entry *vspe)
{
	fvsq_remove_vspe(fvsq, vspe);
	fvsq_delete_vspe(fvsq, vspe);
}

static bool fvsq_check_cap_add(const struct silofs_freevsq *fvsq)
{
	const size_t size = fvsq->fvs_avl.size;

	return (size < 1024);
}

static int fvsq_pull(struct silofs_freevsq *fvsq, size_t len, off_t *out_off)
{
	struct silofs_vsp_entry *vspe;
	int err;

	err = fvsa_pop(&fvsq->fvs_arr, len, out_off);
	if (!err) {
		return 0;
	}
	vspe = fvsq_minimal_vspe(fvsq);
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
		fvsq_evict_vspe(fvsq, vspe);
	}
	return 0;
}

static int fvsq_merge(struct silofs_freevsq *fvsq, off_t off, size_t len)
{
	struct silofs_vsp_entry *vspe = nullptr;
	struct silofs_vsp_entry *vspe_prev, *vspe_next;
	off_t end;
	int ret = -SILOFS_ENOENT;

	end = silofs_off_end(off, len);
	fvsq_find_next_prev(fvsq, off, &vspe_prev, &vspe_next);

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
		fvsq_evict_vspe(fvsq, vspe_next);
		vspe = fvsq_new_vspe(fvsq, off, new_len);
		if (vspe == nullptr) {
			return -SILOFS_ENOMEM;
		}
		fvsq_insert_vspe(fvsq, vspe);
	} else {
		/* full merge (prev + next ) */
		vspan_merge_with(&vspe->vspe_span, &vspe_next->vspe_span);
		fvsq_evict_vspe(fvsq, vspe_next);
	}
	return 0;
}

static int fvsq_insert(struct silofs_freevsq *fvsq, off_t off, size_t len)
{
	struct silofs_vsp_entry *vspe;

	vspe = fvsq_new_vspe(fvsq, off, len);
	if (vspe == nullptr) {
		return -SILOFS_ENOMEM;
	}
	fvsq_insert_vspe(fvsq, vspe);
	return 0;
}

static int fvsq_add(struct silofs_freevsq *fvsq, off_t off, size_t len)
{
	int err;
	bool cap_add;

	err = fvsa_push(&fvsq->fvs_arr, off, len);
	if (!err) {
		return 0;
	}
	err = fvsq_merge(fvsq, off, len);
	if (err != -SILOFS_ENOENT) {
		return err;
	}
	cap_add = fvsq_check_cap_add(fvsq);
	if (!cap_add) {
		return -SILOFS_ENOMEM;
	}
	err = fvsq_insert(fvsq, off, len);
	if (err) {
		return err;
	}
	return 0;
}

static void fvsq_avl_node_delete_cb(struct silofs_avl_node *an, void *p)
{
	struct silofs_freevsq *fvsq   = p;
	struct silofs_vsp_entry *vspe = avl_node_to_vspe(an);

	fvsq_delete_vspe(fvsq, vspe);
}

static void fvsq_clear(struct silofs_freevsq *fvsq)
{
	const struct silofs_avl_node_functor fn = {
		.fn  = fvsq_avl_node_delete_cb,
		.ctx = fvsq,
	};

	silofs_avl_clear(&fvsq->fvs_avl, &fn);
	fvsa_clear(&fvsq->fvs_arr);
}

static void fvsq_init(struct silofs_freevsq *fvsq, uint32_t objsz,
                      struct silofs_alloc *alloc)
{
	fvsa_init(&fvsq->fvs_arr, objsz);
	silofs_avl_init(&fvsq->fvs_avl, vspe_getkey, off_compare, fvsq);
	fvsq->fvs_alloc = alloc;
}

static void fvsq_fini(struct silofs_freevsq *fvsq)
{
	fvsq_clear(fvsq);
	fvsa_fini(&fvsq->fvs_arr);
	silofs_avl_fini(&fvsq->fvs_avl);
	fvsq->fvs_alloc = nullptr;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t fvsqs_vtype_to_slot(enum silofs_vtype vtype)
{
	return (size_t)(vtype - 1);
}

static enum silofs_vtype fvsqs_slot_to_vtype(size_t slot)
{
	return (enum silofs_vtype)(slot + 1);
}

static struct silofs_freevsq *
fvsqs_mut_sub(struct silofs_freevsqs *fvsqs, enum silofs_vtype vtype)
{
	constexpr size_t nslots = ARRAY_SIZE(fvsqs->fvsq);
	const size_t slot       = fvsqs_vtype_to_slot(vtype);

	return (slot < nslots) ? &fvsqs->fvsq[slot] : nullptr;
}

int silofs_freevsqs_push(struct silofs_freevsqs *fvsqs,
                         const struct silofs_vaddr *vaddr)
{
	struct silofs_freevsq *fvsq;
	size_t len;

	fvsq = fvsqs_mut_sub(fvsqs, vaddr->vtype);
	if (unlikely(fvsq == nullptr)) {
		return -SILOFS_EINVAL;
	}
	len = vtype_size(vaddr->vtype);
	return fvsq_add(fvsq, vaddr->off, len);
}

int silofs_freevsqs_pull(struct silofs_freevsqs *fvsqs,
                         enum silofs_vtype vtype,
                         struct silofs_vaddr *out_vaddr)
{
	struct silofs_freevsq *fvsq;
	size_t len;
	off_t off;
	int err;

	fvsq = fvsqs_mut_sub(fvsqs, vtype);
	if (unlikely(fvsq == nullptr)) {
		return -SILOFS_EINVAL;
	}
	len = vtype_size(vtype);
	err = fvsq_pull(fvsq, len, &off);
	if (err) {
		return err;
	}
	silofs_vaddr_setup(out_vaddr, vtype, off);
	return 0;
}

void silofs_freevsqs_drop(struct silofs_freevsqs *fvsqs)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(fvsqs->fvsq); ++slot) {
		fvsq_clear(&fvsqs->fvsq[slot]);
	}
}

int silofs_freevsqs_init(struct silofs_freevsqs *fvsqs,
                         struct silofs_alloc *alloc)
{
	enum silofs_vtype vtype;

	for (size_t slot = 0; slot < ARRAY_SIZE(fvsqs->fvsq); ++slot) {
		vtype = fvsqs_slot_to_vtype(slot);
		fvsq_init(&fvsqs->fvsq[slot], vtype_size(vtype), alloc);
	}
	return 0;
}

void silofs_freevsqs_fini(struct silofs_freevsqs *fvsqs)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(fvsqs->fvsq); ++slot) {
		fvsq_fini(&fvsqs->fvsq[slot]);
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_freepaq_entry *fpae_from_lh(struct silofs_list_head *lh)
{
	return mut_container_of(lh, struct silofs_freepaq_entry, lh);
}

static struct silofs_freepaq_entry *fpae_malloc(struct silofs_alloc *alloc)
{
	struct silofs_freepaq_entry *fpae = nullptr;

	fpae = silofs_memalloc(alloc, sizeof(*fpae), 0);
	return fpae;
}

static void
fpae_free(struct silofs_freepaq_entry *fpae, struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, fpae, sizeof(*fpae), 0);
}

static void
fpae_init(struct silofs_freepaq_entry *fpae, const struct silofs_paddr *paddr)
{
	silofs_list_head_init(&fpae->lh);
	silofs_paddr_assign(&fpae->paddr, paddr);
}

static void fpae_fini(struct silofs_freepaq_entry *fpae)
{
	silofs_list_head_fini(&fpae->lh);
	silofs_paddr_reset(&fpae->paddr);
}

static struct silofs_freepaq_entry *
fpae_new(const struct silofs_paddr *paddr, struct silofs_alloc *alloc)
{
	struct silofs_freepaq_entry *fpae;

	fpae = fpae_malloc(alloc);
	if (fpae != nullptr) {
		fpae_init(fpae, paddr);
	}
	return fpae;
}

static void
fpae_del(struct silofs_freepaq_entry *fpae, struct silofs_alloc *alloc)
{
	fpae_fini(fpae);
	fpae_free(fpae, alloc);
}

static void fpae_paddr(const struct silofs_freepaq_entry *fpae,
                       struct silofs_paddr *out_paddr)
{
	silofs_paddr_assign(out_paddr, &fpae->paddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fpaq_init(struct silofs_freepaq *fpaq, struct silofs_alloc *alloc)
{
	silofs_listq_init(&fpaq->fpaq_listq);
	fpaq->fpaq_alloc = alloc;
}

static void fpaq_fini(struct silofs_freepaq *fpaq)
{
	silofs_listq_init(&fpaq->fpaq_listq);
	fpaq->fpaq_alloc = nullptr;
}

static bool fpaq_cap_push(const struct silofs_freepaq *fpaq)
{
	const size_t sz = silofs_listq_size(&fpaq->fpaq_listq);

	return (sz < 1024);
}

static int
fpaq_push(struct silofs_freepaq *fpaq, const struct silofs_paddr *paddr)
{
	struct silofs_freepaq_entry *fpae;

	if (!fpaq_cap_push(fpaq)) {
		return -SILOFS_ENOSPC;
	}
	fpae = fpae_new(paddr, fpaq->fpaq_alloc);
	if (fpae == nullptr) {
		return -SILOFS_ENOMEM;
	}
	silofs_listq_push_back(&fpaq->fpaq_listq, &fpae->lh);
	return 0;
}

static struct silofs_freepaq_entry *fpaq_pop_front(struct silofs_freepaq *fpaq)
{
	struct silofs_list_head *lh;
	struct silofs_freepaq_entry *fpae = nullptr;

	lh = silofs_listq_pop_front(&fpaq->fpaq_listq);
	if (lh != nullptr) {
		fpae = fpae_from_lh(lh);
	}
	return fpae;
}

static int
fpaq_pop(struct silofs_freepaq *fpaq, struct silofs_paddr *out_paddr)
{
	struct silofs_freepaq_entry *fpae;

	fpae = fpaq_pop_front(fpaq);
	if (fpae == nullptr) {
		return -SILOFS_ENOENT;
	}
	fpae_paddr(fpae, out_paddr);
	fpae_del(fpae, fpaq->fpaq_alloc);
	return 0;
}

static void fpaq_clear(struct silofs_freepaq *fpaq)
{
	struct silofs_freepaq_entry *fpae;

	fpae = fpaq_pop_front(fpaq);
	while (fpae != nullptr) {
		fpae_del(fpae, fpaq->fpaq_alloc);
		fpae = fpaq_pop_front(fpaq);
	}
}

static void fpaq_clear_fini(struct silofs_freepaq *fpaq)
{
	fpaq_clear(fpaq);
	fpaq_fini(fpaq);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_freepaqs_init(struct silofs_freepaqs *fpaqs,
                          struct silofs_alloc *alloc)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(fpaqs->fpaq_bn); ++slot) {
		fpaq_init(&fpaqs->fpaq_bn[slot], alloc);
	}
	for (size_t slot = 0; slot < ARRAY_SIZE(fpaqs->fpaq_vn); ++slot) {
		fpaq_init(&fpaqs->fpaq_vn[slot], alloc);
	}
}

void silofs_freepaqs_fini(struct silofs_freepaqs *fpaqs)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(fpaqs->fpaq_bn); ++slot) {
		fpaq_clear_fini(&fpaqs->fpaq_bn[slot]);
	}
	for (size_t slot = 0; slot < ARRAY_SIZE(fpaqs->fpaq_vn); ++slot) {
		fpaq_clear_fini(&fpaqs->fpaq_vn[slot]);
	}
}

void silofs_freepaqs_drop(struct silofs_freepaqs *fpaqs)
{
	for (size_t slot = 0; slot < ARRAY_SIZE(fpaqs->fpaq_bn); ++slot) {
		fpaq_clear(&fpaqs->fpaq_bn[slot]);
	}
	for (size_t slot = 0; slot < ARRAY_SIZE(fpaqs->fpaq_vn); ++slot) {
		fpaq_clear(&fpaqs->fpaq_vn[slot]);
	}
}

static size_t fpaqs_vtype_to_slot(enum silofs_vtype vtype)
{
	return (size_t)(vtype - 1);
}

static struct silofs_freepaq *
freepaqs_mut_sub(struct silofs_freepaqs *fpaqs,
                 const struct silofs_stype *stype)
{
	struct silofs_freepaq *fpaq = nullptr;
	size_t slot;

	if (stype->ptype == SILOFS_PTYPE_BTNODE) {
		slot = fpaqs_vtype_to_slot(stype->vtype);
		if (slot < ARRAY_SIZE(fpaqs->fpaq_bn)) {
			fpaq = &fpaqs->fpaq_bn[slot];
		}
	} else if (stype->ptype == SILOFS_PTYPE_VNODE) {
		slot = fpaqs_vtype_to_slot(stype->vtype);
		if (slot < ARRAY_SIZE(fpaqs->fpaq_vn)) {
			fpaq = &fpaqs->fpaq_vn[slot];
		}
	}
	return fpaq;
}

static const struct silofs_stype *stype_of(const struct silofs_paddr *paddr)
{
	return &paddr->blobid.stype;
}

int silofs_freepaqs_push(struct silofs_freepaqs *fpaqs,
                         const struct silofs_paddr *paddr)
{
	struct silofs_freepaq *fpaq;
	int ret = -SILOFS_ENOENT;

	fpaq = freepaqs_mut_sub(fpaqs, stype_of(paddr));
	if (fpaq != nullptr) {
		ret = fpaq_push(fpaq, paddr);
	}
	return ret;
}

int silofs_freepaqs_pull(struct silofs_freepaqs *fpaqs,
                         const struct silofs_stype *stype,
                         struct silofs_paddr *out_paddr)
{
	struct silofs_freepaq *fpaq;
	int ret = -SILOFS_ENOENT;

	fpaq = freepaqs_mut_sub(fpaqs, stype);
	if (fpaq != nullptr) {
		ret = fpaq_pop(fpaq, out_paddr);
	}
	return ret;
}
