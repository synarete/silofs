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

static void vsplifo_clear(struct silofs_vsp_lifo *vspl)
{
	silofs_memzero(vspl->vsl_lifo, sizeof(vspl->vsl_lifo));
	vspl->vsl_count = 0;
}

static void vsplifo_init(struct silofs_vsp_lifo *vspl, uint32_t objsz)
{
	vsplifo_clear(vspl);
	vspl->vsl_objsz = objsz;
}

static void vsplifo_fini(struct silofs_vsp_lifo *vspl)
{
	vsplifo_clear(vspl);
}

static int
vsplifo_pop(struct silofs_vsp_lifo *vspl, size_t len, off_t *out_off)
{
	if (!vspl->vsl_count || (vspl->vsl_objsz != len)) {
		return -SILOFS_ENOENT;
	}
	*out_off = vspl->vsl_lifo[vspl->vsl_count - 1];
	vspl->vsl_count--;
	return 0;
}

static int vsplifo_push(struct silofs_vsp_lifo *vspl, off_t off, size_t len)
{
	constexpr size_t size_max = ARRAY_SIZE(vspl->vsl_lifo);

	if (!(vspl->vsl_count < size_max) || (vspl->vsl_objsz != len)) {
		return -SILOFS_ENOSPC;
	}
	vspl->vsl_lifo[vspl->vsl_count] = off;
	vspl->vsl_count++;
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

	vspe = vspe_new(off, len, vspm->vspm_alloc);
	return vspe;
}

static void
vspmap_delete_vspe(struct silofs_vspmap *vspm, struct silofs_vsp_entry *vspe)
{
	vspe_del(vspe, vspm->vspm_alloc);
}

static struct silofs_vsp_entry *
vspmap_minimal_vspe(const struct silofs_vspmap *vspm)
{
	struct silofs_avl_node *an;
	const struct silofs_avl *avl = &vspm->vspm_avl;

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
	const struct silofs_avl *avl = &vspm->vspm_avl;

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
	const struct silofs_avl *avl = &vspm->vspm_avl;

	an = silofs_avl_lower_bound(avl, &off);
	return avl_node_to_vspe(an);
}

static struct silofs_vsp_entry *
vspmap_prev_of(const struct silofs_vspmap *vspm,
               const struct silofs_vsp_entry *vspe)
{
	const struct silofs_avl_node *an_prev;
	const struct silofs_avl *avl = &vspm->vspm_avl;

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
	struct silofs_avl *avl     = &vspm->vspm_avl;

	silofs_avl_insert(avl, an);
}

static void
vspmap_remove_vspe(struct silofs_vspmap *vspm, struct silofs_vsp_entry *vspe)
{
	struct silofs_avl_node *an = &vspe->vspe_an;
	struct silofs_avl *avl     = &vspm->vspm_avl;

	silofs_avl_remove(avl, an);
}

static void
vspmap_evict_vspe(struct silofs_vspmap *vspm, struct silofs_vsp_entry *vspe)
{
	vspmap_remove_vspe(vspm, vspe);
	vspmap_delete_vspe(vspm, vspe);
}

static int vspmap_check_cap_add(const struct silofs_vspmap *vspm)
{
	const size_t size = vspm->vspm_avl.size;

	return (size < 1024);
}

static int vspmap_pull(struct silofs_vspmap *vspm, size_t len, off_t *out_off)
{
	struct silofs_vsp_entry *vspe;
	int err;

	err = vsplifo_pop(&vspm->vspm_lifo, len, out_off);
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

	err = vsplifo_push(&vspm->vspm_lifo, off, len);
	if (!err) {
		return 0;
	}
	err = vspmap_merge(vspm, off, len);
	if (err != -SILOFS_ENOENT) {
		return err;
	}
	err = vspmap_check_cap_add(vspm);
	if (err) {
		return err;
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

	silofs_avl_clear(&vspm->vspm_avl, &fn);
	vsplifo_clear(&vspm->vspm_lifo);
}

static void vspmap_init(struct silofs_vspmap *vspm, uint32_t objsz,
                        struct silofs_alloc *alloc)
{
	vsplifo_init(&vspm->vspm_lifo, objsz);
	silofs_avl_init(&vspm->vspm_avl, vspe_getkey, off_compare, vspm);
	vspm->vspm_alloc = alloc;
}

static void vspmap_fini(struct silofs_vspmap *vspm)
{
	vspmap_clear(vspm);
	vsplifo_fini(&vspm->vspm_lifo);
	silofs_avl_fini(&vspm->vspm_avl);
	vspm->vspm_alloc = nullptr;
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
