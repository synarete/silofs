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
#include <limits.h>

#include <silofs/errors.h>
#include <silofs/panic.h>
#include <silofs/base.h>
#include <silofs/addr.h>
#include <silofs/pv.h>
#include <silofs/fs/lcache.h>
#include <silofs/fs/lsmap.h>
#include <silofs/fs/lspace.h>
#include <silofs/run.h>

static void silofs_lsmap_vaddr_of2(const struct silofs_vaddr *ref_vaddr,
                                   struct silofs_vaddr *out_vaddr)
{
	const uint64_t lsmap_size = sizeof(struct silofs_lsmap);
	uint64_t ref_vsize, ref_vseg_size;
	uint64_t ref_voff, lsmap_off, lsmap_vsp;

	ref_voff      = (uint64_t)ref_vaddr->off;
	ref_vsize     = silofs_vtype_size(ref_vaddr->vtype);
	ref_vseg_size = ref_vsize * SILOFS_SPMAP_NCHILDS;
	lsmap_off     = (ref_voff / ref_vseg_size) * lsmap_size;

	silofs_assert_ge(ref_vsize, SILOFS_KILO);
	silofs_assert_ne(ref_vaddr->vtype, SILOFS_VTYPE_LSMAP);

	lsmap_vsp = (uint64_t)(ref_vaddr->vtype);
	silofs_assert_gt(lsmap_vsp, 0);
	silofs_assert_lt(lsmap_vsp, INT8_MAX);
	silofs_assert_eq(lsmap_off >> 56, 0);

	lsmap_off |= (lsmap_vsp << 56);
	silofs_vaddr_setup(out_vaddr, SILOFS_VTYPE_LSMAP, (off_t)lsmap_off);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int fetch_cached_lsi(struct silofs_task_ctx *task,
                            const struct silofs_vaddr *vaddr,
                            struct silofs_lsmap_info **out_lsi)
{
	struct silofs_vnode_info *vni;

	vni = silofs_lcache_lookup_vnode(task->lcache, vaddr);
	if (vni == nullptr) {
		return -SILOFS_ENOENT;
	}
	*out_lsi = silofs_lsi_from_vni(vni);
	return 0;
}

int silofs_require_lsmap_of(struct silofs_task_ctx *task,
                            const struct silofs_vaddr *ref_vaddr,
                            struct silofs_lsmap_info **out_lsi)
{
	struct silofs_vaddr vaddr;
	int err;

	silofs_lsmap_vaddr_of2(ref_vaddr, &vaddr);
	err = fetch_cached_lsi(task, &vaddr, out_lsi);
	if (err) {
		return err;
	}

	/* XXX YOU ARE HERE */
	return 0;
}
