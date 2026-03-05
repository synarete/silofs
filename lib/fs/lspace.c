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
#include <silofs/errors.h>
#include <silofs/panic.h>
#include <limits.h>
#include "infra.h"
#include "addr.h"
#include "bs.h"
#include "lcache.h"
#include "lsmap.h"
#include "lspace.h"
#include "exectx.h"

static void lsmap_vaddr_of(const struct silofs_vaddr *ref_vaddr,
                           struct silofs_vaddr *out_vaddr)
{
	const off_t ref_off         = ref_vaddr->off;
	const ssize_t ref_size      = silofs_vtype_ssize(ref_vaddr->vtype);
	const ssize_t ref_lseg_size = ref_size * SILOFS_SPMAP_NCHILDS;
	const ssize_t lsmap_size    = sizeof(struct silofs_lsmap);
	off_t lsmap_off, lsmap_vsp;

	lsmap_off = (ref_off / ref_lseg_size) * lsmap_size;

	silofs_assert_ge(ref_size, SILOFS_KILO);
	silofs_assert_ne(ref_vaddr->vtype, SILOFS_VTYPE_LSMAP);

	lsmap_vsp = (off_t)(ref_vaddr->vtype);
	silofs_assert_gt(lsmap_vsp, 0);
	silofs_assert_lt(lsmap_vsp, INT8_MAX);
	silofs_assert_eq(lsmap_off >> 56, 0);

	lsmap_off |= (lsmap_vsp << 56);
	silofs_vaddr_setup(out_vaddr, SILOFS_VTYPE_LSMAP, lsmap_off);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int fetch_cached_lsi(struct silofs_task_ctx *task,
                            const struct silofs_vaddr *vaddr,
                            struct silofs_lsmap_info **out_lsi)
{
	struct silofs_vnode_info *vni;

	vni = silofs_lcache_lookup_vni(task->lcache, vaddr);
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

	lsmap_vaddr_of(ref_vaddr, &vaddr);
	err = fetch_cached_lsi(task, &vaddr, out_lsi);
	if (err) {
		return err;
	}

	/* XXX YOU ARE HERE */
	return 0;
}
