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

	silofs_vaddr_of_lsmap2(ref_vaddr, &vaddr);
	err = fetch_cached_lsi(task, &vaddr, out_lsi);
	if (err) {
		return err;
	}

	/* XXX YOU ARE HERE */
	return 0;
}
