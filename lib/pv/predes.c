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
#include <silofs/types.h>
#include <silofs/nodes.h>
#include <silofs/pv.h>

static const struct silofs_paddr *paddr_of(const struct silofs_dq_elem *dqe)
{
	const struct silofs_pnode_info *pni = silofs_pni_from_dqe(dqe);

	return silofs_pni_paddr(pni);
}

static int compare_pnodes(const struct silofs_dq_elem *dqe1,
                          const struct silofs_dq_elem *dqe2)
{
	const struct silofs_paddr *paddr1 = paddr_of(dqe1);
	const struct silofs_paddr *paddr2 = paddr_of(dqe2);
	long cmp;

	cmp = silofs_paddr_compare(paddr1, paddr2);
	return (cmp < 0) ? -1 : ((cmp > 0) ? 1 : 0);
}

int silofs_prepare_destageq(const struct silofs_pexec_ctx *pexec,
                            struct silofs_destageq *dsq)
{
	const struct silofs_dirtyq *drq = &pexec->pcache->pc_dirtyq;

	silofs_destageq_populate(dsq, drq);
	silofs_destageq_sort(dsq, compare_pnodes);
	return 0;
}

void silofs_cleanup_destageq(const struct silofs_pexec_ctx *pexec,
                             struct silofs_destageq *dsq, bool cleardirty)
{
	silofs_destageq_depopulate(dsq, cleardirty);
	silofs_unused(pexec);
}
