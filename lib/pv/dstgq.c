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

static struct silofs_pnode_info *
dsq_lh_to_mut_pni(struct silofs_list_head *dsq_lh)
{
	return silofs_mut_container_of(dsq_lh, struct silofs_pnode_info,
	                               pn_dsq_lh);
}

static const struct silofs_pnode_info *
dsq_lh_to_pni(const struct silofs_list_head *dsq_lh)
{
	const struct silofs_pnode_info *pni = nullptr;

	if (dsq_lh != nullptr) {
		pni = silofs_container_of(dsq_lh, struct silofs_pnode_info,
		                          pn_dsq_lh);
	}
	return pni;
}

static const struct silofs_paddr *
paddr_of_dsq_lh(const struct silofs_list_head *dsq_lh)
{
	const struct silofs_pnode_info *pni = dsq_lh_to_pni(dsq_lh);

	return (pni != nullptr) ? silofs_pni_paddr(pni) : nullptr;
}

static struct silofs_pnode_info *
first_in_dirtyq(const struct silofs_pexec_ctx *pexec)
{
	struct silofs_dq_elem *dqe;

	dqe = silofs_dirtyq_front(&pexec->pcache->pc_dirtyq);
	return silofs_pni_from_dqe(dqe);
}

static struct silofs_pnode_info *
next_in_dirtyq(const struct silofs_pexec_ctx *pexec,
               const struct silofs_pnode_info *pni)
{
	const struct silofs_dq_elem *dqe = &pni->pn_hmqe.hme_dqe;
	struct silofs_dq_elem *dqe_next;

	dqe_next = silofs_dirtyq_next_of(&pexec->pcache->pc_dirtyq, dqe);
	return silofs_pni_from_dqe(dqe_next);
}

static void
fill_dstgq(const struct silofs_pexec_ctx *pexec, struct silofs_listq *dsq)
{
	struct silofs_pnode_info *pni = first_in_dirtyq(pexec);

	while (pni != nullptr) {
		silofs_listq_push_back(dsq, &pni->pn_dsq_lh);
		silofs_pni_incref(pni);
		pni = next_in_dirtyq(pexec, pni);
	}
}

static int compare_pnodes(const struct silofs_list_functor *self,
                          const struct silofs_list_head *dsq_lh1,
                          const struct silofs_list_head *dsq_lh2)
{
	const struct silofs_paddr *paddr1 = paddr_of_dsq_lh(dsq_lh1);
	const struct silofs_paddr *paddr2 = paddr_of_dsq_lh(dsq_lh2);
	long cmp;

	cmp = silofs_paddr_compare(paddr1, paddr2);
	silofs_unused(self);
	return (cmp < 0) ? -1 : ((cmp > 0) ? 1 : 0);
}

static void sort_dstgq(struct silofs_listq *dsq)
{
	const struct silofs_list_functor cmp = {
		.compare_fn = compare_pnodes,
	};

	silofs_list_sort(&dsq->ls, &cmp);
}

int silofs_popoulate_dsq(const struct silofs_pexec_ctx *pexec,
                         struct silofs_listq *dsq)
{
	fill_dstgq(pexec, dsq);
	sort_dstgq(dsq);
	return 0;
}

void silofs_cleanup_dsq(struct silofs_listq *dsq, bool cleardirty)
{
	struct silofs_list_head *dsq_lh;

	dsq_lh = silofs_listq_pop_front(dsq);
	while (dsq_lh != nullptr) {
		struct silofs_pnode_info *pni = dsq_lh_to_mut_pni(dsq_lh);

		silofs_pni_decref(pni);
		if (cleardirty) {
			silofs_pni_cleardirty(pni);
		}
		dsq_lh = silofs_listq_pop_front(dsq);
	}
}
