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

static struct silofs_pnode_info *pni_of(const struct silofs_dq_elem *dqe)
{
	return silofs_pni_from_dqe(dqe);
}

static const struct silofs_paddr *paddr_of(const struct silofs_dq_elem *dqe)
{
	const struct silofs_pnode_info *pni = pni_of(dqe);

	return silofs_pni_paddr(pni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int
stage_uber(struct silofs_pexec_ctx *pexec, const struct silofs_pnptr *pnptr,
           struct silofs_pnode_info **out_pni)
{
	struct silofs_uber_info *ubi = nullptr;
	int err;

	err = silofs_stage_uber(pexec, pnptr, &ubi);
	if (err) {
		return err;
	}
	*out_pni = &ubi->ub_pni;
	return 0;
}

static int
stage_btnode(struct silofs_pexec_ctx *pexec, const struct silofs_pnptr *pnptr,
             struct silofs_pnode_info **out_pni)
{
	struct silofs_btnode_info *bti = nullptr;
	int err;

	err = silofs_stage_btnode(pexec, pnptr, &bti);
	if (err) {
		return err;
	}
	*out_pni = &bti->btn_pni;
	return 0;
}

static inline int
stage_pnode(struct silofs_pexec_ctx *pexec, const struct silofs_pnptr *pnptr,
            struct silofs_pnode_info **out_pni)
{
	const enum silofs_ptype ptype = pnptr->paddr.ptype;
	int err;

	switch (ptype) {
	case SILOFS_PTYPE_UBER:
		err = stage_uber(pexec, pnptr, out_pni);
		break;
	case SILOFS_PTYPE_BTNODE:
		err = stage_btnode(pexec, pnptr, out_pni);
		break;
	case SILOFS_PTYPE_NONE:
	case SILOFS_PTYPE_MBR:
	case SILOFS_PTYPE_BLDESC:
	case SILOFS_PTYPE_VNODE:
	case SILOFS_PTYPE_LAST:
	default:
		silofs_panic("can not stage pnode: ptype=%d", ptype);
		err = -SILOFS_EBUG;
		break;
	}
	return err;
}

static inline int stage_parent_of(struct silofs_pexec_ctx *pexec,
                                  const struct silofs_pnode_info *pni,
                                  struct silofs_pnode_info **out_pni)
{
	const struct silofs_pnptr *pnptr = silofs_pni_parent(pni);

	return stage_pnode(pexec, pnptr, out_pni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int compare_paddrs_of(const struct silofs_dq_elem *dqe1,
                             const struct silofs_dq_elem *dqe2)
{
	const struct silofs_paddr *paddr1 = paddr_of(dqe1);
	const struct silofs_paddr *paddr2 = paddr_of(dqe2);
	long cmp;

	cmp = silofs_paddr_compare(paddr1, paddr2);
	return (cmp < 0) ? -1 : ((cmp > 0) ? 1 : 0);
}

static struct silofs_alloc *alloc_of(const struct silofs_pexec_ctx *pexec)
{
	return pexec->alloc;
}

static int attach_viewx_of(struct silofs_dq_elem *dqe, const void *userp)
{
	struct silofs_pnode_info *pni = pni_of(dqe);

	return silofs_ni_attach_viewx(&pni->pn_base, alloc_of(userp));
}

static int detach_viewx_of(struct silofs_dq_elem *dqe, const void *userp)
{
	struct silofs_pnode_info *pni = pni_of(dqe);

	silofs_ni_detach_viewx(&pni->pn_base, alloc_of(userp));
	return 0;
}

static int require_viewx(const struct silofs_pexec_ctx *pexec,
                         const struct silofs_destageq *dsq)
{
	return silofs_destageq_foreach(dsq, attach_viewx_of, pexec);
}

static void cleanup_viewx(const struct silofs_pexec_ctx *pexec,
                          const struct silofs_destageq *dsq)
{
	silofs_destageq_foreach(dsq, detach_viewx_of, pexec);
}

#if 0
static int pre_destage_pnode(struct silofs_pexec_ctx *pexec,
			     struct silofs_pnode_info *pni)
{
	int err;

	if (pni->pn_base.viewx.pview != nullptr) {
		return 0;
	}
	err = silofs_ni_attach_viewx(&pni->pn_base, alloc_of(pexec));
	if (err) {
		return err;
	}

}

static int pre_destage_at(struct silofs_dq_elem *dqe, const void *userp)
{
}
#endif

int silofs_pre_destage(struct silofs_pexec_ctx *pexec,
                       struct silofs_destageq *dsq)
{
	const struct silofs_dirtyq *drq = &pexec->pcache->pc_dirtyq;
	int err;

	silofs_destageq_populate(dsq, drq);

	err = require_viewx(pexec, dsq);
	if (err) {
		goto out_err;
	}

	silofs_destageq_sort(dsq, compare_paddrs_of);
	return 0;
out_err:
	silofs_post_destage(pexec, dsq, false);
	return err;
}

static int cleardirty_of(struct silofs_dq_elem *dqe, const void *userp)
{
	struct silofs_pnode_info *pni = pni_of(dqe);

	silofs_pni_cleardirty(pni);
	silofs_unused(userp);
	return 0;
}

static void clear_dirty(const struct silofs_pexec_ctx *pexec,
                        const struct silofs_destageq *dsq)
{
	silofs_destageq_foreach(dsq, cleardirty_of, pexec);
}

void silofs_post_destage(struct silofs_pexec_ctx *pexec,
                         struct silofs_destageq *dsq, bool cleardirty)
{
	cleanup_viewx(pexec, dsq);
	if (cleardirty) {
		clear_dirty(pexec, dsq);
	}
	silofs_destageq_depopulate(dsq);
}
