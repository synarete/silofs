/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#include <silofs/ps.h>


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void prange_init(struct silofs_prange *prange)
{
	silofs_psid_generate(&prange->psid);
	prange->nsegs = 1;
	prange->cur_pos = 0;
}

static void prange_fini(struct silofs_prange *prange)
{
	prange->nsegs = 0;
	prange->cur_pos = 0;
}

void silofs_prange_assign(struct silofs_prange *prange,
                          const struct silofs_prange *other)
{
	silofs_psid_assign(&prange->psid, &other->psid);
	prange->nsegs = other->nsegs;
	prange->cur_pos = other->cur_pos;
}

static void prange_cur_paddr(struct silofs_prange *prange,
                             enum silofs_ptype ptype,
                             struct silofs_paddr *out_paddr)
{
	silofs_paddr_init(out_paddr, &prange->psid, ptype,
	                  prange->cur_pos, silofs_ptype_size(ptype));
}

static void prange_advance_by(struct silofs_prange *prange,
                              const struct silofs_paddr *paddr)
{
	prange->cur_pos = off_end(paddr->off, paddr->len);
}

static void prange_carve(struct silofs_prange *prange,
                         enum silofs_ptype ptype,
                         struct silofs_paddr *out_paddr)
{
	prange_cur_paddr(prange, ptype, out_paddr);
	prange_advance_by(prange, out_paddr);
}

void silofs_prange48b_htox(struct silofs_prange48b *prange48,
                           const struct silofs_prange *prange)
{
	memset(prange48, 0, sizeof(*prange48));
	silofs_psid32b_htox(&prange48->psid, &prange->psid);
	prange48->cur = silofs_cpu_to_off(prange->cur_pos);
	prange48->nsegs = silofs_cpu_to_le32((uint32_t)prange->nsegs);
}

void silofs_prange48b_xtoh(const struct silofs_prange48b *prange48,
                           struct silofs_prange *prange)
{
	silofs_psid32b_xtoh(&prange48->psid, &prange->psid);
	prange->cur_pos = silofs_off_to_cpu(prange48->cur);
	prange->nsegs = silofs_le32_to_cpu(prange48->nsegs);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void pstate_init(struct silofs_pstate *pstate)
{
	prange_init(&pstate->data);
	prange_init(&pstate->meta);
}

static void pstate_fini(struct silofs_pstate *pstate)
{
	prange_fini(&pstate->data);
	prange_fini(&pstate->meta);
}

static struct silofs_prange *
pstate_sub(struct silofs_pstate *pstate, bool meta)
{
	return meta ? &pstate->meta : &pstate->data;
}

static void pstate_next_psu(struct silofs_pstate *pstate, bool meta,
                            struct silofs_paddr *out_paddr)
{
	struct silofs_prange *prange = pstate_sub(pstate, meta);

	silofs_assert_eq(prange->cur_pos, 0);

	prange_carve(prange, SILOFS_PTYPE_UBER, out_paddr);
}

static void pstate_next_btn(struct silofs_pstate *pstate,
                            struct silofs_paddr *out_paddr)
{
	struct silofs_prange *prange = pstate_sub(pstate, true);

	silofs_assert_gt(prange->cur_pos, 0);

	prange_carve(prange, SILOFS_PTYPE_BTNODE, out_paddr);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_pstore_init(struct silofs_pstore *pstore,
                       struct silofs_repo *repo)
{
	pstate_init(&pstore->pstate);
	pstore->repo = repo;
	pstore->alloc = repo->re.alloc;
	return silofs_bcache_init(&pstore->bcache, pstore->alloc);
}

void silofs_pstore_fini(struct silofs_pstore *pstore)
{
	silofs_bcache_drop(&pstore->bcache);
	silofs_bcache_fini(&pstore->bcache);
	pstate_fini(&pstore->pstate);
	pstore->alloc = NULL;
	pstore->repo = NULL;
}

static void pstore_bind_pni(struct silofs_pstore *pstore,
                            struct silofs_pnode_info *pni)
{
	silofs_assert_null(pni->pn_pstore);

	pni->pn_pstore = pstore;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_paddr *
pui_paddr(const struct silofs_puber_info *pui)
{
	return &pui->pu_pni.pn_paddr;
}

static int pstore_spawn_cached_pui(struct silofs_pstore *pstore,
                                   const struct silofs_paddr *paddr,
                                   struct silofs_puber_info **out_pui)
{
	struct silofs_puber_info *pui;

	pui = silofs_bcache_create_pui(&pstore->bcache, paddr);
	if (pui == NULL) {
		return -SILOFS_ENOMEM;
	}
	pstore_bind_pni(pstore, &pui->pu_pni);
	*out_pui = pui;
	return 0;
}

static int pstore_format_pseg_at(struct silofs_pstore *pstore,
                                 const struct silofs_paddr *paddr,
                                 struct silofs_puber_info **out_pui)
{
	int err;

	err = silofs_repo_create_pseg(pstore->repo, &paddr->psid);
	if (err) {
		return err;
	}
	err = pstore_spawn_cached_pui(pstore, paddr, out_pui);
	if (err) {
		return err;
	}
	return 0;
}

static int pstore_commit_puber(const struct silofs_pstore *pstore,
                               struct silofs_puber_info *pui)
{
	const struct silofs_rovec rov = {
		.rov_base = pui->pu,
		.rov_len = sizeof(*pui->pu),
	};
	int err;

	err = silofs_repo_save_pobj(pstore->repo, pui_paddr(pui), &rov);
	if (err) {
		return err;
	}
	silofs_pui_undirtify(pui);
	return 0;
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_paddr *
bti_paddr(const struct silofs_btnode_info *bti)
{
	return &bti->bn_pni.pn_paddr;
}

static int pstore_create_cached_bti(struct silofs_pstore *pstore,
                                    const struct silofs_paddr *paddr,
                                    struct silofs_btnode_info **out_bti)
{
	struct silofs_btnode_info *bti;

	bti = silofs_bcache_create_bti(&pstore->bcache, paddr);
	if (bti == NULL) {
		return -SILOFS_ENOMEM;
	}
	pstore_bind_pni(pstore, &bti->bn_pni);
	*out_bti = bti;
	return 0;
}

static int pstore_commit_btnode(const struct silofs_pstore *pstore,
                                struct silofs_btnode_info *bti)
{
	const struct silofs_rovec rov = {
		.rov_base = bti->bn,
		.rov_len = sizeof(*bti->bn),
	};
	int err;

	err = silofs_repo_save_pobj(pstore->repo, bti_paddr(bti), &rov);
	if (err) {
		return err;
	}
	silofs_bti_undirtify(bti);
	return 0;
}

static int pstore_require_pseg_of(struct silofs_pstore *pstore,
                                  const struct silofs_paddr *paddr)
{
	return silofs_repo_stage_pseg(pstore->repo, &paddr->psid);
}

static int pstore_create_btree_root_at(struct silofs_pstore *pstore,
                                       const struct silofs_paddr *paddr)
{
	struct silofs_btnode_info *bti = NULL;
	int err;

	err = pstore_create_cached_bti(pstore, paddr, &bti);
	if (err) {
		return err;
	}
	silofs_bti_mark_root(bti);
	return 0;
}

static int pstore_format_btree_root(struct silofs_pstore *pstore)
{
	struct silofs_paddr paddr;
	int err;

	pstate_next_btn(&pstore->pstate, &paddr);
	err = pstore_require_pseg_of(pstore, &paddr);
	if (err) {
		return err;
	}
	err = pstore_create_btree_root_at(pstore, &paddr);
	if (err) {
		return err;
	}
	return 0;
}

static int pstore_format_meta_pseg(struct silofs_pstore *pstore)
{
	struct silofs_paddr paddr;
	struct silofs_puber_info *pui = NULL;
	int err;

	pstate_next_psu(&pstore->pstate, true, &paddr);
	err = pstore_format_pseg_at(pstore, &paddr, &pui);
	if (err) {
		return err;
	}
	silofs_pui_mark_meta(pui);
	return 0;
}

static int pstore_format_data_pseg(struct silofs_pstore *pstore)
{
	struct silofs_paddr paddr;
	struct silofs_puber_info *pui = NULL;
	int err;

	pstate_next_psu(&pstore->pstate, false, &paddr);
	err = pstore_format_pseg_at(pstore, &paddr, &pui);
	if (err) {
		return err;
	}
	silofs_pui_mark_data(pui);
	return 0;
}

int silofs_pstore_format(struct silofs_pstore *pstore)
{
	int err;

	err = pstore_format_meta_pseg(pstore);
	if (err) {
		return err;
	}
	err = pstore_format_data_pseg(pstore);
	if (err) {
		return err;
	}
	err = pstore_format_btree_root(pstore);
	if (err) {
		return err;
	}
	err = silofs_pstore_flush_dirty(pstore);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int pstore_commit_pnode(struct silofs_pstore *pstore,
                               struct silofs_pnode_info *pni)
{
	const enum silofs_ptype ptype = pni_ptype(pni);
	int ret = -SILOFS_EINVAL;

	switch (ptype) {
	case SILOFS_PTYPE_UBER:
		ret = pstore_commit_puber(pstore, silofs_pui_from_pni(pni));
		break;
	case SILOFS_PTYPE_BTNODE:
		ret = pstore_commit_btnode(pstore, silofs_bti_from_pni(pni));
		break;
	case SILOFS_PTYPE_BTLEAF:
	case SILOFS_PTYPE_NONE:
	case SILOFS_PTYPE_DATA:
	case SILOFS_PTYPE_LAST:
	default:
		silofs_panic("bad commit: ptype=%d", (int)ptype);
		break;
	}
	return ret;
}

static struct silofs_pnode_info *
pstore_dirtyq_front(const struct silofs_pstore *pstore)
{
	return silofs_bcache_dq_front(&pstore->bcache);
}

static void pstore_drop_dirty(struct silofs_pstore *pstore)
{
	struct silofs_pnode_info *pni;

	pni = pstore_dirtyq_front(pstore);
	while (pni != NULL) {
		silofs_pni_undirtify(pni);
		pni = pstore_dirtyq_front(pstore);
	}
}

int silofs_pstore_flush_dirty(struct silofs_pstore *pstore)
{
	struct silofs_pnode_info *pni;
	int err;

	pni = pstore_dirtyq_front(pstore);
	while (pni != NULL) {
		err = pstore_commit_pnode(pstore, pni);
		if (err) {
			return err;
		}
		pni = pstore_dirtyq_front(pstore);
	}
	return 0;
}

int silofs_pstore_dropall(struct silofs_pstore *pstore)
{
	pstore_drop_dirty(pstore);
	silofs_bcache_drop(&pstore->bcache);
	return 0;
}
