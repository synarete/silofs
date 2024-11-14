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


static bool paddr_is_uber(const struct silofs_paddr *paddr)
{
	return paddr->ptype == SILOFS_PTYPE_UBER;
}

static bool paddr_is_data(const struct silofs_paddr *paddr)
{
	return paddr->ptype == SILOFS_PTYPE_DATA;
}

static void paddr_of_uber(const struct silofs_psid *psid,
                          struct silofs_paddr *out_paddr)
{
	silofs_paddr_init(out_paddr, psid, SILOFS_PTYPE_UBER,
	                  0, SILOFS_PSEG_UBER_SIZE);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void prange_init(struct silofs_prange *prange, bool data)
{
	silofs_psid_generate(&prange->psid);
	prange->nsegs = 1;
	prange->cur_pos = 0;
	prange->data = data;
}

static void prange_fini(struct silofs_prange *prange)
{
	prange->nsegs = 0;
	prange->cur_pos = 0;
}

static void prange_assign(struct silofs_prange *prange,
                          const struct silofs_prange *other)
{
	silofs_psid_assign(&prange->psid, &other->psid);
	prange->nsegs = other->nsegs;
	prange->cur_pos = other->cur_pos;
	prange->data = other->data;
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

static bool prange_has_pvid(const struct silofs_prange *prange,
                            const struct silofs_pvid *pvid)
{
	return silofs_pvid_isequal(&prange->psid.pvid, pvid);
}

static bool prange_has_index(const struct silofs_prange *prange, uint32_t idx)
{
	const uint32_t idx_beg = prange->psid.index;
	const uint32_t idx_end = idx_beg + prange->nsegs;

	return (idx >= idx_beg) && (idx < idx_end);
}

static bool prange_has_paddr(const struct silofs_prange *prange,
                             const struct silofs_paddr *paddr)
{
	if (!prange_has_pvid(prange, &paddr->psid.pvid)) {
		return false;
	}
	if (!prange_has_index(prange, paddr->psid.index)) {
		return false;
	}
	if (prange->data != silofs_paddr_isdata(paddr)) {
		return false;
	}
	return true;
}

static void prange64b_htox(struct silofs_prange64b *prange64,
                           const struct silofs_prange *prange)
{
	memset(prange64, 0, sizeof(*prange64));
	silofs_psid32b_htox(&prange64->psid, &prange->psid);
	prange64->cur = silofs_cpu_to_off(prange->cur_pos);
	prange64->nsegs = silofs_cpu_to_le32((uint32_t)prange->nsegs);
}

static void prange64b_xtoh(const struct silofs_prange64b *prange64,
                           struct silofs_prange *prange)
{
	silofs_psid32b_xtoh(&prange64->psid, &prange->psid);
	prange->cur_pos = silofs_off_to_cpu(prange64->cur);
	prange->nsegs = silofs_le32_to_cpu(prange64->nsegs);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void pstate_init(struct silofs_pstate *pstate)
{
	prange_init(&pstate->data, true);
	prange_init(&pstate->meta, false);
}

static void pstate_fini(struct silofs_pstate *pstate)
{
	prange_fini(&pstate->data);
	prange_fini(&pstate->meta);
}

void silofs_pstate_assign(struct silofs_pstate *pstate,
                          const struct silofs_pstate *other)
{
	prange_assign(&pstate->meta, &other->meta);
	prange_assign(&pstate->data, &other->data);
}

static struct silofs_prange *
pstate_sub(struct silofs_pstate *pstate, bool meta)
{
	return meta ? &pstate->meta : &pstate->data;
}

static const struct silofs_prange *
pstate_sub2(const struct silofs_pstate *pstate, bool meta)
{
	return meta ? &pstate->meta : &pstate->data;
}

static void pstate_next_uber(struct silofs_pstate *pstate, bool meta,
                             struct silofs_paddr *out_paddr)
{
	struct silofs_prange *prange = pstate_sub(pstate, meta);

	silofs_assert_eq(prange->cur_pos, 0);

	prange_carve(prange, SILOFS_PTYPE_UBER, out_paddr);
}

static void pstate_next_btnode(struct silofs_pstate *pstate,
                               struct silofs_paddr *out_paddr)
{
	struct silofs_prange *prange = pstate_sub(pstate, true);

	silofs_assert_gt(prange->cur_pos, 0);

	prange_carve(prange, SILOFS_PTYPE_BTNODE, out_paddr);
}

static bool pstate_has_paddr(const struct silofs_pstate *pstate,
                             const struct silofs_paddr *paddr)
{
	bool ret;

	if (paddr_is_uber(paddr)) {
		ret = prange_has_paddr(&pstate->data, paddr) ||
		      prange_has_paddr(&pstate->meta, paddr);
	} else if (paddr_is_data(paddr)) {
		ret = prange_has_paddr(&pstate->data, paddr);
	} else {
		ret = prange_has_paddr(&pstate->meta, paddr);
	}
	return ret;
}

void silofs_pstate128b_htox(struct silofs_pstate128b *pstate128,
                            const struct silofs_pstate *pstate)
{
	prange64b_htox(&pstate128->meta, &pstate->meta);
	prange64b_htox(&pstate128->data, &pstate->data);
}

void silofs_pstate128b_xtoh(const struct silofs_pstate128b *pstate128,
                            struct silofs_pstate *pstate)
{
	prange64b_xtoh(&pstate128->meta, &pstate->meta);
	prange64b_xtoh(&pstate128->data, &pstate->data);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_pstore_init(struct silofs_pstore *pstore,
                       struct silofs_repo *repo)
{
	pstate_init(&pstore->pstate);
	pstore->repo = repo;
	return silofs_bcache_init(&pstore->bcache, repo->re.alloc);
}

void silofs_pstore_fini(struct silofs_pstore *pstore)
{
	silofs_bcache_drop(&pstore->bcache);
	silofs_bcache_fini(&pstore->bcache);
	pstate_fini(&pstore->pstate);
	pstore->repo = NULL;
}

static void pstore_bind_pni(struct silofs_pstore *pstore,
                            struct silofs_pnode_info *pni)
{
	silofs_assert_null(pni->pn_pstore);

	pni->pn_pstore = pstore;
}

static int pstore_validate_paddr(const struct silofs_pstore *pstore,
                                 const struct silofs_paddr *paddr)
{
	return pstate_has_paddr(&pstore->pstate, paddr) ? 0 : -SILOFS_EINVAL;
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_paddr *
ubi_paddr(const struct silofs_uber_info *ubi)
{
	return &ubi->ub_pni.pn_paddr;
}

static int pstore_save_uber(const struct silofs_pstore *pstore,
                            const struct silofs_uber_info *ubi)
{
	const struct silofs_rovec rov = {
		.rov_base = ubi->ub,
		.rov_len = sizeof(*ubi->ub),
	};

	return silofs_repo_save_pobj(pstore->repo, ubi_paddr(ubi), &rov);
}

static int pstore_load_uber(const struct silofs_pstore *pstore,
                            const struct silofs_uber_info *ubi)
{
	const struct silofs_rwvec rwv = {
		.rwv_base = ubi->ub,
		.rwv_len = sizeof(*ubi->ub),
	};

	return silofs_repo_load_pobj(pstore->repo, ubi_paddr(ubi), &rwv);
}


static int pstore_commit_uber(const struct silofs_pstore *pstore,
                              struct silofs_uber_info *ubi)
{
	int err;

	err = pstore_save_uber(pstore, ubi);
	if (err) {
		return err;
	}
	silofs_ubi_undirtify(ubi);
	return 0;
}

static int pstore_stage_uber(const struct silofs_pstore *pstore,
                             const struct silofs_uber_info *ubi)
{
	return pstore_load_uber(pstore, ubi);
}

static int pstore_create_cached_ubi(struct silofs_pstore *pstore,
                                    const struct silofs_paddr *paddr,
                                    struct silofs_uber_info **out_ubi)
{
	struct silofs_uber_info *ubi;

	ubi = silofs_bcache_create_ubi(&pstore->bcache, paddr);
	if (ubi == NULL) {
		return -SILOFS_ENOMEM;
	}
	pstore_bind_pni(pstore, &ubi->ub_pni);
	*out_ubi = ubi;
	return 0;
}

static int pstore_format_pseg_of(struct silofs_pstore *pstore,
                                 const struct silofs_paddr *paddr,
                                 struct silofs_uber_info **out_ubi)
{
	int err;

	err = silofs_repo_create_pseg(pstore->repo, &paddr->psid);
	if (err) {
		return err;
	}
	err = pstore_create_cached_ubi(pstore, paddr, out_ubi);
	if (err) {
		return err;
	}
	return 0;
}

static void pstore_evict_cached_ubi(struct silofs_pstore *pstore,
                                    struct silofs_uber_info *ubi)
{
	silofs_bcache_evict_ubi(&pstore->bcache, ubi);
}

static int pstore_stage_uber_at(struct silofs_pstore *pstore,
                                const struct silofs_paddr *paddr,
                                struct silofs_uber_info **out_ubi)
{
	struct silofs_uber_info *ubi = NULL;
	int err;

	err = pstore_validate_paddr(pstore, paddr);
	if (err) {
		return err;
	}
	err = pstore_create_cached_ubi(pstore, paddr, &ubi);
	if (err) {
		return err;
	}
	err = pstore_stage_uber(pstore, ubi);
	if (err) {
		pstore_evict_cached_ubi(pstore, ubi);
		return err;
	}
	*out_ubi = ubi;
	return 0;
}

static int pstore_stage_uber_of(struct silofs_pstore *pstore,
                                const struct silofs_psid *psid,
                                struct silofs_uber_info **out_ubi)
{
	struct silofs_paddr paddr;

	paddr_of_uber(psid, &paddr);
	return pstore_stage_uber_at(pstore, &paddr, out_ubi);
}

static int pstore_stage_pseg_of(struct silofs_pstore *pstore,
                                const struct silofs_psid *psid)
{
	struct silofs_uber_info *ubi = NULL;
	int err;

	err = silofs_repo_stage_pseg(pstore->repo, psid);
	if (err) {
		return err;
	}
	err = pstore_stage_uber_of(pstore, psid, &ubi);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_paddr *
bti_paddr(const struct silofs_btnode_info *bti)
{
	return &bti->bn_pni.pn_paddr;
}

static int pstore_save_btnode(const struct silofs_pstore *pstore,
                              const struct silofs_btnode_info *bti)
{
	const struct silofs_rovec rov = {
		.rov_base = bti->bn,
		.rov_len = sizeof(*bti->bn),
	};

	return silofs_repo_save_pobj(pstore->repo, bti_paddr(bti), &rov);
}

#if 0
static int pstore_load_btnode(const struct silofs_pstore *pstore,
                              const struct silofs_btnode_info *bti)
{
	const struct silofs_rwvec rwv = {
		.rwv_base = bti->bn,
		.rwv_len = sizeof(*bti->bn),
	};

	return silofs_repo_load_pobj(pstore->repo, bti_paddr(bti), &rwv);
}
#endif

static int pstore_commit_btnode(const struct silofs_pstore *pstore,
                                struct silofs_btnode_info *bti)
{
	int err;

	err = pstore_save_btnode(pstore, bti);
	if (err) {
		return err;
	}
	silofs_bti_undirtify(bti);
	return 0;
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

	pstate_next_btnode(&pstore->pstate, &paddr);
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
	struct silofs_uber_info *ubi = NULL;
	int err;

	pstate_next_uber(&pstore->pstate, true, &paddr);
	err = pstore_format_pseg_of(pstore, &paddr, &ubi);
	if (err) {
		return err;
	}
	silofs_ubi_mark_meta(ubi);
	return 0;
}

static int pstore_format_data_pseg(struct silofs_pstore *pstore)
{
	struct silofs_paddr paddr;
	struct silofs_uber_info *ubi = NULL;
	int err;

	pstate_next_uber(&pstore->pstate, false, &paddr);
	err = pstore_format_pseg_of(pstore, &paddr, &ubi);
	if (err) {
		return err;
	}
	silofs_ubi_mark_data(ubi);
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

static int pstore_stage_meta_pseg(struct silofs_pstore *pstore)
{
	const struct silofs_prange *prange;

	prange = pstate_sub2(&pstore->pstate, true);
	return pstore_stage_pseg_of(pstore, &prange->psid);
}

static int pstore_stage_data_pseg(struct silofs_pstore *pstore)
{
	const struct silofs_prange *prange;

	prange = pstate_sub2(&pstore->pstate, false);
	return pstore_stage_pseg_of(pstore, &prange->psid);
}

static int pstore_assign_pstate(struct silofs_pstore *pstore,
                                const struct silofs_pstate *pstate)
{
	/* TODO: check validity */
	silofs_pstate_assign(&pstore->pstate, pstate);
	return 0;
}

int silofs_pstore_open(struct silofs_pstore *pstore,
                       const struct silofs_pstate *pstate)
{
	int err;

	err = pstore_assign_pstate(pstore, pstate);
	if (err) {
		return err;
	}
	err = pstore_stage_meta_pseg(pstore);
	if (err) {
		return err;
	}
	err = pstore_stage_data_pseg(pstore);
	if (err) {
		return err;
	}

	/* TODO: Complete me */
	return 0;
}

int silofs_pstore_close(struct silofs_pstore *pstore)
{
	int err;

	err = silofs_pstore_flush_dirty(pstore);
	if (err) {
		return err;
	}
	silofs_bcache_drop(&pstore->bcache);
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
		ret = pstore_commit_uber(pstore, silofs_ubi_from_pni(pni));
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
