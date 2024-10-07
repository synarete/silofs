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


static void pstate_init(struct silofs_pstate *pstate)
{
	silofs_psid_setup(&pstate->beg);
	silofs_psid_assign(&pstate->cur, &pstate->beg);
	pstate->cur_pos = 0;
}

static void pstate_fini(struct silofs_pstate *pstate)
{
	silofs_psid_reset(&pstate->beg);
	silofs_psid_reset(&pstate->cur);
	pstate->cur_pos = -1;
}

static void pstate_next_btn(struct silofs_pstate *pstate,
                            struct silofs_paddr *out_paddr)
{
	silofs_paddr_init_btn(out_paddr, &pstate->cur, pstate->cur_pos);
	pstate->cur_pos = off_end(out_paddr->off, out_paddr->len);
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
	*out_bti = silofs_bcache_create_bti(&pstore->bcache, paddr);
	if (*out_bti == NULL) {
		return -SILOFS_ENOMEM;
	}
	(*out_bti)->bn_pni.pn_pstore = pstore;
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

static int pstore_require_pseg(const struct silofs_pstore *pstore,
                               const struct silofs_psid *psid)
{
	int err;

	err = silofs_repo_stage_pseg(pstore->repo, psid);
	if (err == -SILOFS_ENOENT) {
		err = silofs_repo_create_pseg(pstore->repo, psid);
	}
	return err;
}

static int pstore_require_pseg_of(const struct silofs_pstore *pstore,
                                  const struct silofs_paddr *paddr)
{
	return pstore_require_pseg(pstore, &paddr->psid);
}

static int pstore_commit_bnode(struct silofs_pstore *pstore,
                               struct silofs_pnode_info *bni)
{
	const enum silofs_ptype ptype = pni_ptype(bni);
	int ret = -SILOFS_EINVAL;

	switch (ptype) {
	case SILOFS_PTYPE_BTNODE:
		ret = pstore_commit_btnode(pstore, silofs_bti_from_pni(bni));
		break;
	case SILOFS_PTYPE_BTLEAF:
	case SILOFS_PTYPE_NONE:
	case SILOFS_PTYPE_UBER:
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

int silofs_pstore_format_btree(struct silofs_pstore *pstore)
{
	int err;

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

static void pstore_drop_dirty(struct silofs_pstore *pstore)
{
	struct silofs_pnode_info *pni;

	pni = pstore_dirtyq_front(pstore);
	while (pni != NULL) {
		pni_undirtify(pni);
		pni = pstore_dirtyq_front(pstore);
	}
}

int silofs_pstore_flush_dirty(struct silofs_pstore *pstore)
{
	struct silofs_pnode_info *bni;
	int err;

	bni = pstore_dirtyq_front(pstore);
	while (bni != NULL) {
		err = pstore_commit_bnode(pstore, bni);
		if (err) {
			return err;
		}
		bni = pstore_dirtyq_front(pstore);
	}
	return 0;
}

int silofs_pstore_dropall(struct silofs_pstore *pstore)
{
	pstore_drop_dirty(pstore);
	silofs_bcache_drop(&pstore->bcache);
	return 0;
}
