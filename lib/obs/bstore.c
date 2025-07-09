/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#include "configs.h"
#include "infra.h"
#include "addr.h"
#include "repo.h"
#include "pnodes.h"
#include "pcache.h"
#include "btree.h"
#include "bstore.h"

int silofs_bstore_init(struct silofs_bstore *bstore,
                       struct silofs_pcache *pcache, struct silofs_repo *repo)
{
	const struct silofs_btree_base base = {
		.pcache = pcache,
		.repo = repo,
	};

	silofs_btree_init(&bstore->btree, &base);
	bstore->repo = repo;
	bstore->pcache = pcache;
	return 0;
}

void silofs_bstore_fini(struct silofs_bstore *bstore)
{
	silofs_btree_fini(&bstore->btree);
	bstore->repo = NULL;
	bstore->pcache = NULL;
}

static int bstore_validate_paddr(const struct silofs_bstore *bstore,
                                 const struct silofs_paddr *paddr)
{
	// XXX FIXME
	silofs_unused(bstore);
	silofs_unused(paddr);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_paddr *
cpi_paddr(const struct silofs_chkpt_info *cpi)
{
	return &cpi->cp_pni.pn_paddr;
}

static int bstore_save_chkpt(const struct silofs_bstore *bstore,
                             const struct silofs_chkpt_info *cpi)
{
	const struct silofs_rovec rov = {
		.rov_base = cpi->cp,
		.rov_len = sizeof(*cpi->cp),
	};

	return silofs_repo_save_pobj(bstore->repo, cpi_paddr(cpi), &rov);
}

static int bstore_load_chkpt(const struct silofs_bstore *bstore,
                             const struct silofs_chkpt_info *cpi)
{
	const struct silofs_rwvec rwv = {
		.rwv_base = cpi->cp,
		.rwv_len = sizeof(*cpi->cp),
	};

	return silofs_repo_load_pobj(bstore->repo, cpi_paddr(cpi), &rwv);
}

static int bstore_commit_chkpt(const struct silofs_bstore *bstore,
                               struct silofs_chkpt_info *cpi)
{
	int err;

	err = bstore_save_chkpt(bstore, cpi);
	if (err) {
		return err;
	}
	silofs_cpi_undirtify(cpi);
	return 0;
}

static int bstore_create_cached_cpi(struct silofs_bstore *bstore,
                                    const struct silofs_paddr *paddr,
                                    struct silofs_chkpt_info **out_cpi)
{
	struct silofs_chkpt_info *cpi;

	cpi = silofs_pcache_create_cpi(bstore->pcache, paddr);
	if (cpi == NULL) {
		return -SILOFS_ENOMEM;
	}
	*out_cpi = cpi;
	return 0;
}

static int bstore_require_pvseg(struct silofs_bstore *bstore, bool create,
                                const struct silofs_blobidx *blobidx)

{
	int err;

	if (create) {
		err = silofs_repo_spawn_pvseg(bstore->repo, blobidx);
	} else {
		err = silofs_repo_stage_pvseg(bstore->repo, blobidx);
	}
	return err;
}

static int bstore_require_pvseg_of(struct silofs_bstore *bstore, bool create,
                                   const struct silofs_paddr *paddr)
{
	return bstore_require_pvseg(bstore, create, &paddr->blobidx);
}

static void bstore_update_chkpt(const struct silofs_bstore *bstore,
                                struct silofs_chkpt_info *cpi)
{
	const struct silofs_btree *btree = &bstore->btree;

	silofs_cpi_set_btree_root(cpi, &btree->bt_root);
}

static int bstore_spawn_chkpt(struct silofs_bstore *bstore, bool create,
                              const struct silofs_paddr *paddr,
                              struct silofs_chkpt_info **out_cpi)
{
	int err;

	err = bstore_require_pvseg_of(bstore, create, paddr);
	if (err) {
		return err;
	}
	err = bstore_create_cached_cpi(bstore, paddr, out_cpi);
	if (err) {
		return err;
	}
	bstore_update_chkpt(bstore, *out_cpi);
	return 0;
}

static void bstore_evict_cached_cpi(struct silofs_bstore *bstore,
                                    struct silofs_chkpt_info *cpi)
{
	silofs_pcache_evict_cpi(bstore->pcache, cpi);
}

static int bstore_lookup_cached_chkpt(struct silofs_bstore *bstore,
                                      const struct silofs_paddr *paddr,
                                      struct silofs_chkpt_info **out_cpi)
{
	*out_cpi = silofs_pcache_lookup_cpi(bstore->pcache, paddr);
	return (*out_cpi == NULL) ? -SILOFS_ENOENT : 0;
}

static int bstore_stage_chkpt(struct silofs_bstore *bstore,
                              const struct silofs_paddr *paddr,
                              struct silofs_chkpt_info **out_cpi)
{
	struct silofs_chkpt_info *cpi = NULL;
	int err;

	err = bstore_lookup_cached_chkpt(bstore, paddr, out_cpi);
	if (!err) {
		return 0; /* cache hit */
	}
	err = bstore_validate_paddr(bstore, paddr);
	if (err) {
		return err;
	}
	err = bstore_require_pvseg_of(bstore, false, paddr);
	if (err) {
		return err;
	}
	err = bstore_create_cached_cpi(bstore, paddr, &cpi);
	if (err) {
		return err;
	}
	err = bstore_load_chkpt(bstore, cpi);
	if (err) {
		bstore_evict_cached_cpi(bstore, cpi);
		return err;
	}
	*out_cpi = cpi;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_paddr *
bni_paddr(const struct silofs_btnode_info *bni)
{
	return &bni->bn_pni.pn_paddr;
}

static int bstore_save_btnode(const struct silofs_bstore *bstore,
                              const struct silofs_btnode_info *bni)
{
	const struct silofs_rovec rov = {
		.rov_base = bni->bn,
		.rov_len = sizeof(*bni->bn),
	};

	return silofs_repo_save_pobj(bstore->repo, bni_paddr(bni), &rov);
}

static int bstore_commit_btnode(const struct silofs_bstore *bstore,
                                struct silofs_btnode_info *bni)
{
	int err;

	err = bstore_save_btnode(bstore, bni);
	if (err) {
		return err;
	}
	silofs_bni_undirtify(bni);
	return 0;
}

static int bstore_create_cached_bni(struct silofs_bstore *bstore,
                                    const struct silofs_paddr *paddr,
                                    struct silofs_btnode_info **out_bni)
{
	struct silofs_btnode_info *bni;

	bni = silofs_pcache_create_bni(bstore->pcache, paddr);
	if (bni == NULL) {
		return -SILOFS_ENOMEM;
	}
	*out_bni = bni;
	return 0;
}

static int bstore_spawn_btnode(struct silofs_bstore *bstore, bool create,
                               const struct silofs_paddr *paddr,
                               struct silofs_btnode_info **out_bni)
{
	int err;

	silofs_assert_eq(paddr->ptype, SILOFS_PTYPE_BTNODE);

	err = bstore_require_pvseg_of(bstore, create, paddr);
	if (err) {
		return err;
	}
	err = bstore_create_cached_bni(bstore, paddr, out_bni);
	if (err) {
		return err;
	}
	silofs_bni_dirtify(*out_bni);
	return 0;
}

static int bstore_create_btroot_at(struct silofs_bstore *bstore,
                                   const struct silofs_paddr *paddr)
{
	struct silofs_btnode_info *bni = NULL;
	int err;

	err = bstore_spawn_btnode(bstore, false, paddr, &bni);
	if (err) {
		return err;
	}
	silofs_bni_mark_root(bni);
	return 0;
}

static int bstore_spawn_btroot(struct silofs_bstore *bstore)
{
	struct silofs_paddr paddr;
	int err;

	// XXX FIXME
	silofs_paddr_reset(&paddr);

	err = bstore_create_btroot_at(bstore, &paddr);
	if (err) {
		return err;
	}

	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int bstore_spawn_next_chkpt(struct silofs_bstore *bstore)
{
	struct silofs_paddr paddr;
	struct silofs_chkpt_info *cpi = NULL;

	// XXX FIXME
	silofs_paddr_reset(&paddr);

	return bstore_spawn_chkpt(bstore, paddr.off == 0, &paddr, &cpi);
}

int silofs_bstore_format(struct silofs_bstore *bstore)
{
	int err;

	err = bstore_spawn_next_chkpt(bstore);
	if (err) {
		return err;
	}
	err = bstore_spawn_btroot(bstore);
	if (err) {
		return err;
	}
	err = bstore_spawn_next_chkpt(bstore);
	if (err) {
		return err;
	}
	err = silofs_bstore_flush_dirty(bstore);
	if (err) {
		return err;
	}
	return 0;
}

static int bstore_update_btree_root_by(struct silofs_bstore *bstore,
                                       const struct silofs_chkpt_info *cpi)
{
	struct silofs_paddr btree_root;

	silofs_cpi_btree_root(cpi, &btree_root);
	if (btree_root.ptype != SILOFS_PTYPE_BTNODE) {
		return -SILOFS_EFSCORRUPTED;
	}
	(void)bstore;
	return 0;
}

static int bstore_stage_last_chkpt(struct silofs_bstore *bstore)
{
	struct silofs_paddr paddr;
	struct silofs_chkpt_info *cpi = NULL;
	int err;

	// XXX FIXME
	silofs_paddr_reset(&paddr);

	err = bstore_stage_chkpt(bstore, &paddr, &cpi);
	if (err) {
		return err;
	}
	err = bstore_update_btree_root_by(bstore, cpi);
	if (err) {
		return err;
	}
	return 0;
}

static int bstore_reload_btree_root(struct silofs_bstore *bstore)
{
	/* XXX YOU ARE HERE */
	silofs_unused(bstore);

	return 0;
}

int silofs_bstore_reload(struct silofs_bstore *bstore)
{
	int err;

	err = bstore_stage_last_chkpt(bstore);
	if (err) {
		return err;
	}
	err = bstore_reload_btree_root(bstore);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_bstore_close(struct silofs_bstore *bstore)
{
	int err;

	err = silofs_bstore_flush_dirty(bstore);
	if (err) {
		return err;
	}
	silofs_pcache_drop(bstore->pcache);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int bstore_commit_pnode(struct silofs_bstore *bstore,
                               struct silofs_pnode_info *pni)
{
	const enum silofs_ptype ptype = silofs_pni_ptype(pni);
	int ret = -SILOFS_EINVAL;

	switch (ptype) {
	case SILOFS_PTYPE_CHKPT:
		ret = bstore_commit_chkpt(bstore, silofs_cpi_from_pni(pni));
		break;
	case SILOFS_PTYPE_BTNODE:
		ret = bstore_commit_btnode(bstore, silofs_bni_from_pni(pni));
		break;
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
bstore_dirtyq_front(const struct silofs_bstore *bstore)
{
	return silofs_pcache_dq_front(bstore->pcache);
}

static void bstore_drop_dirty(struct silofs_bstore *bstore)
{
	struct silofs_pnode_info *pni;

	pni = bstore_dirtyq_front(bstore);
	while (pni != NULL) {
		silofs_pni_undirtify(pni);
		pni = bstore_dirtyq_front(bstore);
	}
}

int silofs_bstore_flush_dirty(struct silofs_bstore *bstore)
{
	struct silofs_pnode_info *pni;
	int err;

	pni = bstore_dirtyq_front(bstore);
	while (pni != NULL) {
		err = bstore_commit_pnode(bstore, pni);
		if (err) {
			return err;
		}
		pni = bstore_dirtyq_front(bstore);
	}
	return 0;
}

int silofs_bstore_dropall(struct silofs_bstore *bstore)
{
	bstore_drop_dirty(bstore);
	silofs_pcache_drop(bstore->pcache);
	return 0;
}
