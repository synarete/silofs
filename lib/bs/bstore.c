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
#include "pnode.h"
#include "pcache.h"
#include "bdesc.h"
#include "btnode.h"
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
bdi_paddr(const struct silofs_bdesc_info *bdi)
{
	return &bdi->bd_pni.pn_paddr;
}

static int bstore_save_bdesc(const struct silofs_bstore *bstore,
                             const struct silofs_bdesc_info *bdi)
{
	const struct silofs_rovec rov = {
		.rov_base = bdi->bd,
		.rov_len = sizeof(*bdi->bd),
	};

	return silofs_repo_save_pobj(bstore->repo, bdi_paddr(bdi), &rov);
}

static int bstore_load_bdesc(const struct silofs_bstore *bstore,
                             const struct silofs_bdesc_info *bdi)
{
	const struct silofs_rwvec rwv = {
		.rwv_base = bdi->bd,
		.rwv_len = sizeof(*bdi->bd),
	};

	return silofs_repo_load_pobj(bstore->repo, bdi_paddr(bdi), &rwv);
}

static int bstore_commit_bdesc(const struct silofs_bstore *bstore,
                               struct silofs_bdesc_info *bdi)
{
	int err;

	err = bstore_save_bdesc(bstore, bdi);
	if (err) {
		return err;
	}
	silofs_bdi_undirtify(bdi);
	return 0;
}

static int bstore_create_cached_bdi(struct silofs_bstore *bstore,
                                    const struct silofs_paddr *paddr,
                                    struct silofs_bdesc_info **out_bdi)
{
	struct silofs_bdesc_info *bdi;

	bdi = silofs_pcache_create_bdi(bstore->pcache, paddr);
	if (bdi == NULL) {
		return -SILOFS_ENOMEM;
	}
	*out_bdi = bdi;
	return 0;
}

static int bstore_require_blob(struct silofs_bstore *bstore, bool create,
                               const struct silofs_blobid *blobid)

{
	int err;

	if (create) {
		err = silofs_repo_spawn_blob(bstore->repo, blobid);
	} else {
		err = silofs_repo_stage_blob(bstore->repo, blobid);
	}
	return err;
}

static int bstore_require_blob_of(struct silofs_bstore *bstore, bool create,
                                  const struct silofs_paddr *paddr)
{
	return bstore_require_blob(bstore, create, &paddr->blobid);
}

static void bstore_update_bdesc(const struct silofs_bstore *bstore,
                                struct silofs_bdesc_info *bdi)
{
	const struct silofs_btree *btree = &bstore->btree;

	// XXX
	//silofs_bdi_set_btree_root(bdi, &btree->bt_root);
	silofs_unused(btree);
	silofs_unused(bdi);
}

static int bstore_spawn_bdesc(struct silofs_bstore *bstore, bool create,
                              const struct silofs_paddr *paddr,
                              struct silofs_bdesc_info **out_bdi)
{
	int err;

	err = bstore_require_blob_of(bstore, create, paddr);
	if (err) {
		return err;
	}
	err = bstore_create_cached_bdi(bstore, paddr, out_bdi);
	if (err) {
		return err;
	}
	bstore_update_bdesc(bstore, *out_bdi);
	return 0;
}

static void bstore_evict_cached_bdi(struct silofs_bstore *bstore,
                                    struct silofs_bdesc_info *bdi)
{
	silofs_pcache_evict_bdi(bstore->pcache, bdi);
}

static int bstore_lookup_cached_bdesc(struct silofs_bstore *bstore,
                                      const struct silofs_paddr *paddr,
                                      struct silofs_bdesc_info **out_bdi)
{
	*out_bdi = silofs_pcache_lookup_bdi(bstore->pcache, paddr);
	return (*out_bdi == NULL) ? -SILOFS_ENOENT : 0;
}

static int bstore_stage_bdesc(struct silofs_bstore *bstore,
                              const struct silofs_paddr *paddr,
                              struct silofs_bdesc_info **out_bdi)
{
	struct silofs_bdesc_info *bdi = NULL;
	int err;

	err = bstore_lookup_cached_bdesc(bstore, paddr, out_bdi);
	if (!err) {
		return 0; /* cache hit */
	}
	err = bstore_validate_paddr(bstore, paddr);
	if (err) {
		return err;
	}
	err = bstore_require_blob_of(bstore, false, paddr);
	if (err) {
		return err;
	}
	err = bstore_create_cached_bdi(bstore, paddr, &bdi);
	if (err) {
		return err;
	}
	err = bstore_load_bdesc(bstore, bdi);
	if (err) {
		bstore_evict_cached_bdi(bstore, bdi);
		return err;
	}
	*out_bdi = bdi;
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

	silofs_assert_eq(paddr->mtype, SILOFS_MTYPE_BTNODE);

	err = bstore_require_blob_of(bstore, create, paddr);
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

static int bstore_spawn_next_bdesc(struct silofs_bstore *bstore)
{
	struct silofs_paddr paddr;
	struct silofs_bdesc_info *bdi = NULL;

	// XXX FIXME
	silofs_paddr_reset(&paddr);

	return bstore_spawn_bdesc(bstore, paddr.off == 0, &paddr, &bdi);
}

int silofs_bstore_format(struct silofs_bstore *bstore)
{
	int err;

	err = bstore_spawn_next_bdesc(bstore);
	if (err) {
		return err;
	}
	err = bstore_spawn_btroot(bstore);
	if (err) {
		return err;
	}
	err = bstore_spawn_next_bdesc(bstore);
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
                                       const struct silofs_bdesc_info *bdi)
{
	// XXX
	silofs_unused(bstore);
	silofs_unused(bdi);

	return 0;
}

static int bstore_stage_last_bdesc(struct silofs_bstore *bstore)
{
	struct silofs_paddr paddr;
	struct silofs_bdesc_info *bdi = NULL;
	int err;

	// XXX FIXME
	silofs_paddr_reset(&paddr);

	err = bstore_stage_bdesc(bstore, &paddr, &bdi);
	if (err) {
		return err;
	}
	err = bstore_update_btree_root_by(bstore, bdi);
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

	err = bstore_stage_last_bdesc(bstore);
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
	const enum silofs_mtype mtype = silofs_pni_mtype(pni);
	int ret = -SILOFS_EINVAL;

	switch (mtype) {
	case SILOFS_MTYPE_BLDESC:
		ret = bstore_commit_bdesc(bstore, silofs_bdi_from_pni(pni));
		break;
	case SILOFS_MTYPE_BTNODE:
		ret = bstore_commit_btnode(bstore, silofs_bni_from_pni(pni));
		break;
	case SILOFS_MTYPE_NONE:
	case SILOFS_MTYPE_BOOTREC:
	case SILOFS_MTYPE_SUPER:
	case SILOFS_MTYPE_SPNODE:
	case SILOFS_MTYPE_SPLEAF:
	case SILOFS_MTYPE_LSMAP:
	case SILOFS_MTYPE_INODE:
	case SILOFS_MTYPE_XANODE:
	case SILOFS_MTYPE_DTNODE:
	case SILOFS_MTYPE_SYMVAL:
	case SILOFS_MTYPE_FTNODE:
	case SILOFS_MTYPE_DATA1K:
	case SILOFS_MTYPE_DATA4K:
	case SILOFS_MTYPE_DATABK:
	case SILOFS_MTYPE_LAST:
	default:
		silofs_panic("bad commit: mtype=%d", (int)mtype);
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
