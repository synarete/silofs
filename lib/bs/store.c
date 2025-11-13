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
#include <sys/stat.h>
#include "nodes.h"
#include "locos.h"
#include "uber.h"
#include "store.h"
#include "gbr.h"
#include "env.h"

struct silofs_store_ctx {
	const struct silofs_gbrs *gbrs;
	struct silofs_alloc *alloc;
	struct silofs_locos *locos;
	struct silofs_pcache *pcache;
	struct silofs_mdigest *mdigest;
	struct silofs_cipher *enc_cipher;
	struct silofs_cipher *dec_cipher;
	struct silofs_view *view;
};

static void stc_init(struct silofs_store_ctx *st_ctx, struct silofs_env *env)
{
	st_ctx->gbrs = &env->gbrs;
	st_ctx->alloc = env->base.alloc;
	st_ctx->locos = &env->base.repo->re_locos;
	st_ctx->pcache = env->base.pcache;
	st_ctx->mdigest = &env->mdigest;
	st_ctx->enc_cipher = &env->enc_cipher;
	st_ctx->dec_cipher = &env->dec_cipher;
	st_ctx->view = nullptr;
}

static int stc_init2(struct silofs_store_ctx *st_ctx, struct silofs_env *env)
{
	struct silofs_view *view = nullptr;

	stc_init(st_ctx, env);
	view = silofs_memalloc(st_ctx->alloc, sizeof(*view), 0);
	if (view == nullptr) {
		return -SILOFS_ENOENT;
	}
	st_ctx->view = view;
	return 0;
}

static void stc_fini(struct silofs_store_ctx *st_ctx)
{
	struct silofs_view *view = st_ctx->view;

	if (view != nullptr) {
		silofs_memfree(st_ctx->alloc, view, sizeof(*view), 0);
	}
}

static const struct silofs_key *
stc_main_key(const struct silofs_store_ctx *st_ctx)
{
	return &st_ctx->gbrs->fs_gbr.main_ivkey.key;
}

static int stc_require_paddr(const struct silofs_store_ctx *st_ctx,
                             const struct silofs_paddr *paddr)
{
	return silofs_locos_require_bpos(st_ctx->locos, &paddr->blobid,
	                                 paddr->pos);
}

static int stc_create_cached_ubi(const struct silofs_store_ctx *st_ctx,
                                 const struct silofs_paddr *paddr, bool spawn,
                                 struct silofs_uber_info **out_ubi)
{
	*out_ubi = silofs_create_cached_uber(st_ctx->pcache, paddr, spawn);
	return ((*out_ubi) == nullptr) ? -SILOFS_ENOMEM : 0;
}

static void stc_update_spawned_pnode(const struct silofs_store_ctx *st_ctx,
                                     const struct silofs_key *key,
                                     struct silofs_pnode_info *pni)
{
	silofs_pni_setup_ivkey(pni, st_ctx->mdigest, key);
	silofs_pni_dirtify(pni);
}

static void stc_update_spawned_uber(const struct silofs_store_ctx *st_ctx,
                                    struct silofs_uber_info *ubi)
{
	stc_update_spawned_pnode(st_ctx, stc_main_key(st_ctx), &ubi->ub_pni);
}

static void stc_update_pre_stage_pnode(const struct silofs_store_ctx *st_ctx,
                                       const struct silofs_key *key,
                                       struct silofs_pnode_info *pni)
{
	silofs_pni_setup_ivkey(pni, st_ctx->mdigest, key);
}

static void stc_update_pre_stage_uber(const struct silofs_store_ctx *st_ctx,
                                      struct silofs_uber_info *ubi)
{
	stc_update_pre_stage_pnode(st_ctx, stc_main_key(st_ctx), &ubi->ub_pni);
}

static int stc_spawn_uber(const struct silofs_store_ctx *st_ctx,
                          const struct silofs_paddr *paddr,
                          struct silofs_uber_info **out_ubi)
{
	int err;

	err = stc_require_paddr(st_ctx, paddr);
	if (err) {
		return err;
	}
	err = stc_create_cached_ubi(st_ctx, paddr, true, out_ubi);
	if (err) {
		return err;
	}
	stc_update_spawned_uber(st_ctx, *out_ubi);
	return 0;
}

int silofs_spawn_uber(struct silofs_env *env, const struct silofs_paddr *paddr,
                      struct silofs_uber_info **out_ubi)
{
	struct silofs_store_ctx st_ctx = {};
	int err;

	stc_init(&st_ctx, env);
	err = stc_spawn_uber(&st_ctx, paddr, out_ubi);
	stc_fini(&st_ctx);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stc_lookup_cached_ubi(const struct silofs_store_ctx *st_ctx,
                                 const struct silofs_paddr *paddr,
                                 struct silofs_uber_info **out_ubi)
{
	*out_ubi = silofs_lookup_cached_uber(st_ctx->pcache, paddr);
	return (*out_ubi == nullptr) ? -SILOFS_ENOENT : 0;
}

static int stc_access_pnode(const struct silofs_store_ctx *st_ctx,
                            const struct silofs_paddr *paddr)
{
	const off_t off = silofs_paddr_next(paddr);

	return silofs_locos_access_bpos(st_ctx->locos, &paddr->blobid, off);
}

static size_t viewlen_of(const struct silofs_pnode_info *pni)
{
	return silofs_mtype_size(silofs_pni_mtype(pni));
}

static int
stc_stage_pnode(struct silofs_store_ctx *st_ctx, struct silofs_pnode_info *pni)
{
	const struct silofs_rwvec rwvec = {
		.rwv_base = st_ctx->view,
		.rwv_len = viewlen_of(pni),
	};
	int err;

	err = silofs_locos_read_blob(st_ctx->locos, &pni->pn_paddr, &rwvec);
	if (err) {
		return err;
	}
	err = silofs_decrypt_pnode(pni, st_ctx->dec_cipher, st_ctx->view);
	if (err) {
		return err;
	}
	err = silofs_verify_pnode(pni);
	if (err) {
		return err;
	}
	return 0;
}

static int stc_stage_uber(struct silofs_store_ctx *st_ctx,
                          const struct silofs_paddr *paddr,
                          struct silofs_uber_info **out_ubi)
{
	struct silofs_uber_info *ubi = nullptr;
	int err;

	err = stc_lookup_cached_ubi(st_ctx, paddr, &ubi);
	if (!err) {
		goto out_ok; /* OK -- cache hit */
	}
	err = stc_access_pnode(st_ctx, paddr);
	if (err) {
		return err;
	}
	err = stc_create_cached_ubi(st_ctx, paddr, false, &ubi);
	if (err) {
		return err;
	}
	stc_update_pre_stage_uber(st_ctx, ubi);

	err = stc_stage_pnode(st_ctx, &ubi->ub_pni);
	if (err) {
		return err;
	}
out_ok:
	*out_ubi = ubi;
	return 0;
}

int silofs_stage_uber(struct silofs_env *env, const struct silofs_paddr *paddr,
                      struct silofs_uber_info **out_ubi)
{
	struct silofs_store_ctx st_ctx = {};
	int err;

	err = stc_init2(&st_ctx, env);
	if (!err) {
		err = stc_stage_uber(&st_ctx, paddr, out_ubi);
	}
	stc_fini(&st_ctx);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int stc_destage_dirty_pnode(struct silofs_store_ctx *st_ctx,
                                   struct silofs_pnode_info *pni)
{
	const struct silofs_rovec rovec = {
		.rov_base = st_ctx->view,
		.rov_len = viewlen_of(pni),
	};
	int err;

	silofs_seal_pnode(pni);
	err = silofs_encrypt_pnode(pni, st_ctx->enc_cipher, st_ctx->view);
	if (err) {
		return err;
	}
	err = silofs_locos_write_blob(st_ctx->locos, &pni->pn_paddr, &rovec);
	if (err) {
		return err;
	}
	return 0;
}

static struct silofs_pnode_info *stc_get_dirty(struct silofs_store_ctx *st_ctx)
{
	return silofs_pcache_dq_front(st_ctx->pcache);
}

static int stc_destage_dirty(struct silofs_store_ctx *st_ctx)
{
	struct silofs_pnode_info *pni;
	int err;

	pni = stc_get_dirty(st_ctx);
	while (pni != nullptr) {
		err = stc_destage_dirty_pnode(st_ctx, pni);
		if (err) {
			return err;
		}
		silofs_pni_undirtify(pni);
		pni = stc_get_dirty(st_ctx);
	}
	return 0;
}

int silofs_destage_dirty(struct silofs_env *env)
{
	struct silofs_store_ctx st_ctx = {};
	int err;

	err = stc_init2(&st_ctx, env);
	if (!err) {
		err = stc_destage_dirty(&st_ctx);
	}
	stc_fini(&st_ctx);
	return err;
}
