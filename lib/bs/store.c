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
#include "locos.h"
#include "store.h"
#include "mbr.h"

struct silofs_store_ctx {
	const struct silofs_mbrinfo *mbri;
	struct silofs_alloc *alloc;
	struct silofs_locos *locos;
	struct silofs_bcache *bcache;
	struct silofs_mdigest *mdigest;
	struct silofs_cipher *enc_cipher;
	struct silofs_cipher *dec_cipher;
	struct silofs_view *view;
};

static void stc_init(struct silofs_store_ctx *st_ctx, struct silofs_env *env)
{
	st_ctx->mbri = &env->mbri;
	st_ctx->alloc = env->base.alloc;
	st_ctx->locos = &env->base.repo->re_locos;
	st_ctx->bcache = env->base.bcache;
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
	return &st_ctx->mbri->fs_mbr.main_ivkey.key;
}

static int stc_require_baddr(const struct silofs_store_ctx *st_ctx,
                             const struct silofs_baddr *baddr)
{
	return silofs_locos_require_bpos(st_ctx->locos, &baddr->blobid,
	                                 baddr->pos);
}

static int stc_create_cached_ubi(const struct silofs_store_ctx *st_ctx,
                                 const struct silofs_baddr *baddr, bool spawn,
                                 struct silofs_uber_info **out_ubi)
{
	*out_ubi = silofs_create_cached_uber(st_ctx->bcache, baddr, spawn);
	return ((*out_ubi) == nullptr) ? -SILOFS_ENOMEM : 0;
}

static void stc_update_spawned_bnode(const struct silofs_store_ctx *st_ctx,
                                     const struct silofs_key *key,
                                     struct silofs_bnode_info *bni)
{
	silofs_bni_setup_ivkey(bni, st_ctx->mdigest, key);
	silofs_bni_dirtify(bni);
}

static void stc_update_spawned_uber(const struct silofs_store_ctx *st_ctx,
                                    struct silofs_uber_info *ubi)
{
	const struct silofs_key *key = stc_main_key(st_ctx);

	stc_update_spawned_bnode(st_ctx, key, &ubi->ub_bni);
}

static int stc_spawn_uber(const struct silofs_store_ctx *st_ctx,
                          const struct silofs_baddr *baddr,
                          struct silofs_uber_info **out_ubi)
{
	int err;

	err = stc_require_baddr(st_ctx, baddr);
	if (err) {
		return err;
	}
	err = stc_create_cached_ubi(st_ctx, baddr, true, out_ubi);
	if (err) {
		return err;
	}
	stc_update_spawned_uber(st_ctx, *out_ubi);
	return 0;
}

int silofs_spawn_uber(struct silofs_env *env, const struct silofs_baddr *baddr,
                      struct silofs_uber_info **out_ubi)
{
	struct silofs_store_ctx st_ctx = {};
	int err;

	stc_init(&st_ctx, env);
	err = stc_spawn_uber(&st_ctx, baddr, out_ubi);
	stc_fini(&st_ctx);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static size_t viewlen_of(const struct silofs_bnode_info *bni)
{
	return silofs_mtype_size(silofs_bni_mtype(bni));
}

static struct silofs_bnode_info *stc_get_dirty(struct silofs_store_ctx *st_ctx)
{
	return silofs_bcache_dq_front(st_ctx->bcache);
}

static int stc_destage_dirty_bnode(struct silofs_store_ctx *st_ctx,
                                   const struct silofs_bnode_info *bni)
{
	const struct silofs_rovec rovec = {
		.rov_base = st_ctx->view,
		.rov_len = viewlen_of(bni),
	};
	int err;

	err = silofs_encrypt_bnode(bni, st_ctx->enc_cipher, st_ctx->view);
	if (err) {
		return err;
	}
	err = silofs_locos_write_blob(st_ctx->locos, &bni->bn_baddr, &rovec);
	if (err) {
		return err;
	}
	return 0;
}

static int stc_destage_dirty(struct silofs_store_ctx *st_ctx)
{
	struct silofs_bnode_info *bni;
	int err;

	bni = stc_get_dirty(st_ctx);
	while (bni != nullptr) {
		err = stc_destage_dirty_bnode(st_ctx, bni);
		if (err) {
			return err;
		}
		silofs_bni_undirtify(bni);
		bni = stc_get_dirty(st_ctx);
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
