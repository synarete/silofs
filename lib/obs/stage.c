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
#include <silofs/configs.h>
#include <sys/stat.h>
#include "nodes.h"
#include "dstor.h"
#include "uber.h"
#include "stage.h"
#include "mbr.h"
#include "env.h"

struct silofs_stage_ctx {
	struct silofs_alloc   *alloc;
	struct silofs_dstor   *dstor;
	struct silofs_pcache  *pcache;
	struct silofs_mdigest *mdigest;
	struct silofs_cipher  *enc_cipher;
	struct silofs_cipher  *dec_cipher;
	struct silofs_view    *view;
};

static void stc_init(struct silofs_stage_ctx *st_ctx, struct silofs_env *env)
{
	st_ctx->alloc      = env->base.alloc;
	st_ctx->dstor      = &env->base.repo->re_dstor;
	st_ctx->pcache     = env->base.pcache;
	st_ctx->mdigest    = &env->mdigest;
	st_ctx->enc_cipher = &env->enc_cipher;
	st_ctx->dec_cipher = &env->dec_cipher;
	st_ctx->view       = nullptr;
}

static void stc_fini(struct silofs_stage_ctx *st_ctx)
{
	struct silofs_view *view = st_ctx->view;

	if (view != nullptr) {
		silofs_memfree(st_ctx->alloc, view, sizeof(*view), 0);
	}
}

static int stc_require_view(struct silofs_stage_ctx *st_ctx)
{
	struct silofs_view *view = nullptr;

	if (st_ctx->view != nullptr) {
		return 0;
	}
	view = silofs_memalloc(st_ctx->alloc, sizeof(*view), 0);
	if (view == nullptr) {
		return -SILOFS_ENOENT;
	}
	st_ctx->view = view;
	return 0;
}

static int stc_require_paddr(const struct silofs_stage_ctx *st_ctx,
                             const struct silofs_paddr     *paddr)
{
	return silofs_dstor_require_blob_at(st_ctx->dstor, &paddr->blobid,
	                                    paddr->pos);
}

static int stc_require_paddr_of(const struct silofs_stage_ctx *st_ctx,
                                const struct silofs_pmeta     *pmeta)
{
	return stc_require_paddr(st_ctx, &pmeta->paddr);
}

static void stc_update_spawned_pnode(const struct silofs_stage_ctx *st_ctx,
                                     struct silofs_pnode_info      *pni)

{
	silofs_pni_dirtify(pni);
	silofs_unused(st_ctx);
}

static int stc_access_pnode(const struct silofs_stage_ctx *st_ctx,
                            const struct silofs_paddr     *paddr)
{
	const off_t off = silofs_paddr_next(paddr);

	return silofs_dstor_access_blob_at(st_ctx->dstor, &paddr->blobid, off);
}

static int stc_access_pnode_of(const struct silofs_stage_ctx *st_ctx,
                               const struct silofs_pmeta     *pmeta)
{
	return stc_access_pnode(st_ctx, &pmeta->paddr);
}

static size_t viewlen_of(const struct silofs_pnode_info *pni)
{
	return silofs_mtype_size(silofs_pni_mtype(pni));
}

static int
stc_read_pnode(struct silofs_stage_ctx *st_ctx, struct silofs_pnode_info *pni)
{
	const struct silofs_paddr *paddr = &pni->pn_meta.paddr;
	const size_t               len   = viewlen_of(pni);

	return silofs_dstor_read_blob_at(st_ctx->dstor, &paddr->blobid,
	                                 paddr->pos, st_ctx->view, len);
}

static int stc_decrypt_verify_pnode(struct silofs_stage_ctx  *st_ctx,
                                    struct silofs_pnode_info *pni)
{
	int err;

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

static int
stc_stage_pnode(struct silofs_stage_ctx *st_ctx, struct silofs_pnode_info *pni)
{
	int err;

	err = stc_require_view(st_ctx);
	if (err) {
		return err;
	}
	err = stc_read_pnode(st_ctx, pni);
	if (err) {
		return err;
	}
	err = stc_decrypt_verify_pnode(st_ctx, pni);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stc_create_cached_ubi(const struct silofs_stage_ctx *st_ctx,
                                 const struct silofs_pmeta *pmeta, bool spawn,
                                 struct silofs_uber_info **out_ubi)
{
	*out_ubi = silofs_create_cached_uber(st_ctx->pcache, pmeta, spawn);
	return ((*out_ubi) == nullptr) ? -SILOFS_ENOMEM : 0;
}

static int stc_spawn_uber(const struct silofs_stage_ctx *st_ctx,
                          const struct silofs_pmeta     *pmeta,
                          struct silofs_uber_info      **out_ubi)
{
	int err;

	err = stc_require_paddr_of(st_ctx, pmeta);
	if (err) {
		return err;
	}
	err = stc_create_cached_ubi(st_ctx, pmeta, true, out_ubi);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_spawn_uber(struct silofs_env *env, const struct silofs_pmeta *pmeta,
                      struct silofs_uber_info **out_ubi)
{
	struct silofs_stage_ctx st_ctx = {};
	int                     err;

	stc_init(&st_ctx, env);
	err = stc_spawn_uber(&st_ctx, pmeta, out_ubi);
	stc_fini(&st_ctx);
	return err;
}

static int stc_lookup_cached_ubi(const struct silofs_stage_ctx *st_ctx,
                                 const struct silofs_paddr     *paddr,
                                 struct silofs_uber_info      **out_ubi)
{
	*out_ubi = silofs_lookup_cached_uber(st_ctx->pcache, paddr);
	return (*out_ubi == nullptr) ? -SILOFS_ENOENT : 0;
}

static int stc_stage_uber(struct silofs_stage_ctx   *st_ctx,
                          const struct silofs_pmeta *pmeta,
                          struct silofs_uber_info  **out_ubi)
{
	struct silofs_uber_info *ubi = nullptr;
	int                      err;

	err = stc_lookup_cached_ubi(st_ctx, &pmeta->paddr, &ubi);
	if (!err) {
		goto out_ok; /* OK -- cache hit */
	}
	err = stc_access_pnode_of(st_ctx, pmeta);
	if (err) {
		return err;
	}
	err = stc_create_cached_ubi(st_ctx, pmeta, false, &ubi);
	if (err) {
		return err;
	}
	err = stc_stage_pnode(st_ctx, &ubi->ub_pni);
	if (err) {
		return err;
	}
out_ok:
	*out_ubi = ubi;
	return 0;
}

int silofs_stage_uber(struct silofs_env *env, const struct silofs_pmeta *pmeta,
                      struct silofs_uber_info **out_ubi)
{
	struct silofs_stage_ctx st_ctx = {};
	int                     err;

	stc_init(&st_ctx, env);
	err = stc_stage_uber(&st_ctx, pmeta, out_ubi);
	stc_fini(&st_ctx);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stc_create_cached_bdi(const struct silofs_stage_ctx *st_ctx,
                                 const struct silofs_pmeta *pmeta, bool spawn,
                                 struct silofs_bldesc_info **out_bdi)
{
	*out_bdi = silofs_create_cached_bldesc(st_ctx->pcache, pmeta, spawn);
	return ((*out_bdi) == nullptr) ? -SILOFS_ENOMEM : 0;
}

static void stc_update_spawned_bldesc(const struct silofs_stage_ctx *st_ctx,
                                      struct silofs_bldesc_info     *bdi)
{
	stc_update_spawned_pnode(st_ctx, &bdi->bld_pni);
}

static int stc_spawn_bldesc(const struct silofs_stage_ctx *st_ctx,
                            const struct silofs_pmeta     *pmeta,
                            struct silofs_bldesc_info    **out_bdi)
{
	int err;

	err = stc_require_paddr_of(st_ctx, pmeta);
	if (err) {
		return err;
	}
	err = stc_create_cached_bdi(st_ctx, pmeta, true, out_bdi);
	if (err) {
		return err;
	}
	stc_update_spawned_bldesc(st_ctx, *out_bdi);
	return 0;
}

int silofs_spawn_bldesc(struct silofs_env          *env,
                        const struct silofs_pmeta  *pmeta,
                        struct silofs_bldesc_info **out_bdi)
{
	struct silofs_stage_ctx st_ctx = {};
	int                     err;

	stc_init(&st_ctx, env);
	err = stc_spawn_bldesc(&st_ctx, pmeta, out_bdi);
	stc_fini(&st_ctx);
	return err;
}

static int stc_lookup_cached_bdi(const struct silofs_stage_ctx *st_ctx,
                                 const struct silofs_paddr     *paddr,
                                 struct silofs_bldesc_info    **out_bdi)
{
	*out_bdi = silofs_lookup_cached_bldesc(st_ctx->pcache, paddr);
	return (*out_bdi == nullptr) ? -SILOFS_ENOENT : 0;
}

static int stc_stage_bldesc(struct silofs_stage_ctx    *st_ctx,
                            const struct silofs_pmeta  *pmeta,
                            struct silofs_bldesc_info **out_bdi)
{
	struct silofs_bldesc_info *bdi = nullptr;
	int                        err;

	err = stc_lookup_cached_bdi(st_ctx, &pmeta->paddr, &bdi);
	if (!err) {
		goto out_ok; /* OK -- cache hit */
	}
	err = stc_access_pnode_of(st_ctx, pmeta);
	if (err) {
		return err;
	}
	err = stc_create_cached_bdi(st_ctx, pmeta, false, &bdi);
	if (err) {
		return err;
	}
	err = stc_stage_pnode(st_ctx, &bdi->bld_pni);
	if (err) {
		return err;
	}
out_ok:
	*out_bdi = bdi;
	return 0;
}

int silofs_stage_bldesc(struct silofs_env          *env,
                        const struct silofs_pmeta  *pmeta,
                        struct silofs_bldesc_info **out_bdi)
{
	struct silofs_stage_ctx st_ctx = {};
	int                     err;

	stc_init(&st_ctx, env);
	err = stc_stage_bldesc(&st_ctx, pmeta, out_bdi);
	stc_fini(&st_ctx);
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int stc_create_cached_bti(const struct silofs_stage_ctx *st_ctx,
                                 const struct silofs_pmeta *pmeta, bool spawn,
                                 struct silofs_btnode_info **out_bti)
{
	*out_bti = silofs_create_cached_btnode(st_ctx->pcache, pmeta, spawn);
	return ((*out_bti) == nullptr) ? -SILOFS_ENOMEM : 0;
}

static void stc_update_spawned_btnode(const struct silofs_stage_ctx *st_ctx,
                                      struct silofs_btnode_info     *bti)
{
	stc_update_spawned_pnode(st_ctx, &bti->btn_pni);
}

static int stc_spawn_btnode(const struct silofs_stage_ctx *st_ctx,
                            const struct silofs_pmeta     *pmeta,
                            struct silofs_btnode_info    **out_bti)
{
	int err;

	err = stc_require_paddr(st_ctx, &pmeta->paddr);
	if (err) {
		return err;
	}
	err = stc_create_cached_bti(st_ctx, pmeta, true, out_bti);
	if (err) {
		return err;
	}
	stc_update_spawned_btnode(st_ctx, *out_bti);
	return 0;
}

int silofs_spawn_btnode(struct silofs_env          *env,
                        const struct silofs_pmeta  *pmeta,
                        struct silofs_btnode_info **out_bti)
{
	struct silofs_stage_ctx st_ctx = {};
	int                     err;

	stc_init(&st_ctx, env);
	err = stc_spawn_btnode(&st_ctx, pmeta, out_bti);
	stc_fini(&st_ctx);
	return err;
}

static int stc_lookup_cached_bti(const struct silofs_stage_ctx *st_ctx,
                                 const struct silofs_paddr     *paddr,
                                 struct silofs_btnode_info    **out_bti)
{
	*out_bti = silofs_lookup_cached_btnode(st_ctx->pcache, paddr);
	return (*out_bti == nullptr) ? -SILOFS_ENOENT : 0;
}

static int stc_stage_btnode(struct silofs_stage_ctx    *st_ctx,
                            const struct silofs_pmeta  *pmeta,
                            struct silofs_btnode_info **out_bti)
{
	struct silofs_btnode_info *bti = nullptr;
	int                        err;

	err = stc_lookup_cached_bti(st_ctx, &pmeta->paddr, &bti);
	if (!err) {
		goto out_ok; /* OK -- cache hit */
	}
	err = stc_access_pnode_of(st_ctx, pmeta);
	if (err) {
		return err;
	}
	err = stc_create_cached_bti(st_ctx, pmeta, false, &bti);
	if (err) {
		return err;
	}
	err = stc_stage_pnode(st_ctx, &bti->btn_pni);
	if (err) {
		return err;
	}
out_ok:
	*out_bti = bti;
	return 0;
}

int silofs_stage_btnode(struct silofs_env          *env,
                        const struct silofs_pmeta  *pmeta,
                        struct silofs_btnode_info **out_bti)
{
	struct silofs_stage_ctx st_ctx = {};
	int                     err;

	stc_init(&st_ctx, env);
	err = stc_stage_btnode(&st_ctx, pmeta, out_bti);
	stc_fini(&st_ctx);
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int stc_write_pnode(struct silofs_stage_ctx        *st_ctx,
                           const struct silofs_pnode_info *pni)
{
	const struct silofs_paddr *paddr = &pni->pn_meta.paddr;
	const size_t               len   = viewlen_of(pni);

	return silofs_dstor_write_blob_at(st_ctx->dstor, &paddr->blobid,
	                                  paddr->pos, st_ctx->view, len);
}

static int stc_seal_encrypt_pnode(struct silofs_stage_ctx  *st_ctx,
                                  struct silofs_pnode_info *pni)
{
	silofs_seal_pnode(pni);
	return silofs_encrypt_pnode(pni, st_ctx->enc_cipher, st_ctx->view);
}

static int stc_destage_dirty_pnode(struct silofs_stage_ctx  *st_ctx,
                                   struct silofs_pnode_info *pni)
{
	int err;

	err = stc_require_view(st_ctx);
	if (err) {
		return err;
	}
	err = stc_seal_encrypt_pnode(st_ctx, pni);
	if (err) {
		return err;
	}
	err = stc_write_pnode(st_ctx, pni);
	if (err) {
		return err;
	}
	return 0;
}

static struct silofs_pnode_info *stc_get_dirty(struct silofs_stage_ctx *st_ctx)
{
	return silofs_pcache_dq_front(st_ctx->pcache);
}

static int stc_destage_dirty(struct silofs_stage_ctx *st_ctx)
{
	struct silofs_pnode_info *pni;
	int                       err;

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
	struct silofs_stage_ctx st_ctx = {};
	int                     err;

	stc_init(&st_ctx, env);
	err = stc_destage_dirty(&st_ctx);
	stc_fini(&st_ctx);
	return err;
}
