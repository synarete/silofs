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

struct silofs_store_ctx {
	struct silofs_locos *locos;
	struct silofs_bcache *bcache;
};

static void stc_setup(struct silofs_store_ctx *st_ctx, struct silofs_env *env)
{
	st_ctx->locos = &env->base.repo->re_locos;
	st_ctx->bcache = env->base.bcache;
}

static int stc_require_baddr(const struct silofs_store_ctx *st_ctx,
                             const struct silofs_baddr *baddr)
{
	return silofs_locos_require_bpos(st_ctx->locos, &baddr->blobid,
	                                 baddr->pos);
}

static int stc_create_ubi(const struct silofs_store_ctx *st_ctx,
                          const struct silofs_baddr *baddr,
                          struct silofs_ub_info **out_ubi)
{
	*out_ubi = silofs_bcache_create_ubi(st_ctx->bcache, baddr);
	return ((*out_ubi) == nullptr) ? -SILOFS_ENOMEM : 0;
}

static int stc_spawn_uber(struct silofs_store_ctx *st_ctx,
                          const struct silofs_baddr *baddr,
                          struct silofs_ub_info **out_ubi)
{
	int err;

	err = stc_require_baddr(st_ctx, baddr);
	if (err) {
		return err;
	}
	err = stc_create_ubi(st_ctx, baddr, out_ubi);
	if (err) {
		return err;
	}
	silofs_ubi_setup_spawned(*out_ubi);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_spawn_uber(struct silofs_env *env, const struct silofs_baddr *baddr,
                      struct silofs_ub_info **out_ubi)
{
	struct silofs_store_ctx st_ctx = {};

	stc_setup(&st_ctx, env);
	return stc_spawn_uber(&st_ctx, baddr, out_ubi);
}
