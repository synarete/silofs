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
#include "infra.h"
#include "addr.h"
#include "crypto.h"
#include "nodes.h"
#include "uber.h"
#include "space.h"
#include "exectx.h"
#include "env.h"

static const struct silofs_layerid *
top_layerid(const struct silofs_task_ctx *task)
{
	const struct silofs_uber_info *ubi = task->env->ubi;

	silofs_assert_not_null(ubi);
	return silofs_ubi_layerid(ubi);
}

static void gen_layerid(const struct silofs_task_ctx *task,
                        struct silofs_layerid *out_layerid)
{
	silofs_generate_layerid(task->prng, out_layerid);
}

static void gen_uniqid(const struct silofs_task_ctx *task,
                       struct silofs_uniqid *out_uniqid)
{
	silofs_generate_uniqid(task->prng, out_uniqid);
}

static void gen_civkey(const struct silofs_task_ctx *task,
                       struct silofs_civkey *out_civkey)
{
	silofs_generate_civkey(task->prng, out_civkey);
}

void silofs_ignite_pnptr(const struct silofs_task_ctx *task,
                         const struct silofs_paddr *paddr,
                         struct silofs_pnptr *out_pnptr)
{
	struct silofs_civkey civkey;

	gen_civkey(task, &civkey);
	silofs_pnptr_setup(out_pnptr, paddr, &civkey);
}

void silofs_ignite_ubspace(const struct silofs_task_ctx *task,
                           struct silofs_paddr *out_paddr)
{
	struct silofs_layerid layerid;
	struct silofs_uniqid uniqid;
	struct silofs_blobid blobid;
	const struct silofs_stype stype = {
		.ptype = SILOFS_PTYPE_UBER,
		.vtype = SILOFS_VTYPE_NONE,
	};

	gen_layerid(task, &layerid);
	gen_uniqid(task, &uniqid);
	silofs_blobid_init(&blobid, &stype, &layerid, &uniqid);
	silofs_paddr_init(out_paddr, &blobid, 0);
}

void silofs_ignite_btspace(const struct silofs_task_ctx *task,
                           enum silofs_vtype vtype,
                           struct silofs_paddr *out_paddr)
{
	struct silofs_uniqid uniqid;
	struct silofs_blobid blobid;
	const struct silofs_stype stype = {
		.ptype = SILOFS_PTYPE_BTNODE,
		.vtype = vtype,
	};

	gen_uniqid(task, &uniqid);
	silofs_blobid_init(&blobid, &stype, top_layerid(task), &uniqid);
	silofs_paddr_init(out_paddr, &blobid, 0);
}

void silofs_ignite_vspace(const struct silofs_task_ctx *task,
                          enum silofs_vtype vtype,
                          struct silofs_paddr *out_paddr)
{
	struct silofs_uniqid uniqid;
	struct silofs_blobid blobid;
	const struct silofs_stype stype = {
		.ptype = SILOFS_PTYPE_VNODE,
		.vtype = vtype,
	};

	gen_uniqid(task, &uniqid);
	silofs_blobid_init(&blobid, &stype, top_layerid(task), &uniqid);
	silofs_paddr_init(out_paddr, &blobid, 0);
}

void silofs_carve_btspace(const struct silofs_task_ctx *task,
                          enum silofs_vtype vtype,
                          struct silofs_paddr *out_paddr)
{
	struct silofs_spdesc spdesc[2];
	const struct silofs_stype stype = {
		.ptype = SILOFS_PTYPE_BTNODE,
		.vtype = vtype,
	};

	silofs_ubi_spdesc_of(task->env->ubi, &stype, &spdesc[0]);
	silofs_paddr_next(&spdesc[0].end, out_paddr);

	silofs_spdesc_setup(&spdesc[1], &spdesc[0].beg, out_paddr);
	silofs_ubi_update_spdesc(task->env->ubi, &spdesc[1]);
}
