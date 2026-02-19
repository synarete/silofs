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

static void generate_pnptr_at(const struct silofs_task_ctx *task,
                              const struct silofs_paddr *paddr,
                              struct silofs_pnptr *out_pnptr)
{
	struct silofs_civkey civkey;

	silofs_generate_civkey(task->prng, &civkey);
	silofs_pnptr_setup(out_pnptr, paddr, &civkey);
}

void silofs_ignite_ubspace(const struct silofs_task_ctx *task,
                           struct silofs_pnptr *out_pnptr)
{
	struct silofs_layerid layerid;
	struct silofs_uniqid uniqid;
	struct silofs_blobid blobid;
	struct silofs_paddr paddr;

	silofs_generate_layerid(task->prng, &layerid);
	silofs_generate_uniqid(task->prng, &uniqid);

	silofs_blobid_init(&blobid, SILOFS_PTYPE_UBER, SILOFS_VTYPE_NONE);
	silofs_blobid_update(&blobid, &layerid, &uniqid);

	silofs_paddr_init(&paddr, &blobid, 0);
	generate_pnptr_at(task, &paddr, out_pnptr);
}

void silofs_ignite_btspace(const struct silofs_task_ctx *task,
                           enum silofs_vtype vspace,
                           struct silofs_pnptr *out_pnptr)
{
	struct silofs_uniqid uniqid;
	struct silofs_blobid blobid;
	struct silofs_paddr paddr;
	const struct silofs_uber_info *ubi = task->env->ubi;

	silofs_assert_not_null(ubi);
	silofs_generate_uniqid(task->prng, &uniqid);

	silofs_blobid_init(&blobid, SILOFS_PTYPE_BTNODE, vspace);
	silofs_blobid_update(&blobid, silofs_ubi_layerid(ubi), &uniqid);

	silofs_paddr_init(&paddr, &blobid, 0);
	generate_pnptr_at(task, &paddr, out_pnptr);
}

void silofs_ignite_vspace(const struct silofs_task_ctx *task,
                          enum silofs_vtype vtype,
                          struct silofs_spdesc *out_spdesc)
{
	struct silofs_uniqid uniqid;
	struct silofs_blobid blobid;
	struct silofs_paddr paddr;
	const struct silofs_uber_info *ubi = task->env->ubi;

	silofs_assert_not_null(ubi);
	silofs_generate_uniqid(task->prng, &uniqid);

	silofs_blobid_init(&blobid, SILOFS_PTYPE_VNODE, vtype);
	silofs_blobid_update(&blobid, silofs_ubi_layerid(ubi), &uniqid);

	silofs_paddr_init(&paddr, &blobid, 0);
	silofs_spdesc_setup1(out_spdesc, &paddr);
}
