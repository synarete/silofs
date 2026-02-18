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

static void
make_uniq_blobid(struct silofs_prandgen *prng, enum silofs_mtype mtype,
                 struct silofs_blobid *out_blobid)
{
	silofs_blobid_initv(out_blobid, mtype);
	silofs_generate_layerid(prng, &out_blobid->layerid);
	silofs_generate_uniqid(prng, &out_blobid->uniqid);
}

static void
make_base_paddr(struct silofs_prandgen *prng, enum silofs_mtype mtype,
                struct silofs_paddr *out_paddr)
{
	struct silofs_blobid blobid;

	make_uniq_blobid(prng, mtype, &blobid);
	silofs_paddr_init(out_paddr, &blobid, 0);
}

static void
ignite_space_at(struct silofs_prandgen *prng, const struct silofs_paddr *paddr,
                struct silofs_pnptr *out_pnptr)
{
	struct silofs_civkey civkey;

	silofs_generate_civkey(prng, &civkey);
	silofs_pnptr_setup(out_pnptr, paddr, &civkey);
}

static void
ignite_space_of(struct silofs_prandgen *prng, enum silofs_mtype mtype,
                struct silofs_pnptr *out_pnptr)
{
	struct silofs_paddr paddr = {};

	make_base_paddr(prng, mtype, &paddr);
	ignite_space_at(prng, &paddr, out_pnptr);
}

void silofs_ignite_ubspace(const struct silofs_task_ctx *task,
                           struct silofs_pnptr *out_pnptr)
{
	ignite_space_of(task->prng, SILOFS_MTYPE_UBER, out_pnptr);
}

void silofs_ignite_btspace(const struct silofs_task_ctx *task,
                           struct silofs_pnptr *out_pnptr)
{
	ignite_space_of(task->prng, SILOFS_MTYPE_BTNODE, out_pnptr);
}

void silofs_ignite_vspace(const struct silofs_task_ctx *task,
                          enum silofs_mtype vtype,
                          struct silofs_spdesc *out_spdesc)
{
	struct silofs_paddr paddr = {};

	make_base_paddr(task->prng, vtype, &paddr);
	silofs_spdesc_setup1(out_spdesc, &paddr);
}
