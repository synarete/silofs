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
#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>
#include <silofs/pstor.h>

static int create_lnode_mapping(const struct silofs_pexec_ctx *pexec,
                                const struct silofs_laddr *laddr,
                                struct silofs_pnptr *out_pnptr)
{
	int err;

	err = silofs_carve_lspace_pnptr(pexec, laddr->ltype, out_pnptr);
	return_if_err(err);

	err = silofs_require_paddr(pexec, &out_pnptr->paddr);
	return_if_err(err);

	err = silofs_insert_ltop_mapping(pexec, laddr, out_pnptr);
	return_if_err(err);

	return 0;
}

int silofs_stage_lnode_by_mapping(const struct silofs_pexec_ctx *pexec,
                                  const struct silofs_laddr *laddr,
                                  enum silofs_lspacef lspf,
                                  struct silofs_lnode_info **out_lni)
{
	struct silofs_pnptr pnptr;
	int err;

	err = silofs_resolve_ltop_mapping(pexec, laddr, &pnptr);
	return_if_err(err);

	err = silofs_stage_lnode_with(pexec, laddr, &pnptr, lspf, out_lni);
	return_if_err(err);

	return 0;
}

static void lni_setdirty(struct silofs_lnode_info *lni)
{
	silofs_lni_setdirty(lni, nullptr);
}

int silofs_spawn_lnode_by_mapping(const struct silofs_pexec_ctx *pexec,
                                  const struct silofs_laddr *laddr,
                                  struct silofs_lnode_info **out_lni)
{
	struct silofs_pnptr pnptr;
	int err;

	err = create_lnode_mapping(pexec, laddr, &pnptr);
	return_if_err(err);

	err = silofs_spawn_lnode_with(pexec, laddr, &pnptr, out_lni);
	return_if_err(err);

	lni_setdirty(*out_lni);
	return 0;
}

int silofs_claim_lnode_mapping(const struct silofs_pexec_ctx *pexec,
                               const struct silofs_laddr *laddr)
{
	struct silofs_pnptr pnptr = {};
	int err;

	err = create_lnode_mapping(pexec, laddr, &pnptr);
	return_if_err(err);

	err = silofs_claim_lnode_pspace(pexec, laddr, &pnptr);
	return_if_err(err);

	return 0;
}

int silofs_reclaim_lnode_mapping(const struct silofs_pexec_ctx *pexec,
                                 const struct silofs_laddr *laddr)
{
	struct silofs_pnptr pnptr;
	int err;

	err = silofs_resolve_ltop_mapping(pexec, laddr, &pnptr);
	return_if_err(err);

	err = silofs_detach_lnode_at(pexec, laddr, &pnptr);
	return_if_err(err);

	err = silofs_remove_ltop_mapping(pexec, laddr);
	return_if_err(err);

	silofs_pspools_push(pexec->pspools, &pnptr.paddr);

	return 0;
}
