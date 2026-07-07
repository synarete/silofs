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

static void lni_setdirty(struct silofs_lnode_info *lni)
{
	silofs_lni_setdirty(lni, nullptr);
}

static bool uses_spmap(const struct silofs_laddr *laddr)
{
	return silofs_ltype_usespmap(laddr->ltype);
}

static int resolve_spacef_of(const struct silofs_pexec_ctx *pexec,
                             const struct silofs_laddr *laddr,
                             enum silofs_lspacef *out_spacef)
{
	struct silofs_lspace_ref vspref = {
		.flags = SILOFS_LSPACEF_NONE,
	};
	int ret = 0;

	if (uses_spmap(laddr)) {
		/* XXX silofs_probe_lspace_ref(pexec, laddr, &vspref); */
		(void)pexec;
		ret = 0;
	}
	*out_spacef = vspref.flags;
	return ret;
}

int silofs_stage_lnode_at(const struct silofs_pexec_ctx *pexec,
                          const struct silofs_laddr *laddr,
                          struct silofs_lnode_info **out_lni)
{
	struct silofs_pnptr pnptr;
	enum silofs_lspacef lspf;
	int err;

	err = silofs_resolve_ltop_mapping(pexec, laddr, &pnptr);
	return_if_err(err);

	err = resolve_spacef_of(pexec, laddr, &lspf);
	return_if_err(err);

	err = silofs_stage_lnode_with(pexec, laddr, &pnptr, lspf, out_lni);
	return_if_err(err);

	return 0;
}

int silofs_create_ltop_mapping(const struct silofs_pexec_ctx *pexec,
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

int silofs_spawn_lnode2_at(const struct silofs_pexec_ctx *pexec,
                           const struct silofs_laddr *laddr,
                           struct silofs_lnode_info **out_lni)
{
	struct silofs_pnptr pnptr = {};
	int err;

	err = silofs_create_ltop_mapping(pexec, laddr, &pnptr);
	return_if_err(err);

	err = silofs_spawn_lnode_with(pexec, laddr, &pnptr, out_lni);
	return_if_err(err);

	lni_setdirty(*out_lni);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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

	silofs_lspools_push(pexec->lspools, laddr);
	silofs_pspools_push(pexec->pspools, &pnptr.paddr);

	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int resolve_stage_spnode2_at(const struct silofs_pexec_ctx *pexec,
                                    const struct silofs_laddr *laddr,
                                    struct silofs_spnode_info **out_spi)
{
	struct silofs_lnode_info *lni = nullptr;
	int err;

	err = silofs_stage_lnode_at(pexec, laddr, &lni);
	return_if_err(err);

	*out_spi = silofs_spi_from_lni(lni);
	silofs_spi_setup_staged(*out_spi);
	return 0;
}

int silofs_stage_spnode_by(const struct silofs_pexec_ctx *pexec,
                           const struct silofs_laddr *ref_laddr,
                           struct silofs_spnode_info **out_spi)
{
	struct silofs_laddr laddr;

	silofs_resolve_spnode_laddr(ref_laddr, &laddr);
	return resolve_stage_spnode2_at(pexec, &laddr, out_spi);
}
