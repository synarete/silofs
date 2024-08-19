/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#include <silofs/ps.h>


static void prange_init(struct silofs_prange *prange, enum silofs_ptype ptype)
{
	silofs_psid_setup(&prange->beg, ptype);
	silofs_psid_assign(&prange->cur, &prange->beg);
	prange->cur_pos = 0;
}

static void prange_fini(struct silofs_prange *prange)
{
	silofs_psid_reset(&prange->beg);
	silofs_psid_reset(&prange->cur);
	prange->cur_pos = -1;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void pstate_init(struct silofs_pstate *pstate)
{
	prange_init(&pstate->btn, SILOFS_PTYPE_BTNODE);
	prange_init(&pstate->btl, SILOFS_PTYPE_BTLEAF);
	prange_init(&pstate->dat, SILOFS_PTYPE_DATA);
}

static void pstate_fini(struct silofs_pstate *pstate)
{
	prange_fini(&pstate->btn);
	prange_fini(&pstate->btl);
	prange_fini(&pstate->dat);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_psenv_init(struct silofs_psenv *psenv,
                      struct silofs_repo *repo)
{
	pstate_init(&psenv->pstate);
	psenv->repo = repo;
	psenv->alloc = repo->re.alloc;
	return silofs_bcache_init(&psenv->bcache, psenv->alloc);
}

void silofs_psenv_fini(struct silofs_psenv *psenv)
{
	silofs_bcache_drop(&psenv->bcache);
	silofs_bcache_fini(&psenv->bcache);
	pstate_fini(&psenv->pstate);
	psenv->alloc = NULL;
	psenv->repo = NULL;
}

void silofs_psenv_format_bt(struct silofs_psenv *psenv);
