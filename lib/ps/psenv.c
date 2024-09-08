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


static void pstate_init(struct silofs_pstate *pstate)
{
	silofs_psid_setup(&pstate->beg);
	silofs_psid_assign(&pstate->cur, &pstate->beg);
	pstate->cur_pos = 0;
}

static void pstate_fini(struct silofs_pstate *pstate)
{
	silofs_psid_reset(&pstate->beg);
	silofs_psid_reset(&pstate->cur);
	pstate->cur_pos = -1;
}

static void pstate_next_btn(struct silofs_pstate *pstate,
                            struct silofs_paddr *out_paddr)
{
	silofs_paddr_init_btn(out_paddr, &pstate->cur, pstate->cur_pos);
	pstate->cur_pos = off_end(out_paddr->off, out_paddr->len);
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

int silofs_psenv_dropall(struct silofs_psenv *psenv)
{
	silofs_bcache_drop(&psenv->bcache);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_paddr *
bti_paddr(const struct silofs_btnode_info *bti)
{
	return &bti->btn_bni.bn_paddr;
}

static int create_cached_bti(struct silofs_psenv *psenv,
                             const struct silofs_paddr *paddr,
                             struct silofs_btnode_info **out_bti)
{
	*out_bti = silofs_bcache_create_bti(&psenv->bcache, paddr);
	return (*out_bti == NULL) ? -SILOFS_ENOMEM : 0;
}

static void forget_cached_bti(struct silofs_psenv *psenv,
                              struct silofs_btnode_info *bti)
{
	silofs_bcache_forget_bti(&psenv->bcache, bti);
}

static int commit_btnode(const struct silofs_psenv *psenv,
                         const struct silofs_btnode_info *bti)
{
	const struct silofs_rovec rov = {
		.rov_base = bti->btn,
		.rov_len = sizeof(*bti->btn),
	};

	return silofs_repo_save_pobj(psenv->repo, bti_paddr(bti), &rov);
}

static int require_pseg(const struct silofs_psenv *psenv,
                        const struct silofs_psid *psid)
{
	int err;

	err = silofs_repo_stage_pseg(psenv->repo, psid);
	if (err == -SILOFS_ENOENT) {
		err = silofs_repo_create_pseg(psenv->repo, psid);
	}
	return err;
}

static int require_pseg_of(const struct silofs_psenv *psenv,
                           const struct silofs_paddr *paddr)
{
	return require_pseg(psenv, &paddr->psid);
}

static int format_btree_root(struct silofs_psenv *psenv)
{
	struct silofs_paddr paddr;
	struct silofs_btnode_info *bti = NULL;
	int err;

	pstate_next_btn(&psenv->pstate, &paddr);
	err = require_pseg_of(psenv, &paddr);
	if (err) {
		return err;
	}
	err = create_cached_bti(psenv, &paddr, &bti);
	if (err) {
		return err;
	}
	silofs_bti_mark_root(bti);

	err = commit_btnode(psenv, bti);
	if (err) {
		forget_cached_bti(psenv, bti);
		return err;
	}
	return 0;
}

int silofs_format_btree(struct silofs_psenv *psenv)
{
	return format_btree_root(psenv);
}
