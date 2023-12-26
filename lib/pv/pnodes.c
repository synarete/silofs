/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
 *
 * Silofs is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *      ut_inspect_ok(ute, dino);
 * Silofs is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/pv.h>


static void pni_init(struct silofs_pnode_info *pni,
                     const struct silofs_paddr *paddr)
{
	silofs_assert(!silofs_paddr_isnull(paddr));

	paddr_assign(&pni->p_paddr, paddr);
	list_head_init(&pni->p_htb_lh);
	list_head_init(&pni->p_lru_lh);
	pni->p_psenv = NULL;
}

static void pni_fini(struct silofs_pnode_info *pni)
{
	paddr_reset(&pni->p_paddr);
	list_head_fini(&pni->p_htb_lh);
	list_head_fini(&pni->p_lru_lh);
	pni->p_psenv = NULL;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_btnode_info *bti_malloc(struct silofs_alloc *alloc)
{
	struct silofs_btnode_info *bti = NULL;

	bti = silofs_allocate(alloc, sizeof(*bti), 0);
	return bti;
}

static void bti_free(struct silofs_btnode_info *bti,
                     struct silofs_alloc *alloc)
{
	silofs_deallocate(alloc, bti, sizeof(*bti), 0);
}

static void bti_init(struct silofs_btnode_info *bti,
                     const struct silofs_paddr *paddr)
{
	silofs_assert(!silofs_paddr_isnull(paddr));

	pni_init(&bti->btn_pni, paddr);
	bti->btn = NULL;
}

static void bti_fini(struct silofs_btnode_info *bti)
{
	pni_fini(&bti->btn_pni);
	bti->btn = NULL;
}

struct silofs_btnode_info *
silofs_bti_new(const struct silofs_paddr *paddr, struct silofs_alloc *alloc)
{
	struct silofs_btnode_info *bti;

	bti = bti_malloc(alloc);
	if (bti != NULL) {
		bti_init(bti, paddr);
	}
	return bti;
}

void silofs_bti_del(struct silofs_btnode_info *bti, struct silofs_alloc *alloc)
{
	bti_fini(bti);
	bti_free(bti, alloc);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_btleaf_info *bli_malloc(struct silofs_alloc *alloc)
{
	struct silofs_btleaf_info *bli = NULL;

	bli = silofs_allocate(alloc, sizeof(*bli), 0);
	return bli;
}

static void bli_free(struct silofs_btleaf_info *bli,
                     struct silofs_alloc *alloc)
{
	silofs_deallocate(alloc, bli, sizeof(*bli), 0);
}

static void bli_init(struct silofs_btleaf_info *bli,
                     const struct silofs_paddr *paddr)
{
	silofs_assert(!silofs_paddr_isnull(paddr));

	pni_init(&bli->btl_pni, paddr);
	bli->btl = NULL;
}

static void bli_fini(struct silofs_btleaf_info *bli)
{
	pni_fini(&bli->btl_pni);
	bli->btl = NULL;
}

struct silofs_btleaf_info *
silofs_bli_new(const struct silofs_paddr *paddr, struct silofs_alloc *alloc)
{
	struct silofs_btleaf_info *bli;

	bli = bli_malloc(alloc);
	if (bli != NULL) {
		bli_init(bli, paddr);
	}
	return bli;
}

void silofs_bli_del(struct silofs_btleaf_info *bli, struct silofs_alloc *alloc)
{
	bli_fini(bli);
	bli_free(bli, alloc);
}
