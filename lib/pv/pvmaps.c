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



/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_pvnode_info *pni_malloc(struct silofs_alloc *alloc)
{
	struct silofs_pvnode_info *pni = NULL;

	pni = silofs_allocate(alloc, sizeof(*pni), 0);
	return pni;
}

static void pni_free(struct silofs_pvnode_info *pni,
                     struct silofs_alloc *alloc)
{
	silofs_deallocate(alloc, pni, sizeof(*pni), 0);
}

static void pni_init(struct silofs_pvnode_info *pni,
                     const struct silofs_paddr *paddr)
{
	silofs_assert(!silofs_paddr_isnull(paddr));

	paddr_assign(&pni->pn_paddr, paddr);
	list_head_init(&pni->pn_htb_lh);
	list_head_init(&pni->pn_lru_lh);
	pni->pn = NULL;
	pni->pn_psenv = NULL;
}

static void pni_fini(struct silofs_pvnode_info *pni)
{
	list_head_fini(&pni->pn_htb_lh);
	list_head_fini(&pni->pn_lru_lh);
	pni->pn = NULL;
	pni->pn_psenv = NULL;
}


struct silofs_pvnode_info *
silofs_pni_new(const struct silofs_paddr *paddr, struct silofs_alloc *alloc)
{
	struct silofs_pvnode_info *pni;

	pni = pni_malloc(alloc);
	if (pni != NULL) {
		pni_init(pni, paddr);
	}
	return pni;
}

void silofs_pni_del(struct silofs_pvnode_info *pni, struct silofs_alloc *alloc)
{
	pni_fini(pni);
	pni_free(pni, alloc);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_pvmap_init(struct silofs_pvmap *pvmap, struct silofs_alloc *alloc)
{
	const unsigned int cap = 8191; /* TODO: cap based on memory size */

	silofs_memzero(pvmap, sizeof(*pvmap));
	silofs_listq_init(&pvmap->pvm_lru);
	pvmap->pvm_htbl = silofs_lista_new(alloc, cap);
	if (pvmap->pvm_htbl == NULL) {
		return -SILOFS_ENOMEM;
	}
	pvmap->pvm_htbl_cap = cap;
	pvmap->pvm_htbl_sz = 0;
	pvmap->pvm_alloc = alloc;
	return 0;
}

void silofs_pvmap_fini(struct silofs_pvmap *pvmap)
{
	silofs_listq_fini(&pvmap->pvm_lru);
	if (pvmap->pvm_htbl != NULL) {
		silofs_lista_del(pvmap->pvm_htbl,
		                 pvmap->pvm_htbl_cap, pvmap->pvm_alloc);
		pvmap->pvm_htbl_cap = 0;
		pvmap->pvm_htbl_sz = 0;
	}
	pvmap->pvm_alloc = NULL;
}
