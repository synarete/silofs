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
 *
 * Silofs is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
#ifndef SILOFS_PVMAPS_H_
#define SILOFS_PVMAPS_H_

struct silofs_psenv;


struct silofs_pvnode_info {
	struct silofs_paddr             pn_paddr;
	struct silofs_list_head         pn_htb_lh;
	struct silofs_list_head         pn_lru_lh;
	struct silofs_pvmap_node       *pn;
	struct silofs_psenv            *pn_psenv;
};

struct silofs_pvmap {
	struct silofs_alloc            *pvm_alloc;
	struct silofs_listq             pvm_lru;
	struct silofs_list_head        *pvm_htbl;
	size_t                          pvm_htbl_cap;
	size_t                          pvm_htbl_sz;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_pvnode_info *
silofs_pni_new(const struct silofs_paddr *paddr, struct silofs_alloc *alloc);

void silofs_pni_del(struct silofs_pvnode_info *pni,
                    struct silofs_alloc *alloc);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_pvmap_init(struct silofs_pvmap *pvmap, struct silofs_alloc *alloc);

void silofs_pvmap_fini(struct silofs_pvmap *pvmap);

#endif /* SILOFS_PVMAPS_H_ */
