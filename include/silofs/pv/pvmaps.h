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
#ifndef SILOFS_PVMAPS_H_
#define SILOFS_PVMAPS_H_


struct silofs_pvmap {
	struct silofs_alloc            *pvm_alloc;
	struct silofs_listq             pvm_lru;
	struct silofs_list_head        *pvm_htbl;
	size_t                          pvm_htbl_cap;
	size_t                          pvm_htbl_sz;
};


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_pvmap_init(struct silofs_pvmap *pvmap, struct silofs_alloc *alloc);

void silofs_pvmap_fini(struct silofs_pvmap *pvmap);

#endif /* SILOFS_PVMAPS_H_ */
