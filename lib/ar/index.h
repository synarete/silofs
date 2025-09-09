/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#ifndef SILOFS_INDEX_H_
#define SILOFS_INDEX_H_

#include <silofs/ondisk.h>
#include <silofs/memalloc.h>
#include "addr.h"

struct silofs_ar_desc {
	struct silofs_baddr baddr;
	struct silofs_laddr laddr;
	size_t              len;
};

struct silofs_ab_info {
	struct silofs_baddr       ab_baddr;
	struct silofs_list_head   ab_lh;
	struct silofs_arix_block *ab;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ard_init(struct silofs_ar_desc     *ard,
		     const struct silofs_laddr *laddr, size_t len);

void silofs_ard_fini(struct silofs_ar_desc *ard);

void silofs_ard_update_baddr(struct silofs_ar_desc       *ard,
			     const struct silofs_mdigest *md,
			     const struct silofs_rovec   *rov);

void silofs_ard256b_htox(struct silofs_ar_desc256b   *ard256,
			 const struct silofs_ar_desc *ard);

void silofs_ard256b_xtoh(const struct silofs_ar_desc256b *ard256,
			 struct silofs_ar_desc           *ard);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_ab_info *
silofs_abi_new(struct silofs_alloc *alloc, const struct silofs_baddr *baddr);

void silofs_abi_del(struct silofs_ab_info *abi, struct silofs_alloc *alloc);

#endif /* SILOFS_INDEX_H_ */
