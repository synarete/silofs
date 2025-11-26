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
#include "infra.h"
#include "crypt.h"
#include "addr.h"

struct silofs_ar_desc {
	struct silofs_paddr paddr;
	struct silofs_laddr laddr;
	size_t              len;
};

struct silofs_ab_base {
	const struct silofs_cipher  *enc_cipher;
	const struct silofs_cipher  *dec_cipher;
	const struct silofs_mdigest *mdigest;
	struct silofs_repo          *repo;
};

struct silofs_ab_info {
	struct silofs_ab_base     ab_base;
	struct silofs_paddr       ab_paddr;
	struct silofs_arix_block *ab;
	struct silofs_arix_block *ab_enc;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_ab_info *
silofs_abi_new(struct silofs_alloc *alloc, const struct silofs_ab_base *base);

void silofs_abi_del(struct silofs_ab_info *abi, struct silofs_alloc *alloc);

size_t silofs_abi_ndescs(const struct silofs_ab_info *abi);

bool silofs_abi_isfull(const struct silofs_ab_info *abi);

void silofs_abi_set_btime(struct silofs_ab_info *abi,
                          const struct timespec *ts);

void silofs_abi_get_paddr(const struct silofs_ab_info *abi,
                          struct silofs_paddr         *out_paddr);

void silofs_abi_set_paddr(struct silofs_ab_info     *abi,
                          const struct silofs_paddr *paddr);

void silofs_abi_set_next(struct silofs_ab_info       *abi,
                         const struct silofs_ab_info *abi_next);

void silofs_abi_get_next(const struct silofs_ab_info *abi,
                         struct silofs_paddr         *out_paddr);

void silofs_abi_calc_desc(const struct silofs_ab_info *abi,
                          const struct silofs_laddr   *laddr,
                          const struct silofs_rovec   *rovec,
                          struct silofs_ar_desc       *out_ard);

int silofs_abi_append_desc(struct silofs_ab_info       *abi,
                           const struct silofs_ar_desc *ard);

int silofs_abi_fetch_desc(const struct silofs_ab_info *abi, size_t slot,
                          struct silofs_ar_desc *out_ard);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_store_arix_block(struct silofs_ab_info      *abi,
                            const struct silofs_civkey *civkey);

int silofs_fetch_arix_block(struct silofs_ab_info      *abi,
                            const struct silofs_civkey *civkey);

#endif /* SILOFS_INDEX_H_ */
