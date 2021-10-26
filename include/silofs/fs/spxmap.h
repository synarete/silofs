/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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
#ifndef SILOFS_SPXMAP_H_
#define SILOFS_SPXMAP_H_

#include <silofs/infra.h>

/* in-mempry map of free vspace */
struct silofs_spamap {
	struct silofs_alloc_if *spm_alif;
	struct silofs_avl       spm_avl;
	enum silofs_stype       spm_stype;
	unsigned int            spm_cap;
};

/* vspace-allocation map of previously claimed-and-free ranges */
struct silofs_spvmap {
	struct silofs_spamap    spv_data1k;
	struct silofs_spamap    spv_data4k;
	struct silofs_spamap    spv_databk;
	struct silofs_spamap    spv_itnode;
	struct silofs_spamap    spv_inode;
	struct silofs_spamap    spv_xanode;
	struct silofs_spamap    spv_dtnode;
	struct silofs_spamap    spv_ftnode;
	struct silofs_spamap    spv_symval;
};

/* in-memory map of tree unodes indexed by (treeid,voff,height) tuple */
struct silofs_sptmap {
	struct silofs_list_head *spt_htbl;
	unsigned int            spt_htbl_cap;
	unsigned int            spt_htbl_sz;
};


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_list_head *
silofs_lista_new(struct silofs_alloc_if *alif, size_t nelems);

void silofs_lista_del(struct silofs_list_head *lista, size_t nelems,
                      struct silofs_alloc_if *alif);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_spvmap_init(struct silofs_spvmap *spvm,
                       struct silofs_alloc_if *alif);

void silofs_spvmap_fini(struct silofs_spvmap *spvm);

void silofs_spvmap_drop(struct silofs_spvmap *spvm);

int silofs_spvmap_trypop(struct silofs_spvmap *spvm, enum silofs_stype stype,
                         struct silofs_vaddr *out_vaddr);

int silofs_spvmap_store(struct silofs_spvmap *spvm,
                        const struct silofs_vaddr *vaddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_sptmap_init(struct silofs_sptmap *sptm,
                       struct silofs_alloc_if *alif);

void silofs_sptmap_fini(struct silofs_sptmap *sptm,
                        struct silofs_alloc_if *alif);

void silofs_sptmap_insert(struct silofs_sptmap *sptm,
                          struct silofs_unode_info *ui);

void silofs_sptmap_remove(struct silofs_sptmap *sptm,
                          struct silofs_unode_info *ui);

struct silofs_unode_info *
silofs_sptmap_lookup(const struct silofs_sptmap *sptm,
                     const struct silofs_taddr *taddr);

#endif /* SILOFS_SPXMAP_H_ */
