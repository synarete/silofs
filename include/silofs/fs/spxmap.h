/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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

/* in-mempry map of previously-allocated now-free space */
struct silofs_spamap {
	struct silofs_alloc_if *spa_alif;
	struct silofs_avl       spa_avl;
	enum silofs_stype       spa_stype;
	unsigned int            spa_cap_max;
};

/* in-mempry map of previously-allocated now-free space byte stype */
struct silofs_spamaps {
	struct silofs_spamap    spa_data1k;
	struct silofs_spamap    spa_data4k;
	struct silofs_spamap    spa_databk;
	struct silofs_spamap    spa_itnode;
	struct silofs_spamap    spa_inode;
	struct silofs_spamap    spa_xanode;
	struct silofs_spamap    spa_dtnode;
	struct silofs_spamap    spa_ftnode;
	struct silofs_spamap    spa_symval;
};

/* in-memory map of unodes indexed by (treeid,voff,height) tuple */
struct silofs_unomap {
	struct silofs_list_head *uno_htbl;
	unsigned int            uno_htbl_cap;
	unsigned int            uno_htbl_sz;
};


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_list_head *
silofs_lista_new(struct silofs_alloc_if *alif, size_t nelems);

void silofs_lista_del(struct silofs_list_head *lista, size_t nelems,
                      struct silofs_alloc_if *alif);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_spamaps_init(struct silofs_spamaps *spam,
                        struct silofs_alloc_if *alif);

void silofs_spamaps_fini(struct silofs_spamaps *spam);

void silofs_spamaps_drop(struct silofs_spamaps *spam);

int silofs_spamaps_trypop(struct silofs_spamaps *spam, enum silofs_stype stype,
                          size_t len, loff_t *out_voff);

int silofs_spamaps_store(struct silofs_spamaps *spam,
                         enum silofs_stype stype, loff_t voff, size_t len);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_unomap_init(struct silofs_unomap *unom,
                       struct silofs_alloc_if *alif);

void silofs_unomap_fini(struct silofs_unomap *unom,
                        struct silofs_alloc_if *alif);

void silofs_unomap_insert(struct silofs_unomap *unom,
                          struct silofs_unode_info *ui);

void silofs_unomap_remove(struct silofs_unomap *unom,
                          struct silofs_unode_info *ui);

struct silofs_unode_info *
silofs_unomap_lookup(const struct silofs_unomap *unom,
                     const struct silofs_taddr *taddr);

#endif /* SILOFS_SPXMAP_H_ */
