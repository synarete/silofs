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

/* in-memory short lifo of previously-allocated now-free space */
struct silofs_splifo {
	loff_t spl_lifo[512];
	unsigned int spl_size;
	unsigned int spl_ulen;
};

/* in-memory map of previously-allocated now-free space */
struct silofs_spamap {
	struct silofs_splifo    spa_lifo;
	struct silofs_alloc    *spa_alloc;
	struct silofs_avl       spa_avl;
	unsigned int            spa_cap_max;
	enum silofs_stype       spa_stype;
};

/* in-mempry map of previously-allocated now-free space byte stype */
struct silofs_spamaps {
	struct silofs_spamap    spa_data1k;
	struct silofs_spamap    spa_data4k;
	struct silofs_spamap    spa_databk;
	struct silofs_spamap    spa_inode;
	struct silofs_spamap    spa_xanode;
	struct silofs_spamap    spa_dtnode;
	struct silofs_spamap    spa_ftnode;
	struct silofs_spamap    spa_symval;
};

/* key of in-memory uaddress-mapping */
struct silofs_uakey {
	loff_t                  voff;
	enum silofs_height      height;
	enum silofs_stype       vspace;
};

/* in-memory mapping of uaddr by (voff,height,vspace) */
struct silofs_uamap {
	struct silofs_listq      uam_lru;
	struct silofs_alloc     *uam_alloc;
	struct silofs_list_head *uam_htbl;
	unsigned int             uam_htbl_cap;
	unsigned int             uam_htbl_sz;
};


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_list_head *
silofs_lista_new(struct silofs_alloc *alloc, size_t nelems);

void silofs_lista_del(struct silofs_list_head *lista, size_t nelems,
                      struct silofs_alloc *alloc);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_spamaps_init(struct silofs_spamaps *spam,
                        struct silofs_alloc *alloc);

void silofs_spamaps_fini(struct silofs_spamaps *spam);

void silofs_spamaps_drop(struct silofs_spamaps *spam);

int silofs_spamaps_trypop(struct silofs_spamaps *spam, enum silofs_stype stype,
                          size_t len, loff_t *out_voff);

int silofs_spamaps_store(struct silofs_spamaps *spam,
                         enum silofs_stype stype, loff_t voff, size_t len);

int silofs_spamaps_baseof(const struct silofs_spamaps *spam,
                          enum silofs_stype stype, loff_t voff, loff_t *out);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_uakey_setup(struct silofs_uakey *uakey, loff_t voff,
                        enum silofs_height height, enum silofs_stype vspace);

void silofs_uakey_setup_by(struct silofs_uakey *uakey,
                           const struct silofs_uaddr *uaddr);

void silofs_uakey_setup_by2(struct silofs_uakey *uakey,
                            const struct silofs_vrange *vrange,
                            enum silofs_stype vspace);


int silofs_uamap_init(struct silofs_uamap *uamap, struct silofs_alloc *alloc);

void silofs_uamap_fini(struct silofs_uamap *uamap);

const struct silofs_uaddr *
silofs_uamap_lookup(const struct silofs_uamap *uamap,
                    const struct silofs_uakey *uakey);

int silofs_uamap_remove(struct silofs_uamap *uamap,
                        const struct silofs_uaddr *uaddr);

int silofs_uamap_insert(struct silofs_uamap *uamap,
                        const struct silofs_uaddr *uaddr);

void silofs_uamap_drop_all(struct silofs_uamap *uamap);

#endif /* SILOFS_SPXMAP_H_ */
