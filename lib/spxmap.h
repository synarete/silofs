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
#ifndef SILOFS_SPXMAP_H_
#define SILOFS_SPXMAP_H_

#include <silofs/infra.h>

/* short lifo of previously-allocated now-free space-addresses */
struct silofs_spalifo {
	loff_t   sal_lifo[63];
	uint32_t sal_size;
	uint32_t sal_ulen;
};

/* map of previously-allocated now-free space (in-memory only) */
struct silofs_spamap {
	struct silofs_spalifo spa_lifo;
	struct silofs_alloc  *spa_alloc;
	struct silofs_avl     spa_avl;
	loff_t                spa_hint;
	unsigned int          spa_cap_max;
	enum silofs_ltype     spa_ltype;
};

/* map of previously-allocated now-free space-addresses by ltype */
struct silofs_spamaps {
	struct silofs_spamap spa_data1k;
	struct silofs_spamap spa_data4k;
	struct silofs_spamap spa_databk;
	struct silofs_spamap spa_inode;
	struct silofs_spamap spa_xanode;
	struct silofs_spamap spa_dtnode;
	struct silofs_spamap spa_ftnode;
	struct silofs_spamap spa_symval;
};

/* key of in-memory uaddress-mapping */
struct silofs_uakey {
	loff_t             voff;
	enum silofs_height height;
	enum silofs_ltype  vspace;
};

/* in-memory mapping of uaddr by (voff,height,vspace) */
struct silofs_uamap {
	struct silofs_listq      uam_lru;
	struct silofs_alloc     *uam_alloc;
	struct silofs_list_head *uam_htbl;
	uint32_t                 uam_htbl_cap;
	uint32_t                 uam_htbl_sz;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_spamaps_init(struct silofs_spamaps *spam,
                        struct silofs_alloc   *alloc);

void silofs_spamaps_fini(struct silofs_spamaps *spam);

void silofs_spamaps_drop(struct silofs_spamaps *spam);

int silofs_spamaps_trypop(struct silofs_spamaps *spam, enum silofs_ltype ltype,
                          size_t len, loff_t *out_voff);

int silofs_spamaps_store(struct silofs_spamaps *spam, enum silofs_ltype ltype,
                         loff_t voff, size_t len);

int silofs_spamaps_baseof(const struct silofs_spamaps *spam,
                          enum silofs_ltype ltype, loff_t voff, loff_t *out);

loff_t silofs_spamaps_get_hint(const struct silofs_spamaps *spam,
                               enum silofs_ltype            ltype);

void silofs_spamaps_set_hint(struct silofs_spamaps *spam,
                             enum silofs_ltype ltype, loff_t off);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_uakey_setup_by(struct silofs_uakey       *uakey,
                           const struct silofs_uaddr *uaddr);

void silofs_uakey_setup_by2(struct silofs_uakey        *uakey,
                            const struct silofs_vrange *vrange,
                            enum silofs_ltype           vspace);

int silofs_uamap_init(struct silofs_uamap *uamap, struct silofs_alloc *alloc);

void silofs_uamap_fini(struct silofs_uamap *uamap);

const struct silofs_uaddr *
silofs_uamap_lookup(const struct silofs_uamap *uamap,
                    const struct silofs_uakey *uakey);

void silofs_uamap_remove(struct silofs_uamap       *uamap,
                         const struct silofs_uakey *uakey);

int silofs_uamap_insert(struct silofs_uamap       *uamap,
                        const struct silofs_uaddr *uaddr);

void silofs_uamap_drop_all(struct silofs_uamap *uamap);

bool silofs_uamap_drop_lru(struct silofs_uamap *uamap);

#endif /* SILOFS_SPXMAP_H_ */
