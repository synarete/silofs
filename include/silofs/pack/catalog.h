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
#ifndef SILOFS_CATALOG_H_
#define SILOFS_CATALOG_H_


struct silofs_pack_desc {
	struct silofs_caddr    pd_caddr;
	struct silofs_laddr     pd_laddr;
};

struct silofs_pack_desc_info {
	struct silofs_list_head pdi_lh;
	struct silofs_pack_desc pd;
};

struct silofs_catalog {
	struct silofs_mdigest   cat_mdigest;
	struct silofs_listq     cat_descq;
	struct silofs_alloc    *cat_alloc;
	struct silofs_bytebuf   cat_bbuf;
	struct silofs_caddr     cat_caddr;
	size_t cat_capacity;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_pkdesc_init(struct silofs_pack_desc *pd,
                        const struct silofs_laddr *laddr);

void silofs_pkdesc_fini(struct silofs_pack_desc *pd);

void silofs_pkdesc_update_caddr(struct silofs_pack_desc *pd,
                                const struct silofs_mdigest *md,
                                const void *buf, size_t bsz);


void silofs_pkdesc128b_xtoh(const struct silofs_pack_desc256b *pdx,
                            struct silofs_pack_desc *pd);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_pdi_isbootrec(const struct silofs_pack_desc_info *pdi);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_catalog_init(struct silofs_catalog *catalog,
                        struct silofs_alloc *alloc);

void silofs_catalog_fini(struct silofs_catalog *catalog);


struct silofs_pack_desc_info *
silofs_catalog_add_desc(struct silofs_catalog *catalog,
                        const struct silofs_laddr *laddr);

void silofs_catalog_rm_desc(struct silofs_catalog *catalog,
                            struct silofs_pack_desc_info *pdi);

void silofs_catalog_clear_descq(struct silofs_catalog *catalog);

int silofs_catalog_encode(struct silofs_catalog *catalog);

void silofs_catalog_to_name(const struct silofs_catalog *catalog,
                            struct silofs_strbuf *out_name);

#endif /* SILOFS_CATALOG_H_ */
