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

struct silofs_mdigest;

struct silofs_pack_desc {
	struct silofs_hash256   pd_hash;
	struct silofs_laddr     pd_laddr;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_pkdesc_init(struct silofs_pack_desc *pd,
                        const struct silofs_laddr *laddr);

void silofs_pkdesc_fini(struct silofs_pack_desc *pd);

void silofs_pkdesc_to_name(const struct silofs_pack_desc *pd,
                           struct silofs_strbuf *out_name);

void silofs_pkdesc_update_hash(struct silofs_pack_desc *pd,
                               const struct silofs_mdigest *md,
                               const void *buf, size_t bsz);


void silofs_pkdesc128b_htox(struct silofs_pack_desc128b *pdx,
                            const struct silofs_pack_desc *pd);

void silofs_pkdesc128b_xtoh(const struct silofs_pack_desc128b *pdx,
                            struct silofs_pack_desc *pd);

#endif /* SILOFS_CATALOG_H_ */
