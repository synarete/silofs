/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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
#ifndef SILOFS_BTREE_H_
#define SILOFS_BTREE_H_

struct silofs_btree_path {
	struct silofs_btnode_info *bti[SILOFS_BTREE_HEIGHT_MAX];
	unsigned int               cnt;
};

int silofs_resolve_ltop_bpath(const struct silofs_pexec_ctx *pexec,
                              const struct silofs_laddr     *laddr,
                              struct silofs_btree_path      *out_bpath);

int silofs_resolve_ltop_parent(const struct silofs_pexec_ctx *pexec,
                               const struct silofs_laddr     *laddr,
                               const struct silofs_paddr     *paddr,
                               struct silofs_pnptr           *out_pnptr);

int silofs_resolve_ltop_btleaf(const struct silofs_pexec_ctx *pexec,
                               const struct silofs_laddr     *laddr,
                               struct silofs_pnptr           *out_pnptr);

int silofs_resolve_ltop_mapping(const struct silofs_pexec_ctx *pexec,
                                const struct silofs_laddr     *laddr,
                                struct silofs_pnptr           *out_pnptr);

int silofs_insert_ltop_mapping(const struct silofs_pexec_ctx *pexec,
                               const struct silofs_laddr     *laddr,
                               const struct silofs_pnptr     *pnptr);

int silofs_update_ltop_mapping(const struct silofs_pexec_ctx *pexec,
                               const struct silofs_laddr     *laddr,
                               const struct silofs_pnptr     *pnptr);

int silofs_remove_ltop_mapping(const struct silofs_pexec_ctx *pexec,
                               const struct silofs_laddr     *laddr);

#endif /* SILOFS_BTREE_H_ */
