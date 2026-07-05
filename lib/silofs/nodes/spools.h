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
#ifndef SILOFS_SPOOLS_H_
#define SILOFS_SPOOLS_H_

/* logical address span */
struct silofs_lspan {
	off_t  off;
	size_t len;
};

/* space mapping range entry in AVL tree */
struct silofs_lsp_entry {
	struct silofs_avl_node avl_node;
	struct silofs_lspan    lspan;
};

/* fast queue of free logical ranges */
struct silofs_lspoolq {
	struct silofs_lspan lspan[128];
	uint32_t            count;
	uint32_t            objsz;
};

/* in-memory queue of free logical-space */
struct silofs_lspool {
	struct silofs_lspoolq lspq;
	struct silofs_avl     avl;
	struct silofs_alloc  *alloc;
};

/* in-memory logical-space addresses pool */
struct silofs_lspools {
	struct silofs_lspool lspool[SILOFS_LTYPE_LAST - 1];
};

int silofs_lspools_init(struct silofs_lspools *lspools,
                        struct silofs_alloc   *alloc);

void silofs_lspools_fini(struct silofs_lspools *lspools);

void silofs_lspools_drop(struct silofs_lspools *lspools);

int silofs_lspools_push(struct silofs_lspools     *lspools,
                        const struct silofs_laddr *laddr);

int silofs_lspools_pull(struct silofs_lspools *lspools,
                        enum silofs_ltype      ltype,
                        struct silofs_laddr   *out_laddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/* single entry of in-memory paddr queue */
struct silofs_pspool_entry {
	struct silofs_list_head lh;
	struct silofs_paddr     paddr;
};

/* in-memory queue of free paddr by ltype */
struct silofs_pspool {
	struct silofs_listq  listq;
	struct silofs_alloc *alloc;
};

struct silofs_pspools {
	struct silofs_pspool bn[SILOFS_LTYPE_LAST - 1];
	struct silofs_pspool vn[SILOFS_LTYPE_LAST - 1];
};

void silofs_pspools_init(struct silofs_pspools *pspools,
                         struct silofs_alloc   *alloc);

void silofs_pspools_fini(struct silofs_pspools *pspools);

void silofs_pspools_drop(struct silofs_pspools *pspools);

int silofs_pspools_push(struct silofs_pspools     *pspools,
                        const struct silofs_paddr *paddr);

int silofs_pspools_pull(struct silofs_pspools     *pspools,
                        const struct silofs_stype *stype,
                        struct silofs_paddr       *out_paddr);

#endif /* SILOFS_SPOOLS_H_ */
