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
#include "bstore.h"

struct silofs_ar_cargs {
	struct silofs_nmeta          nmeta;
	const struct silofs_cipher  *cipher;
	const struct silofs_mdigest *mdigest;
};

struct silofs_ar_desc {
	struct silofs_paddr paddr;
	struct silofs_laddr laddr;
	size_t              len;
};

struct silofs_arnode_info {
	struct silofs_pmeta      arn_pmeta;
	struct silofs_arix_node *arn;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_arnode_info *
silofs_ari_new(struct silofs_alloc *alloc, const struct silofs_pmeta *pmeta);

void silofs_ari_del(struct silofs_arnode_info *ari,
                    struct silofs_alloc       *alloc);

size_t silofs_ari_ndescs(const struct silofs_arnode_info *ari);

bool silofs_ari_isfull(const struct silofs_arnode_info *ari);

void silofs_ari_set_btime(struct silofs_arnode_info *ari,
                          const struct timespec     *ts);

void silofs_ari_get_paddr(const struct silofs_arnode_info *ari,
                          struct silofs_paddr             *out_paddr);

void silofs_ari_set_paddr(struct silofs_arnode_info *ari,
                          const struct silofs_paddr *paddr);

void silofs_ari_set_next(struct silofs_arnode_info *ari,
                         const struct silofs_pmeta *pmeta);

void silofs_ari_get_next(const struct silofs_arnode_info *ari,
                         struct silofs_pmeta             *out_pmeta);

int silofs_ari_append_desc(struct silofs_arnode_info   *ari,
                           const struct silofs_ar_desc *ard);

int silofs_ari_fetch_desc(const struct silofs_arnode_info *ari, size_t slot,
                          struct silofs_ar_desc *out_ard);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_export_arix_node(const struct silofs_arnode_info *ari,
                            const struct silofs_ar_cargs    *ar_cargs,
                            struct silofs_arix_node         *arn_enc);

int silofs_save_arix_node(struct silofs_filos           *filos,
                          const struct silofs_paddr     *paddr,
                          const struct silofs_arix_node *arn_enc);

int silofs_import_arix_node(struct silofs_arnode_info    *ari,
                            const struct silofs_ar_cargs *ar_cargs,
                            struct silofs_arix_node      *arn_enc);

int silofs_load_arix_node(struct silofs_filos       *filos,
                          const struct silofs_paddr *paddr,
                          struct silofs_arix_node   *arn_enc);

void silofs_calc_ar_desc(const struct silofs_mdigest *mdigest,
                         const struct silofs_laddr   *laddr,
                         const struct silofs_rovec   *rovec,
                         struct silofs_ar_desc       *out_ard);

void silofs_calc_arix_paddr(const struct silofs_arix_node *arn_enc,
                            const struct silofs_mdigest   *mdigest,
                            struct silofs_paddr           *out_paddr);

int silofs_verify_arix_paddr(const struct silofs_arix_node *arn_enc,
                             const struct silofs_mdigest   *mdigest,
                             const struct silofs_paddr     *paddr);

#endif /* SILOFS_INDEX_H_ */
