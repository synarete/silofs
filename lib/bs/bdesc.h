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
#ifndef SILOFS_BDESC_H_
#define SILOFS_BDESC_H_

#include "infra.h"
#include "addr.h"
#include "pnode.h"

/* blob-descriptor node */
struct silofs_bdesc_info {
	struct silofs_pnode_info bd_pni;
	struct silofs_blob_desc *bd;
};

struct silofs_bdesc_info *
silofs_bdi_from_pni(const struct silofs_pnode_info *pni);

struct silofs_bdesc_info *
silofs_bdi_new(const struct silofs_paddr *paddr, struct silofs_alloc *alloc);

void silofs_bdi_del(struct silofs_bdesc_info *bdi, struct silofs_alloc *alloc);

void silofs_bdi_dirtify(struct silofs_bdesc_info *bdi);

void silofs_bdi_undirtify(struct silofs_bdesc_info *bdi);

void silofs_bdi_set_dq(struct silofs_bdesc_info *bdi,
                       struct silofs_dirtyq     *dq);

void silofs_bdi_setup_spawned(struct silofs_bdesc_info *bdi,
                              enum silofs_mtype         refmtype);

void silofs_bdi_set_refblob(struct silofs_bdesc_info   *bdi,
                            const struct silofs_blobid *blobid);

int silofs_bdi_find_free(const struct silofs_bdesc_info *bdi,
                         struct silofs_paddr            *out_paddr);

int silofs_bdi_test_free(const struct silofs_bdesc_info *bdi,
                         const struct silofs_paddr      *paddr);

int silofs_bdi_mark_free(struct silofs_bdesc_info  *bdi,
                         const struct silofs_paddr *paddr);

int silofs_bdi_mark_used(struct silofs_bdesc_info  *bdi,
                         const struct silofs_paddr *paddr);

#endif /* SILOFS_BDESC_H_ */
