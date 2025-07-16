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

struct silofs_bdesc_info;

struct silofs_bdesc_info *
silofs_bdi_from_pni(const struct silofs_pnode_info *pni);

struct silofs_bdesc_info *
silofs_bdi_new(const struct silofs_paddr *paddr, struct silofs_alloc *alloc);

void silofs_bdi_del(struct silofs_bdesc_info *bdi, struct silofs_alloc *alloc);

void silofs_bdi_dirtify(struct silofs_bdesc_info *bdi);

void silofs_bdi_undirtify(struct silofs_bdesc_info *bdi);

void silofs_bdi_set_dq(struct silofs_bdesc_info *bdi,
                       struct silofs_dirtyq     *dq);

#endif /* SILOFS_BDESC_H_ */
