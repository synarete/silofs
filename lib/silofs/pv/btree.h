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

#include <silofs/infra.h>
#include <silofs/addr.h>

struct silofs_task_ctx;

int silofs_resolve_vtop(struct silofs_task_ctx    *task,
                        const struct silofs_vaddr *vaddr,
                        struct silofs_pnptr       *out_pnptr);

int silofs_insert_vtop(struct silofs_task_ctx    *task,
                       const struct silofs_vaddr *vaddr,
                       const struct silofs_pnptr *pnptr);

int silofs_update_vtop(struct silofs_task_ctx    *task,
                       const struct silofs_vaddr *vaddr,
                       const struct silofs_pnptr *pnptr);

int silofs_remove_vtop(struct silofs_task_ctx    *task,
                       const struct silofs_vaddr *vaddr);

#endif /* SILOFS_BTREE_H_ */
