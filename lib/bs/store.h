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
#ifndef SILOFS_STORE_H_
#define SILOFS_STORE_H_

#include "infra.h"
#include "addr.h"
#include "nodes.h"

struct silofs_env;

int silofs_spawn_uber(struct silofs_env *env, const struct silofs_paddr *paddr,
                      struct silofs_uber_info **out_ubi);

int silofs_stage_uber(struct silofs_env *env, const struct silofs_paddr *paddr,
                      struct silofs_uber_info **out_ubi);

int silofs_spawn_btnode(struct silofs_env          *env,
                        const struct silofs_paddr  *paddr,
                        struct silofs_btnode_info **out_bti);

int silofs_stage_btnode(struct silofs_env          *env,
                        const struct silofs_paddr  *paddr,
                        struct silofs_btnode_info **out_bti);

int silofs_destage_dirty(struct silofs_env *env);

#endif /* SILOFS_STORE_H_ */
