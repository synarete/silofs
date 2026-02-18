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
#ifndef SILOFS_STAGE_H_
#define SILOFS_STAGE_H_

#include "infra.h"
#include "addr.h"
#include "nodes.h"

struct silofs_env;

int silofs_spawn_uber(struct silofs_env *env, const struct silofs_pnptr *pnptr,
                      struct silofs_uber_info **out_ubi);

int silofs_stage_uber(struct silofs_env *env, const struct silofs_pnptr *pnptr,
                      struct silofs_uber_info **out_ubi);

int silofs_spawn_bldesc(struct silofs_env          *env,
                        const struct silofs_pnptr  *pnptr,
                        struct silofs_bldesc_info **out_bdi);

int silofs_stage_bldesc(struct silofs_env          *env,
                        const struct silofs_pnptr  *pnptr,
                        struct silofs_bldesc_info **out_bdi);

int silofs_spawn_btnode(struct silofs_env          *env,
                        const struct silofs_pnptr  *pnptr,
                        struct silofs_btnode_info **out_bti);

int silofs_stage_btnode(struct silofs_env          *env,
                        const struct silofs_pnptr  *pnptr,
                        struct silofs_btnode_info **out_bti);

int silofs_require_paddr(struct silofs_env         *env,
                         const struct silofs_paddr *paddr);

int silofs_destage_dirty(struct silofs_env *env);

#endif /* SILOFS_STAGE_H_ */
