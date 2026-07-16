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

int silofs_spawn_uber(const struct silofs_exec_ctx *ectx,
                      const struct silofs_pnptr    *pnptr,
                      struct silofs_uber_info     **out_ubi);

int silofs_stage_uber(const struct silofs_exec_ctx *ectx,
                      const struct silofs_pnptr    *pnptr,
                      struct silofs_uber_info     **out_ubi);

int silofs_spawn_bldesc(const struct silofs_exec_ctx *ectx,
                        const struct silofs_pnptr    *pnptr,
                        struct silofs_bldesc_info   **out_bdi);

int silofs_stage_bldesc(const struct silofs_exec_ctx *ectx,
                        const struct silofs_pnptr    *pnptr,
                        struct silofs_bldesc_info   **out_bdi);

int silofs_spawn_btnode(const struct silofs_exec_ctx *ectx,
                        const struct silofs_pnptr    *pnptr,
                        struct silofs_btnode_info   **out_bti);

int silofs_stage_btnode(const struct silofs_exec_ctx *ectx,
                        const struct silofs_pnptr    *pnptr,
                        struct silofs_btnode_info   **out_bti);

int silofs_spawn_lnode_with(const struct silofs_exec_ctx *ectx,
                            const struct silofs_laddr    *laddr,
                            const struct silofs_pnptr    *pnptr,
                            struct silofs_lnode_info    **out_lni);

int silofs_claim_lnode_pspace(const struct silofs_exec_ctx *ectx,
                              const struct silofs_laddr    *laddr,
                              const struct silofs_pnptr    *pnptr);

int silofs_stage_lnode_with(const struct silofs_exec_ctx *ectx,
                            const struct silofs_laddr    *laddr,
                            const struct silofs_pnptr    *pnptr,
                            enum silofs_lspacef           spacef,
                            struct silofs_lnode_info    **out_lni);

int silofs_detach_lnode_at(const struct silofs_exec_ctx *ectx,
                           const struct silofs_laddr    *laddr,
                           const struct silofs_pnptr    *pnptr);

int silofs_require_paddr(const struct silofs_exec_ctx *ectx,
                         const struct silofs_paddr    *paddr);

int silofs_destage_dirty_nodes(const struct silofs_exec_ctx *ectx);

#endif /* SILOFS_STAGE_H_ */
