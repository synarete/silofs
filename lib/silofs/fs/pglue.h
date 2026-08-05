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
#ifndef SILOFS_PGLUE_H_
#define SILOFS_PGLUE_H_

#include <silofs/infra.h>

/* stage operation control flags */
enum silofs_stg_mode {
	SILOFS_STG_NONE = 0,
	SILOFS_STG_CUR  = SILOFS_BIT(0), /* stage current (normal) */
	SILOFS_STG_COW  = SILOFS_BIT(1), /* copy-on-write */
	SILOFS_STG_RAW  = SILOFS_BIT(2), /* not-set-yet */
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_probe_super(const struct silofs_task_ctx *task);

int silofs_stage_super(const struct silofs_task_ctx *task,
                       enum silofs_stg_mode          stg_mode,
                       struct silofs_sbnode_info   **out_sbi);

int silofs_spawn_super(const struct silofs_task_ctx *task,
                       struct silofs_sbnode_info   **out_sbi);

int silofs_probe_spnode(const struct silofs_task_ctx *task,
                        const struct silofs_laddr    *laddr);

int silofs_stage_spnode_at(const struct silofs_task_ctx *task,
                           const struct silofs_laddr    *laddr,
                           enum silofs_stg_mode          stg_mode,
                           struct silofs_spnode_info   **out_spi);

int silofs_spawn_spnode_at(const struct silofs_task_ctx *task,
                           const struct silofs_laddr    *laddr,
                           struct silofs_spnode_info   **out_spi);

int silofs_stage_spnode_of(const struct silofs_task_ctx *task,
                           const struct silofs_laddr    *ref_laddr,
                           enum silofs_stg_mode          stg_mode,
                           struct silofs_spnode_info   **out_spi);

int silofs_probe_inode(const struct silofs_task_ctx *task,
                       const struct silofs_laddr    *laddr);

int silofs_stage_inode(const struct silofs_task_ctx *task,
                       const struct silofs_laddr    *laddr,
                       enum silofs_stg_mode          stg_mode,
                       struct silofs_inode_info    **out_ii);

int silofs_spawn_inode(const struct silofs_task_ctx *task,
                       struct silofs_inode_info    **out_ii);

int silofs_remove_inode(const struct silofs_task_ctx *task,
                        const struct silofs_laddr    *laddr);

int silofs_stage_xanode(const struct silofs_task_ctx *task,
                        const struct silofs_laddr    *laddr,
                        struct silofs_inode_info     *pii,
                        enum silofs_stg_mode          stg_mode,
                        struct silofs_xanode_info   **out_xai);

int silofs_spawn_xanode(const struct silofs_task_ctx *task,
                        struct silofs_inode_info     *pii,
                        struct silofs_xanode_info   **out_xai);

int silofs_remove_xanode(const struct silofs_task_ctx *task,
                         const struct silofs_laddr    *laddr,
                         struct silofs_inode_info     *pii);

int silofs_stage_symval(const struct silofs_task_ctx *task,
                        const struct silofs_laddr    *laddr,
                        struct silofs_inode_info     *pii,
                        enum silofs_stg_mode          stg_mode,
                        struct silofs_symval_info   **out_svi);

int silofs_spawn_symval(const struct silofs_task_ctx *task,
                        struct silofs_inode_info     *pii,
                        struct silofs_symval_info   **out_svi);

int silofs_remove_symval(const struct silofs_task_ctx *task,
                         const struct silofs_laddr    *laddr,
                         struct silofs_inode_info     *pii);

int silofs_stage_dtnode(const struct silofs_task_ctx *task,
                        const struct silofs_laddr    *laddr,
                        struct silofs_inode_info     *pii,
                        enum silofs_stg_mode          stg_mode,
                        struct silofs_dtnode_info   **out_dti);

int silofs_spawn_dtnode(const struct silofs_task_ctx *task,
                        struct silofs_inode_info     *pii,
                        struct silofs_dtnode_info   **out_dti);

int silofs_remove_dtnode(const struct silofs_task_ctx *task,
                         const struct silofs_laddr    *laddr,
                         struct silofs_inode_info     *pii);

int silofs_stage_ftnode(const struct silofs_task_ctx *task,
                        const struct silofs_laddr    *laddr,
                        struct silofs_inode_info     *pii,
                        enum silofs_stg_mode          stg_mode,
                        struct silofs_ftnode_info   **out_fti);

int silofs_spawn_ftnode(const struct silofs_task_ctx *task,
                        struct silofs_inode_info     *pii,
                        struct silofs_ftnode_info   **out_fti);

int silofs_remove_ftnode(const struct silofs_task_ctx *task,
                         const struct silofs_laddr    *laddr,
                         struct silofs_inode_info     *pii);

int silofs_claim_flnode(const struct silofs_task_ctx *task,
                        enum silofs_ltype ltype, struct silofs_inode_info *pii,
                        struct silofs_laddr *out_laddr);

int silofs_stage_flnode(const struct silofs_task_ctx *task,
                        const struct silofs_laddr    *laddr,
                        struct silofs_inode_info     *pii,
                        enum silofs_stg_mode          stg_mode,
                        struct silofs_flnode_info   **out_fli);

int silofs_remove_flnode(const struct silofs_task_ctx *task,
                         const struct silofs_laddr    *laddr,
                         struct silofs_inode_info     *pii);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_share_flnode(const struct silofs_task_ctx *task,
                        const struct silofs_laddr    *laddr,
                        struct silofs_inode_info     *pii);

int silofs_unshare_flnode(const struct silofs_task_ctx *task,
                          const struct silofs_laddr    *laddr,
                          struct silofs_inode_info     *pii);

int silofs_isshared_flnode(const struct silofs_task_ctx *task,
                           const struct silofs_laddr    *laddr,
                           struct silofs_inode_info *pii, bool *out_res);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_mark_unwritten_flnode(const struct silofs_task_ctx *task,
                                 const struct silofs_laddr    *laddr,
                                 struct silofs_inode_info     *pii);

int silofs_clear_unwritten_flnode(const struct silofs_task_ctx *task,
                                  const struct silofs_laddr    *laddr,
                                  struct silofs_inode_info     *pii);

int silofs_test_unwritten_flnode(const struct silofs_task_ctx *task,
                                 const struct silofs_laddr    *laddr,
                                 struct silofs_inode_info     *pii,
                                 bool                         *out_unwritten);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_spawn_take_lnode(const struct silofs_task_ctx *task,
                            enum silofs_ltype             ltype,
                            struct silofs_lnode_info    **out_lni);

int silofs_remove_give_lnode(const struct silofs_task_ctx   *task,
                             const struct silofs_lnode_info *lni);

int silofs_stage_curr_lnode(const struct silofs_task_ctx *task,
                            const struct silofs_laddr    *laddr,
                            struct silofs_lnode_info    **out_lni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_curr_sbi(const struct silofs_task_ctx *task,
                    struct silofs_sbnode_info   **out_sbi);

int silofs_flush_dirty_now(const struct silofs_task_ctx *task);

int silofs_try_flush_dirty(const struct silofs_task_ctx *task, int flags);

#endif /* SILOFS_PGLUE_H_ */
