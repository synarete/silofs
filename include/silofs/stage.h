/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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

#include <silofs/infra.h>


bool silofs_sbi_ismutable_blobid(const struct silofs_sb_info *sbi,
                                 const struct silofs_blobid *blobid);

bool silofs_sbi_ismutable_oaddr(const struct silofs_sb_info *sbi,
                                const struct silofs_oaddr *oaddr);

int silofs_stage_spmaps_at(struct silofs_task *task,
                           const struct silofs_vaddr *vaddr,
                           enum silofs_stage_mode stg_mode,
                           struct silofs_spnode_info **out_sni,
                           struct silofs_spleaf_info **out_sli);

int silofs_stage_spnode1_at(struct silofs_task *task,
                            const struct silofs_vaddr *vaddr,
                            enum silofs_stage_mode stg_mode,
                            struct silofs_spnode_info **out_sni);

int silofs_require_spmaps_at(struct silofs_task *task,
                             const struct silofs_vaddr *vaddr,
                             enum silofs_stage_mode stg_mode,
                             struct silofs_spnode_info **out_sni,
                             struct silofs_spleaf_info **out_sli);

int silofs_stage_vnode_at(struct silofs_task *task,
                          const struct silofs_vaddr *vaddr,
                          enum silofs_stage_mode stg_mode,
                          silofs_dqid_t dqid, bool verify_view,
                          struct silofs_vnode_info **out_vi);

int silofs_stage_inode_at(struct silofs_task *task, ino_t ino,
                          const struct silofs_vaddr *vaddr,
                          enum silofs_stage_mode stg_mode,
                          struct silofs_inode_info **out_ii);

int silofs_resolve_voaddr_of(struct silofs_task *task,
                             const struct silofs_vaddr *vaddr,
                             enum silofs_stage_mode stg_mode,
                             struct silofs_voaddr *out_voa);

int silofs_resolve_oaddr_of(struct silofs_task *task,
                            const struct silofs_vaddr *vaddr,
                            enum silofs_stage_mode stg_mode,
                            struct silofs_oaddr *out_oaddr);

int silofs_require_stable_at(struct silofs_task *task,
                             const struct silofs_vaddr *vaddr);

int silofs_check_stable_at(struct silofs_task *task,
                           const struct silofs_vaddr *vaddr);

#endif /* SILOFS_STAGE_H_ */
