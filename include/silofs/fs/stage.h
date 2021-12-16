/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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

int silofs_sbi_stage_spnode(struct silofs_sb_info *sbi, loff_t voff,
                            enum silofs_stage_flags stg_flags,
                            struct silofs_spnode_info **out_sni);

int silofs_sbi_stage_child_spnode(struct silofs_sb_info *sbi, loff_t voff,
                                  struct silofs_spnode_info *sni_parent,
                                  enum silofs_stage_flags stg_flags,
                                  struct silofs_spnode_info **out_sni);

int silofs_sbi_stage_spleaf(struct silofs_sb_info *sbi, loff_t voff,
                            enum silofs_stage_flags stg_flags,
                            struct silofs_spleaf_info **out_sli);

int silofs_sbi_stage_spleaf_of(struct silofs_sb_info *sbi,
                               struct silofs_spnode_info *sni, loff_t voff,
                               enum silofs_stage_flags stg_flags,
                               struct silofs_spleaf_info **out_sli);

int silofs_sbi_require_spmaps_at(struct silofs_sb_info *sbi,
                                 const struct silofs_vaddr *vaddr,
                                 enum silofs_stage_flags stg_flags);

int silofs_sbi_reload_spmaps(struct silofs_sb_info *sbi);

int silofs_sbi_spawn_vnode_at(struct silofs_sb_info *sbi,
                              const struct silofs_uvaddr *ova,
                              struct silofs_vnode_info **out_vi);

int silofs_sbi_stage_vnode_at(struct silofs_sb_info *sbi,
                              const struct silofs_uvaddr *ova,
                              enum silofs_stage_flags stg_flags,
                              struct silofs_vnode_info **out_vi);

int silofs_sbi_stage_inode_at(struct silofs_sb_info *sbi,
                              const struct silofs_iuvaddr *iuva,
                              enum silofs_stage_flags stg_flags,
                              struct silofs_inode_info **out_ii);

int silofs_sbi_resolve_uva(struct silofs_sb_info *sbi,
                           const struct silofs_vaddr *vaddr,
                           enum silofs_stage_flags stg_flags,
                           struct silofs_uvaddr *out_ova);

#endif /* SILOFS_STAGE_H_ */
