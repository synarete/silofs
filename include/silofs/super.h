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
#ifndef SILOFS_SUPER_H_
#define SILOFS_SUPER_H_

struct silofs_stats_info;
struct silofs_spnode_info;
struct silofs_spleaf_info;

int silofs_sb_check_version(const struct silofs_super_block *sb);

bool silofs_sb_test_flags(const struct silofs_super_block *sb,
                          enum silofs_superf mask);

int silofs_verify_super_block(const struct silofs_super_block *sb);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_sbi_dirtify(struct silofs_sb_info *sbi);

int silofs_sbi_shut(struct silofs_sb_info *sbi);

void silofs_sbi_setup_spawned(struct silofs_sb_info *sbi);

void silofs_sbi_setup_btime(struct silofs_sb_info *sbi);

void silofs_sbi_setup_ctime(struct silofs_sb_info *sbi);

void silofs_sbi_bind_stats(struct silofs_sb_info *sbi,
                           struct silofs_stats_info *sti);

int silofs_sbi_sproot_of(const struct silofs_sb_info *sbi,
                         enum silofs_stype vstype,
                         struct silofs_uaddr *out_uaddr);

int silofs_sbi_resolve_child(const struct silofs_sb_info *sbi,
                             enum silofs_stype vstype,
                             struct silofs_ulink *out_ulink);

void silofs_sbi_bind_child(struct silofs_sb_info *sbi,
                           enum silofs_stype vstype,
                           const struct silofs_ulink *ulink);

void silofs_sbi_clone_from(struct silofs_sb_info *sbi,
                           const struct silofs_sb_info *sbi_other);


void silofs_sbi_add_flags(struct silofs_sb_info *sbi,
                          enum silofs_superf flags);

bool silofs_sbi_test_flags(const struct silofs_sb_info *sbi,
                           enum silofs_superf flags);

int silof_sbi_check_mut_fs(const struct silofs_sb_info *sbi);


void silofs_sbi_treeid(const struct silofs_sb_info *sbi,
                       struct silofs_treeid *out_treeid);

int silofs_sbi_main_lext(const struct silofs_sb_info *sbi,
                         enum silofs_stype vspace,
                         struct silofs_lextid *out_lextid);

void silofs_sbi_bind_main_lext(struct silofs_sb_info *sbi,
                               enum silofs_stype vspace,
                               const struct silofs_lextid *lextid);

bool silofs_sbi_has_main_lext(const struct silofs_sb_info *sbi,
                              enum silofs_stype vspace);

void silofs_sbi_resolve_main_at(const struct silofs_sb_info *sbi,
                                loff_t voff, enum silofs_stype vspace,
                                struct silofs_ulink *out_ulink);

bool silofs_sbi_ismutable_lextid(const struct silofs_sb_info *sbi,
                                 const struct silofs_lextid *lextid);

bool silofs_sbi_ismutable_laddr(const struct silofs_sb_info *sbi,
                                const struct silofs_laddr *laddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_clear_unwritten_at(struct silofs_task *task,
                              const struct silofs_vaddr *vaddr);

int silofs_mark_unwritten_at(struct silofs_task *task,
                             const struct silofs_vaddr *vaddr);

int silofs_test_unwritten_at(struct silofs_task *task,
                             const struct silofs_vaddr *vaddr, bool *out_res);

int silofs_test_last_allocated(struct silofs_task *task,
                               const struct silofs_vaddr *vaddr,
                               bool *out_res);

int silofs_test_shared_dbkref(struct silofs_task *task,
                              const struct silofs_vaddr *vaddr, bool *out_res);



#endif /* SILOFS_SUPER_H_ */
