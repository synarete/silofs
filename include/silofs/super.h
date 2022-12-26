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

int silofs_sbi_xinit(struct silofs_sb_info *sbi, struct silofs_alloc *alloc);

void silofs_sbi_xfini(struct silofs_sb_info *sbi);

int silofs_sbi_shut(struct silofs_sb_info *sbi);

void silofs_sbi_setup_spawned(struct silofs_sb_info *sbi);

void silofs_sbi_setup_btime(struct silofs_sb_info *sbi);

void silofs_sbi_setup_ctime(struct silofs_sb_info *sbi);

void silofs_sbi_bind_stats(struct silofs_sb_info *sbi,
                           struct silofs_stats_info *sti);

void silofs_sbi_bind_uber(struct silofs_sb_info *sbi,
                          struct silofs_uber *uber);


void silofs_sbi_dirtify(struct silofs_sb_info *sbi);

int silofs_sbi_sproot_of(const struct silofs_sb_info *sbi,
                         enum silofs_stype vstype,
                         struct silofs_uaddr *out_uaddr);

void silofs_sbi_bind_sproot(struct silofs_sb_info *sbi,
                            enum silofs_stype vstype,
                            const struct silofs_spnode_info *sni);

void silofs_sbi_make_clone(struct silofs_sb_info *sbi,
                           const struct silofs_sb_info *sbi_other);

int silofs_sbi_format_itable(struct silofs_sb_info *sbi);

int silofs_sbi_reload_itable(struct silofs_sb_info *sbi);


int silofs_sbi_stage_vnode(struct silofs_sb_info *sbi,
                           const struct silofs_vaddr *vaddr,
                           enum silofs_stage_mode flags, silofs_dqid_t dqid,
                           struct silofs_vnode_info **out_vi);

int silofs_sbi_stage_inode(struct silofs_sb_info *sbi,
                           ino_t ino, enum silofs_stage_mode flags,
                           struct silofs_inode_info **out_ii);


int silofs_sbi_stage_cached_ii(struct silofs_sb_info *sbi, ino_t ino,
                               struct silofs_inode_info **out_ii);

int silofs_sbi_spawn_vnode(struct silofs_sb_info *sbi,
                           enum silofs_stype stype, silofs_dqid_t dqid,
                           struct silofs_vnode_info **out_vi);

int silofs_sbi_spawn_inode(struct silofs_sb_info *sbi,
                           const struct silofs_creds *creds, ino_t parent_ino,
                           mode_t parent_mode, mode_t mode, dev_t rdev,
                           struct silofs_inode_info **out_ii);


int silofs_sbi_remove_inode(struct silofs_sb_info *sbi,
                            struct silofs_inode_info *ii);

int silofs_sbi_remove_vnode(struct silofs_sb_info *sbi,
                            struct silofs_vnode_info *vi);

int silofs_sbi_remove_vnode_at(struct silofs_sb_info *sbi,
                               const struct silofs_vaddr *vaddr);

int silofs_sbi_test_unwritten(struct silofs_sb_info *sbi,
                              const struct silofs_vaddr *vaddr, bool *out_res);

int silofs_sbi_clear_unwritten(struct silofs_sb_info *sbi,
                               const struct silofs_vaddr *vaddr);

int silofs_sbi_mark_unwritten(struct silofs_sb_info *sbi,
                              const struct silofs_vaddr *vaddr);

int silofs_sbi_test_lastref(struct silofs_sb_info *sbi,
                            const struct silofs_vaddr *vaddr, bool *out_res);

int silofs_sbi_test_shared(struct silofs_sb_info *sbi,
                           const struct silofs_vaddr *vaddr, bool *out_res);


void silofs_sbi_add_flags(struct silofs_sb_info *sbi,
                          enum silofs_superf flags);

bool silofs_sbi_test_flags(const struct silofs_sb_info *sbi,
                           enum silofs_superf flags);

int silof_sbi_check_mut_fs(const struct silofs_sb_info *sbi);

void silofs_sbi_treeid(const struct silofs_sb_info *sbi,
                       struct silofs_treeid *out_treeid);

int silofs_sbi_main_blob(const struct silofs_sb_info *sbi,
                         enum silofs_stype vspace,
                         struct silofs_blobid *out_blobid);

void silofs_sbi_bind_main_blob(struct silofs_sb_info *sbi,
                               enum silofs_stype vspace,
                               const struct silofs_blobid *blobid);

bool silofs_sbi_has_main_blob(const struct silofs_sb_info *sbi,
                              enum silofs_stype vspace);

void silofs_sbi_main_child_at(const struct silofs_sb_info *sbi,
                              loff_t voff, enum silofs_stype vspace,
                              struct silofs_uaddr *out_uaddr);

int silofs_sbi_cold_blob(const struct silofs_sb_info *sbi,
                         enum silofs_stype vspace,
                         struct silofs_blobid *out_blobid);

void silofs_sbi_bind_cold_blob(struct silofs_sb_info *sbi,
                               enum silofs_stype vspace,
                               const struct silofs_blobid *blobid);

#endif /* SILOFS_SUPER_H_ */
