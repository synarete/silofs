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

struct silofs_spnode_info;
struct silofs_spleaf_info;

void silofs_sb_set_pass_hash(struct silofs_super_block *sb,
                             const struct silofs_hash512 *hash);

int silofs_sb_check_pass_hash(const struct silofs_super_block *sb,
                              const struct silofs_hash512 *hash);

int silofs_sb_check_rand(const struct silofs_super_block *sb,
                         const struct silofs_mdigest *md);

int silofs_sb_check_root(const struct silofs_super_block *sb);

bool silofs_sb_isfossil(const struct silofs_super_block *sb);

loff_t silofs_sb_vspace_last(const struct silofs_super_block *sb);

loff_t silofs_sb_vlast_by_stype(const struct silofs_super_block *sb,
                                enum silofs_stype stype);

void silofs_sb_set_voff_last(struct silofs_super_block *sb,
                             enum silofs_stype stype, loff_t voff_last);

int silofs_sb_encrypt(const struct silofs_super_block *sb_in,
                      const struct silofs_cipher *ci,
                      const struct silofs_kivam *kivam,
                      struct silofs_super_block *sb_out);

int silofs_sb_decrypt(const struct silofs_super_block *sb_in,
                      const struct silofs_cipher *ci,
                      const struct silofs_kivam *kivam,
                      struct silofs_super_block *sb_out);

int silofs_verify_super_block(const struct silofs_super_block *sb);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_sbi_isrofs(const struct silofs_sb_info *sbi);

void silofs_sbi_dirtify(struct silofs_sb_info *sbi);

void silofs_sbi_init_commons(struct silofs_sb_info *sbi);

void silofs_sbi_fini(struct silofs_sb_info *sbi);

int silofs_sbi_xinit(struct silofs_sb_info *sbi,
                     struct silofs_fs_apex *apex);

int silofs_sbi_shut(struct silofs_sb_info *sbi);

void silofs_sbi_attach_ubi(struct silofs_sb_info *sbi,
                           struct silofs_ubk_info *ubi);

void silofs_sbi_update_by_args(struct silofs_sb_info *sbi,
                               const struct silofs_fs_args *args);

void silofs_sbi_setup_spawned(struct silofs_sb_info *sbi,
                              const struct silofs_namestr *name,
                              size_t capacity, time_t btime);

void silofs_sbi_update_birth_time(struct silofs_sb_info *sbi, time_t btime);

void silofs_sbi_name(const struct silofs_sb_info *sbi,
                     struct silofs_namestr *out_name);

bool silofs_sbi_has_name(const struct silofs_sb_info *sbi,
                         const struct silofs_namestr *name);

void silofs_sbi_clone_from(struct silofs_sb_info *sbi,
                           const struct silofs_sb_info *sbi_other);

int silofs_sbi_format_spmaps(struct silofs_sb_info *sbi);

int silofs_sbi_format_itable(struct silofs_sb_info *sbi);

int silofs_sbi_reload_itable(struct silofs_sb_info *sbi);


int silofs_stage_vnode(struct silofs_sb_info *sbi,
                       const struct silofs_vaddr *vaddr,
                       enum silofs_stage_flags flags,
                       struct silofs_vnode_info **out_vi);

int silofs_stage_inode(struct silofs_sb_info *sbi,
                       ino_t ino, enum silofs_stage_flags flags,
                       struct silofs_inode_info **out_ii);


int silofs_stage_cached_inode(struct silofs_sb_info *sbi, ino_t ino,
                              struct silofs_inode_info **out_ii);

int silofs_spawn_vnode(struct silofs_sb_info *sbi, enum silofs_stype stype,
                       struct silofs_vnode_info **out_vi);

int silofs_spawn_inode(struct silofs_sb_info *sbi,
                       const struct silofs_oper *op, ino_t parent_ino,
                       mode_t parent_mode, mode_t mode, dev_t rdev,
                       struct silofs_inode_info **out_ii);


int silofs_remove_inode(struct silofs_sb_info *sbi,
                        struct silofs_inode_info *ii);

int silofs_remove_vnode(struct silofs_sb_info *sbi,
                        struct silofs_vnode_info *vi);

int silofs_remove_vnode_at(struct silofs_sb_info *sbi,
                           const struct silofs_vaddr *vaddr);

int silofs_probe_unwritten(struct silofs_sb_info *sbi,
                           const struct silofs_vaddr *vaddr, bool *out_res);

int silofs_clear_unwritten(struct silofs_sb_info *sbi,
                           const struct silofs_vaddr *vaddr);

int silofs_mark_unwritten(struct silofs_sb_info *sbi,
                          const struct silofs_vaddr *vaddr);

int silofs_refcnt_islast_at(struct silofs_sb_info *sbi,
                            const struct silofs_vaddr *vaddr, bool *out_res);

int silofs_kivam_of(const struct silofs_vnode_info *vi,
                    struct silofs_kivam *out_kivam);

int silofs_sbi_expand_vspace(struct silofs_sb_info *sbi,
                             enum silofs_stype stype, loff_t *out_voff);

int silofs_stage_spnode(struct silofs_sb_info *sbi, loff_t voff,
                        enum silofs_stage_flags stg_flags,
                        struct silofs_spnode_info **out_sni);

void silofs_sbi_space_stat(const struct silofs_sb_info *sbi,
                           struct silofs_space_stat *out_sp_st);

size_t silofs_sbi_nused_bytes(const struct silofs_sb_info *sbi);

size_t silofs_sbi_vspace_capacity(const struct silofs_sb_info *sbi);

void silofs_sbi_vspace_range(const struct silofs_sb_info *sbi,
                             struct silofs_vrange *out_vrange);

fsfilcnt_t silofs_sbi_inodes_limit(const struct silofs_sb_info *sbi);

fsfilcnt_t silofs_sbi_inodes_current(const struct silofs_sb_info *sbi);

void silofs_sbi_update_stats(struct silofs_sb_info *sbi,
                             const struct silofs_space_stat *spst_dif);

void silofs_sbi_set_fossil(struct silofs_sb_info *sbi);


void silofs_sbi_main_treeid(const struct silofs_sb_info *sbi,
                            struct silofs_metaid *out_mid);

void silofs_sbi_main_blobid(const struct silofs_sb_info *sbi,
                            struct silofs_blobid *out_bid);

void silofs_sbi_bind_main_blob(struct silofs_sb_info *sbi,
                               const struct silofs_blobid *bid);

bool silofs_sbi_has_main_blob(const struct silofs_sb_info *sbi);

size_t silofs_sbi_space_tree_height(const struct silofs_sb_info *sbi);

int silofs_sbi_child_at(const struct silofs_sb_info *sbi, loff_t voff,
                        struct silofs_uaddr *out_uaddr);

void silofs_sbi_main_child_at(const struct silofs_sb_info *sbi,
                              loff_t voff, struct silofs_uaddr *out_uaddr);

int silofs_sbi_commit_dirty(struct silofs_sb_info *sbi);

void silofs_sbi_bind_child(struct silofs_sb_info *sbi,
                           const struct silofs_spnode_info *sni);

void silofs_sbi_update_vlast_by_spleaf(struct silofs_sb_info *sbi,
                                       const struct silofs_spleaf_info *sli);

bool silofs_sbi_has_child_at(const struct silofs_sb_info *sbi, loff_t voff);


void silofs_sbi_update_bootsec(struct silofs_sb_info *sbi,
                               const struct silofs_namestr *name);

int silofs_sbi_save_bootsec(const struct silofs_sb_info *sbi);

int silofs_sbi_load_bootsec(struct silofs_sb_info *sbi,
                            const struct silofs_namestr *name);

#endif /* SILOFS_SUPER_H_ */
