/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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

void silofs_sbi_setup_sb(struct silofs_sb_info *sbi, size_t capacity);

void silofs_sbi_update_birth_time(struct silofs_sb_info *sbi, time_t btime);

void silofs_sbi_clone_from(struct silofs_sb_info *sbi,
                           const struct silofs_sb_info *sbi_other);

int silofs_sbi_format_spmaps(struct silofs_sb_info *sbi);

int silofs_sbi_reload_spmaps(struct silofs_sb_info *sbi);

int silofs_sbi_format_itable(struct silofs_sb_info *sbi);

int silofs_sbi_reload_itable(struct silofs_sb_info *sbi);

void silofs_statvfs_of(const struct silofs_sb_info *sbi,
                       struct statvfs *out_stvfs);

int silofs_stage_inode(struct silofs_sb_info *sbi,
                       ino_t ino, enum silofs_stage_flags flags,
                       struct silofs_inode_info **out_ii);

int silofs_stage_vnode(struct silofs_sb_info *sbi,
                       const struct silofs_vaddr *vaddr,
                       enum silofs_stage_flags flags,
                       struct silofs_vnode_info **out_vi);

int silofs_spawn_inode(struct silofs_sb_info *sbi,
                       const struct silofs_oper *op, ino_t parent_ino,
                       mode_t parent_mode, mode_t mode, dev_t rdev,
                       struct silofs_inode_info **out_ii);

int silofs_spawn_vnode(struct silofs_sb_info *sbi, enum silofs_stype stype,
                       struct silofs_vnode_info **out_vi);

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

int silofs_resolve_oaddr(struct silofs_sb_info *sbi,
                         const struct silofs_vaddr *vaddr,
                         struct silofs_oaddr *out_oaddr);

int silofs_resolve_oaddr_of(struct silofs_sb_info *sbi,
                            const struct silofs_vnode_info *vi,
                            struct silofs_oaddr *out_oaddr);

int silofs_sbi_expand_vspace(struct silofs_sb_info *sbi,
                             enum silofs_stype stype, loff_t *out_voff);

int silofs_stage_spleaf(struct silofs_sb_info *sbi, loff_t voff,
                        enum silofs_stage_flags stg_flags,
                        struct silofs_spleaf_info **out_sli);

int silofs_stage_spnode(struct silofs_sb_info *sbi, loff_t voff,
                        enum silofs_stage_flags stg_flags,
                        struct silofs_spnode_info **out_sni);

size_t silofs_sbi_nused_bytes(const struct silofs_sb_info *sbi);

size_t silofs_sbi_vspace_capacity(const struct silofs_sb_info *sbi);

fsfilcnt_t silofs_sbi_inodes_limit(const struct silofs_sb_info *sbi);

fsfilcnt_t silofs_sbi_inodes_current(const struct silofs_sb_info *sbi);

void silofs_sbi_update_stats(struct silofs_sb_info *sbi,
                             const struct silofs_space_stat *spst_dif);

int silofs_spawn_bind_vnode_at(struct silofs_sb_info *sbi,
                               const struct silofs_ovaddr *ova,
                               enum silofs_stage_flags stg_flags,
                               struct silofs_vnode_info **out_vi);

int silofs_sbi_require_mutable_vaddr(struct silofs_sb_info *sbi,
                                     const struct silofs_vaddr *vaddr);

#endif /* SILOFS_SUPER_H_ */
