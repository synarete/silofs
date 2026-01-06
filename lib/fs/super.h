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
#ifndef SILOFS_SUPER_H_
#define SILOFS_SUPER_H_

#include <stdlib.h>
#include <silofs/ondisk.h>
#include "addr.h"

struct silofs_task_ctx;
struct silofs_spnode_info;
struct silofs_spleaf_info;
struct silofs_spmap_lmap;
struct silofs_super_block;
struct silofs_sb_info;
struct silofs_query_spstats;

int silofs_sb_check_version(const struct silofs_super_block *sb);

bool silofs_sb_test_flags(const struct silofs_super_block *sb,
                          enum silofs_superf               mask);

int silofs_verify_super_block(const struct silofs_super_block *sb);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_uaddr *silofs_sbi_uaddr(const struct silofs_sb_info *sbi);

const struct silofs_laddr *silofs_sbi_laddr(const struct silofs_sb_info *sbi);

const struct silofs_blobid *silofs_sbi_lvid(const struct silofs_sb_info *sbi);

void silofs_sbi_incref(struct silofs_sb_info *sbi);

void silofs_sbi_decref(struct silofs_sb_info *sbi);

void silofs_sbi_dirtify(struct silofs_sb_info *sbi);

void silofs_sbi_setup_spawned(struct silofs_sb_info *sbi);

int silofs_sbi_sproot_of(const struct silofs_sb_info *sbi,
                         enum silofs_mtype            mtype,
                         struct silofs_uaddr         *out_uaddr);

int silofs_sbi_resolve_child(const struct silofs_sb_info *sbi,
                             enum silofs_mtype            mtype,
                             struct silofs_uaddr         *out_uaddr);

void silofs_sbi_bind_child(struct silofs_sb_info *sbi, enum silofs_mtype mtype,
                           const struct silofs_uaddr *uaddr);

void silofs_sbi_make_fork_of(struct silofs_sb_info       *sbi_new,
                             const struct silofs_sb_info *sbi_cur);

void silofs_sbi_resolve_lmap(const struct silofs_sb_info *sbi,
                             struct silofs_spmap_lmap    *out_lmap);

void silofs_sbi_add_flags(struct silofs_sb_info *sbi,
                          enum silofs_superf     flags);

bool silofs_sbi_test_flags(const struct silofs_sb_info *sbi,
                           enum silofs_superf           flags);

bool silofs_sbi_is_fossil(const struct silofs_sb_info *sbi);

int silof_sbi_check_mut_fs(const struct silofs_sb_info *sbi);

void silofs_sbi_self_blobid(const struct silofs_sb_info *sbi,
                            struct silofs_blobid        *out_blobid);

void silofs_sbi_self_svolid(const struct silofs_sb_info *sbi,
                            struct silofs_svolid        *out_svolid);

int silofs_sbi_main_lseg(const struct silofs_sb_info *sbi,
                         enum silofs_mtype            vspace,
                         struct silofs_lsid          *out_lsid);

void silofs_sbi_bind_main_lseg(struct silofs_sb_info    *sbi,
                               enum silofs_mtype         vspace,
                               const struct silofs_lsid *lsid);

bool silofs_sbi_has_main_lseg(const struct silofs_sb_info *sbi,
                              enum silofs_mtype            vspace);

void silofs_sbi_resolve_main_at(const struct silofs_sb_info *sbi, off_t voff,
                                enum silofs_mtype    vspace,
                                struct silofs_uaddr *out_uaddr);

bool silofs_sbi_ismutable_lsid(const struct silofs_sb_info *sbi,
                               const struct silofs_lsid    *lsid);

bool silofs_sbi_ismutable_laddr(const struct silofs_sb_info *sbi,
                                const struct silofs_laddr   *laddr);

struct silofs_sb_refs {
	struct silofs_uaddr curr;
	struct silofs_uaddr prev;
};

void silofs_sbi_resolve_refs(const struct silofs_sb_info *sbi,
                             struct silofs_sb_refs       *out_refs);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_sbst_setup_spawned(struct silofs_sb_info *sbi);

void silofs_sbst_setup_forked(struct silofs_sb_info       *sbi,
                              const struct silofs_sb_info *sbi_from);

void silofs_sbst_account_super(struct silofs_sb_info *sbi);

void silofs_sbst_set_capacity(struct silofs_sb_info *sbi, size_t capacity);

off_t silofs_sbst_vspace_end(const struct silofs_sb_info *sbi);

uint64_t silofs_sbst_next_generation(struct silofs_sb_info *sbi);

void silofs_sbst_update_lsegs(struct silofs_sb_info *sbi,
                              enum silofs_mtype mtype, ssize_t take);

void silofs_sbst_update_bks(struct silofs_sb_info *sbi,
                            enum silofs_mtype mtype, ssize_t take);

void silofs_sbst_update_objs(struct silofs_sb_info *sbi,
                             enum silofs_mtype mtype, ssize_t take);

bool silofs_sbst_mayalloc_some(const struct silofs_sb_info *sbi, size_t nwant);

bool silofs_sbst_mayalloc_data(const struct silofs_sb_info *sbi, size_t nwant);

bool silofs_sbst_mayalloc_meta(const struct silofs_sb_info *sbi,
                               size_t nbytes_want, bool new_file);

void silofs_sbst_fetch_from_sb(struct silofs_sb_info *sbi);

void silofs_sbst_force_into_sb(struct silofs_sb_info *sbi);

void silofs_sbst_fill_statvfs(const struct silofs_sb_info *sbi,
                              struct statvfs              *out_stv);

void silofs_sbst_fill_qspst(const struct silofs_sb_info *sbi,
                            struct silofs_query_spstats *out_qsp);

int silofs_verify_space_stats(const struct silofs_space_stats1k *sp);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_clear_unwritten_at(struct silofs_task_ctx    *task,
                              const struct silofs_vaddr *vaddr);

int silofs_mark_unwritten_at(struct silofs_task_ctx    *task,
                             const struct silofs_vaddr *vaddr);

int silofs_test_unwritten_at(struct silofs_task_ctx    *task,
                             const struct silofs_vaddr *vaddr, bool *out_res);

int silofs_test_last_allocated(struct silofs_task_ctx    *task,
                               const struct silofs_vaddr *vaddr,
                               bool                      *out_res);

int silofs_test_shared_dbkref(struct silofs_task_ctx    *task,
                              const struct silofs_vaddr *vaddr, bool *out_res);

#endif /* SILOFS_SUPER_H_ */
