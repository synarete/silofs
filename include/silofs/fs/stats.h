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
#ifndef SILOFS_STATS_H_
#define SILOFS_STATS_H_


void silofs_spacestat_add(struct silofs_spacestat *spst,
                          const struct silofs_spacestat *other);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_sti_bind_apex(struct silofs_spstat_info *sti,
                          struct silofs_fs_apex *apex);

void silofs_sti_setup_spawned(struct silofs_spstat_info *sti);

void silofs_sti_make_clone(struct silofs_spstat_info *sti,
                           const struct silofs_spstat_info *sti_other);

size_t silofs_sti_capacity(const struct silofs_spstat_info *sti);

void silofs_sti_set_capacity(struct silofs_spstat_info *sti, size_t capacity);

loff_t silofs_sti_vspace_end(const struct silofs_spstat_info *sti);

size_t silofs_sti_bytes_used(const struct silofs_spstat_info *sti);

fsfilcnt_t silofs_sti_inodes_used(const struct silofs_spstat_info *sti);

fsfilcnt_t silofs_sti_inodes_max(const struct silofs_spstat_info *sti);


void silofs_sti_update_objs(struct silofs_spstat_info *sti,
                            enum silofs_stype stype, ssize_t take);

void silofs_sti_collect_objs(const struct silofs_spstat_info *sti,
                             struct silofs_spacestat *out_sp);

void silofs_sti_update_blobs(struct silofs_spstat_info *sti,
                             enum silofs_stype stype, ssize_t take);

bool silofs_sti_may_alloc_some(const struct silofs_spstat_info *sti, size_t n);

bool silofs_sti_may_alloc_data(const struct silofs_spstat_info *sti, size_t n);

bool silofs_sti_may_alloc_meta(const struct silofs_spstat_info *sti,
                               size_t nbytes, bool new_file);

void silofs_sti_fill_statvfs(const struct silofs_spstat_info *sti,
                             struct statvfs *out_stv);

int silofs_verify_stats_node(const struct silofs_spstat_node *ss);

#endif /* SILOFS_STATS_H_ */
