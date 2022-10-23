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


void silofs_spacestats_export(const struct silofs_spacestats *spst,
                              struct silofs_space_stats *out_spst);

void silofs_spacestats_import(struct silofs_spacestats *spst,
                              const struct silofs_space_stats *in_spst);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_sti_setup_spawned(struct silofs_stats_info *sti,
                              struct silofs_sb_info *sbi);

void silofs_sti_make_clone(struct silofs_stats_info *sti,
                           const struct silofs_stats_info *sti_other);

void silofs_sti_renew_stats(struct silofs_stats_info *sti);

void silofs_sti_set_capacity(struct silofs_stats_info *sti,
                             size_t capacity);

void silofs_sti_vspace_end(const struct silofs_stats_info *sti, loff_t *out);

void silofs_sti_update_blobs(struct silofs_stats_info *sti,
                             enum silofs_stype stype, ssize_t take);

void silofs_sti_update_bks(struct silofs_stats_info *sti,
                           enum silofs_stype stype, ssize_t take);

void silofs_sti_update_objs(struct silofs_stats_info *sti,
                            enum silofs_stype stype, ssize_t take);

void silofs_sti_collect_stats(const struct silofs_stats_info *sti,
                              struct silofs_spacestats *out_sp);

bool silofs_sti_mayalloc_some(const struct silofs_stats_info *sti,
                              size_t nbytes_want);

bool silofs_sti_mayalloc_data(const struct silofs_stats_info *sti,
                              size_t nbytes_want);

bool silofs_sti_mayalloc_meta(const struct silofs_stats_info *sti,
                              size_t nbytes_want, bool new_file);

void silofs_sti_fill_statvfs(const struct silofs_stats_info *sti,
                             struct statvfs *out_stv);

int silofs_verify_space_stats(const struct silofs_space_stats *sp);

#endif /* SILOFS_STATS_H_ */
