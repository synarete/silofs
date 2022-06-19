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
                              struct silofs_spstats *out_spst);

void silofs_spacestats_import(struct silofs_spacestats *spst,
                              const struct silofs_spstats *in_spst);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_spi_bind_uber(struct silofs_spstats_info *sti,
                          struct silofs_fs_uber *uber);

void silofs_spi_setup_spawned(struct silofs_spstats_info *sti);

void silofs_spi_make_clone(struct silofs_spstats_info *sti,
                           const struct silofs_spstats_info *spi_other);

size_t silofs_spi_capacity(const struct silofs_spstats_info *sti);

void silofs_spi_set_capacity(struct silofs_spstats_info *sti, size_t capacity);

loff_t silofs_spi_vspace_end(const struct silofs_spstats_info *sti);

size_t silofs_spi_bytes_used(const struct silofs_spstats_info *sti);

fsfilcnt_t silofs_spi_inodes_used(const struct silofs_spstats_info *sti);

fsfilcnt_t silofs_spi_inodes_max(const struct silofs_spstats_info *sti);


void silofs_spi_update_blobs(struct silofs_spstats_info *sti,
                             enum silofs_stype stype, ssize_t take);

void silofs_spi_update_bks(struct silofs_spstats_info *sti,
                           enum silofs_stype stype, ssize_t take);

void silofs_spi_update_objs(struct silofs_spstats_info *sti,
                            enum silofs_stype stype, ssize_t take);

void silofs_spi_collect_stats(const struct silofs_spstats_info *sti,
                              struct silofs_spacestats *out_sp);

bool silofs_spi_mayalloc_some(const struct silofs_spstats_info *spi, size_t n);

bool silofs_spi_mayalloc_data(const struct silofs_spstats_info *spi, size_t n);

bool silofs_spi_mayalloc_meta(const struct silofs_spstats_info *spi,
                              size_t nbytes, bool new_file);

void silofs_spi_fill_statvfs(const struct silofs_spstats_info *spi,
                             struct statvfs *out_stv);

int silofs_verify_spstats_node(const struct silofs_spstats_node *sp);

#endif /* SILOFS_STATS_H_ */
