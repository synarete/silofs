/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#ifndef SILOFS_LSMAP_H_
#define SILOFS_LSMAP_H_

#include <silofs/defs.h>

void silofs_lsi_get_lrange(const struct silofs_lsmap_info *lsi,
                           struct silofs_lrange           *out_lrange);

void silofs_lsi_setup_spawned(struct silofs_lsmap_info *lsi,
                              enum silofs_ltype refltype, loff_t beg);

void silofs_lsi_update_nused(struct silofs_lsmap_info *lsi);

bool silofs_lsi_has_allocated_with(const struct silofs_lsmap_info *lsi,
                                   const struct silofs_vaddr      *vaddr);

int silofs_lsi_find_free_space(const struct silofs_lsmap_info *lsi,
                               struct silofs_vaddr            *out_vaddr);

int silofs_verify_lsmap(const struct silofs_lsmap *lsm);

#endif /* SILOFS_LSMAP_H_ */
