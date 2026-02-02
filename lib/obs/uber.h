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
#ifndef SILOFS_UBER_H_
#define SILOFS_UBER_H_

#include "nodes.h"

void silofs_ubi_incref(struct silofs_uber_info *ubi);

void silofs_ubi_decref(struct silofs_uber_info *ubi);

void silofs_ubi_dirtify(struct silofs_uber_info *ubi);

void silofs_ubi_undirtify(struct silofs_uber_info *ubi);

void silofs_ubi_set_child(struct silofs_uber_info     *ubi,
                          enum silofs_mtype            mtype,
                          const struct silofs_nodeptr *nodeptr);

void silofs_ubi_get_child(const struct silofs_uber_info *ubi,
                          enum silofs_mtype              mtype,
                          struct silofs_nodeptr         *out_nodeptr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_uber_info *
silofs_lookup_cached_uber(struct silofs_pcache      *pcache,
                          const struct silofs_paddr *paddr);

struct silofs_uber_info *
silofs_create_cached_uber(struct silofs_pcache        *pcache,
                          const struct silofs_nodeptr *nodeptr, bool spawn);

void silofs_forget_cached_uber(struct silofs_pcache    *pcache,
                               struct silofs_uber_info *ubi);

#endif /* SILOFS_UBER_H_ */
