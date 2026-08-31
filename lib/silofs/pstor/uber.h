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

#include <silofs/infra.h>
#include <silofs/crypt.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>

/* uber stat per sub-type */
struct silofs_uber_stat {
	size_t bn;
	size_t vn;
};

struct silofs_uber_stats {
	struct silofs_uber_stat st[SILOFS_LTYPE_LAST];
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_usi_incref(struct silofs_uspace_info *usi);

void silofs_usi_decref(struct silofs_uspace_info *usi);

void silofs_usi_setdirty(struct silofs_uspace_info *usi);

void silofs_usi_cleardirty(struct silofs_uspace_info *usi);

void silofs_usi_update_spawned(struct silofs_uspace_info  *usi,
                               const struct silofs_blobid *blobid);

int silofs_usi_grab_space(struct silofs_uspace_info *usi,
                          struct silofs_paddr       *out_paddr);

int silofs_usi_drop_space(struct silofs_uspace_info *usi,
                          const struct silofs_paddr *paddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

const struct silofs_layerid *
silofs_ubi_layerid(const struct silofs_uber_info *ubi);

void silofs_ubi_incref(struct silofs_uber_info *ubi);

void silofs_ubi_decref(struct silofs_uber_info *ubi);

void silofs_ubi_setdirty(struct silofs_uber_info *ubi);

void silofs_ubi_cleardirty(struct silofs_uber_info *ubi);

void silofs_ubi_update_spawned(struct silofs_uber_info *ubi);

bool silofs_ubi_has_btroot(const struct silofs_uber_info *ubi,
                           const struct silofs_pnptr     *pnptr);

void silofs_ubi_set_btroot(struct silofs_uber_info   *ubi,
                           const struct silofs_pnptr *pnptr);

void silofs_ubi_set_btroot_by(struct silofs_uber_info         *ubi,
                              const struct silofs_btnode_info *bti);

void silofs_ubi_btroot_of(const struct silofs_uber_info *ubi,
                          enum silofs_ltype              ltype,
                          struct silofs_pnptr           *out_pnptr);

void silofs_ubi_start_free_space_at(struct silofs_uber_info   *ubi,
                                    const struct silofs_paddr *paddr);

void silofs_ubi_consume_nextfree(struct silofs_uber_info   *ubi,
                                 const struct silofs_stype *stype,
                                 struct silofs_paddr       *out_paddr);

void silofs_ubi_inc_count_by(struct silofs_uber_info    *ubi,
                             const struct silofs_blobid *blobid);

void silofs_ubi_dec_count_by(struct silofs_uber_info    *ubi,
                             const struct silofs_blobid *blobid);

void silofs_ubi_stat_of(const struct silofs_uber_info *ubi,
                        enum silofs_ltype              ltype,
                        struct silofs_uber_stat       *out_stat);

void silofs_ubi_collect_stats(const struct silofs_uber_info *ubi,
                              struct silofs_uber_stats      *out_stats);

bool silofs_ubi_onsame_layer(const struct silofs_uber_info   *ubi,
                             const struct silofs_btnode_info *bti);

int silofs_validate_uber(const struct silofs_uber_info *ubi);

#endif /* SILOFS_UBER_H_ */
