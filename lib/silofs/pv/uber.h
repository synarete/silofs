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

#include <silofs/pv/btnode.h>

const struct silofs_layerid *
silofs_ubi_layerid(const struct silofs_uber_info *ubi);

void silofs_ubi_incref(struct silofs_uber_info *ubi);

void silofs_ubi_decref(struct silofs_uber_info *ubi);

void silofs_ubi_dirtify(struct silofs_uber_info *ubi);

void silofs_ubi_undirtify(struct silofs_uber_info *ubi);

void silofs_ubi_ignite(struct silofs_uber_info *ubi);

void silofs_ubi_set_btroot(struct silofs_uber_info    *ubi,
                           enum silofs_vtype           vtype,
                           const struct silofs_btnptr *btnptr);

void silofs_ubi_set_btroot_by(struct silofs_uber_info         *ubi,
                              const struct silofs_btnode_info *bti);

void silofs_ubi_btroot_of(const struct silofs_uber_info *ubi,
                          enum silofs_vtype              vtype,
                          struct silofs_btnptr          *out_btnptr);

void silofs_ubi_spdesc_of(const struct silofs_uber_info *ubi,
                          const struct silofs_stype     *stype,
                          struct silofs_spdesc          *out_spdesc);

void silofs_ubi_start_spdesc(struct silofs_uber_info   *ubi,
                             const struct silofs_paddr *paddr);

void silofs_ubi_update_spdesc(struct silofs_uber_info    *ubi,
                              const struct silofs_spdesc *spdesc);

bool silofs_ubi_onsame_layer(const struct silofs_uber_info   *ubi,
                             const struct silofs_btnode_info *bti);

int silofs_validate_uber(const struct silofs_uber_info *ubi);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_uber_ref {
	struct silofs_uber_info *ubi;
};

void silofs_ubref_init(struct silofs_uber_ref *ubref);

void silofs_ubref_fini(struct silofs_uber_ref *ubref);

void silofs_ubref_update(struct silofs_uber_ref  *ubref,
                         struct silofs_uber_info *ubi);

#endif /* SILOFS_UBER_H_ */
