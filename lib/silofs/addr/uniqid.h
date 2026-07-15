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
#ifndef SILOFS_UNIQID_H_
#define SILOFS_UNIQID_H_

const struct silofs_layerid *silofs_layerid_none(void);

void silofs_layerid_reset(struct silofs_layerid *layerid);

void silofs_layerid_generate(struct silofs_layerid *layerid);

void silofs_layerid_assign(struct silofs_layerid       *layerid,
                           const struct silofs_layerid *other);

void silofs_layerid_assignx(struct silofs_layerid       *layerid,
                            const struct silofs_layerid *other);

long silofs_layerid_compare(const struct silofs_layerid *layerid,
                            const struct silofs_layerid *other);

bool silofs_layerid_isequal(const struct silofs_layerid *layerid,
                            const struct silofs_layerid *other);

int silofs_layerid_to_str(const struct silofs_layerid *layerid, char *str,
                          size_t len);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_uniqid_reset(struct silofs_uniqid *uniqid);

void silofs_uniqid_setup_by(struct silofs_uniqid        *uniqid,
                            const struct silofs_hash256 *hash);

void silofs_uniqid_assign(struct silofs_uniqid       *uniqid,
                          const struct silofs_uniqid *other);

void silofs_uniqid_assignx(struct silofs_uniqid       *uniqid,
                           const struct silofs_uniqid *other);

long silofs_uniqid_compare(const struct silofs_uniqid *uniqid,
                           const struct silofs_uniqid *other);

#endif /* SILOFS_UNIQID_H_ */
