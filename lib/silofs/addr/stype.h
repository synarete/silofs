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
#ifndef SILOFS_STYPE_H_
#define SILOFS_STYPE_H_

struct silofs_stype {
	enum silofs_ptype ptype;
	enum silofs_ltype ltype;
};

void silofs_stype_clear(struct silofs_stype *stype);

void silofs_stype_assign(struct silofs_stype       *stype,
                         const struct silofs_stype *other);

long silofs_stype_compare(const struct silofs_stype *stype,
                          const struct silofs_stype *other);

size_t silofs_stype_size(const struct silofs_stype *stype);

#endif /* SILOFS_STYPE_H_ */
