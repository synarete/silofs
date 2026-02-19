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

#include <silofs/ondisk.h>
#include <stdlib.h>
#include <stdbool.h>

size_t silofs_ptype_size(enum silofs_ptype ptype);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

bool silofs_vtype_isnone(enum silofs_vtype vtype);

bool silofs_vtype_issuper(enum silofs_vtype vtype);

bool silofs_vtype_isspnode(enum silofs_vtype vtype);

bool silofs_vtype_isspleaf(enum silofs_vtype vtype);

bool silofs_vtype_isinode(enum silofs_vtype vtype);

bool silofs_vtype_isunode(enum silofs_vtype vtype);

bool silofs_vtype_isvnode(enum silofs_vtype vtype);

bool silofs_vtype_isdata(enum silofs_vtype vtype);

size_t silofs_vtype_size(enum silofs_vtype vtype);

ssize_t silofs_vtype_ssize(enum silofs_vtype vtype);

size_t silofs_vtype_nkbs(enum silofs_vtype vtype);

#endif /* SILOFS_STYPE_H_ */
