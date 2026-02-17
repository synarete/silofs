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

bool silofs_mtype_isnone(enum silofs_mtype mtype);

bool silofs_mtype_issuper(enum silofs_mtype mtype);

bool silofs_mtype_isspnode(enum silofs_mtype mtype);

bool silofs_mtype_isspleaf(enum silofs_mtype mtype);

bool silofs_mtype_isinode(enum silofs_mtype mtype);

bool silofs_mtype_isunode(enum silofs_mtype mtype);

bool silofs_mtype_isvnode(enum silofs_mtype mtype);

bool silofs_mtype_isdata(enum silofs_mtype mtype);

size_t silofs_mtype_size(enum silofs_mtype mtype);

ssize_t silofs_mtype_ssize(enum silofs_mtype mtype);

size_t silofs_mtype_nkbs(enum silofs_mtype mtype);

#endif /* SILOFS_STYPE_H_ */
