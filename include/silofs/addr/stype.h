/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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

#include <silofs/defs.h>

bool silofs_stype_isnone(enum silofs_stype stype);

bool silofs_stype_issuper(enum silofs_stype stype);

bool silofs_stype_isspnode(enum silofs_stype stype);

bool silofs_stype_isspleaf(enum silofs_stype stype);

bool silofs_stype_isinode(enum silofs_stype stype);

bool silofs_stype_isxanode(enum silofs_stype stype);

bool silofs_stype_issymval(enum silofs_stype stype);

bool silofs_stype_isdtnode(enum silofs_stype stype);

bool silofs_stype_isftnode(enum silofs_stype stype);

bool silofs_stype_isdata1k(enum silofs_stype stype);

bool silofs_stype_isdata4k(enum silofs_stype stype);

bool silofs_stype_isdatabk(enum silofs_stype stype);

bool silofs_stype_isunode(enum silofs_stype stype);

bool silofs_stype_isvnode(enum silofs_stype stype);

bool silofs_stype_isdata(enum silofs_stype stype);

uint32_t silofs_stype_size(enum silofs_stype stype);

ssize_t silofs_stype_ssize(enum silofs_stype stype);

size_t silofs_stype_nkbs(enum silofs_stype stype);


#endif /* SILOFS_STYPE_H_ */
