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
#ifndef SILOFS_LTYPE_H_
#define SILOFS_LTYPE_H_

#include <silofs/defs.h>
#include <stdbool.h>

bool silofs_ltype_isnone(enum silofs_ltype ltype);

bool silofs_ltype_isbootrec(enum silofs_ltype ltype);

bool silofs_ltype_issuper(enum silofs_ltype ltype);

bool silofs_ltype_isspnode(enum silofs_ltype ltype);

bool silofs_ltype_isspleaf(enum silofs_ltype ltype);

bool silofs_ltype_isinode(enum silofs_ltype ltype);

bool silofs_ltype_isxanode(enum silofs_ltype ltype);

bool silofs_ltype_issymval(enum silofs_ltype ltype);

bool silofs_ltype_isdtnode(enum silofs_ltype ltype);

bool silofs_ltype_isftnode(enum silofs_ltype ltype);

bool silofs_ltype_isdata1k(enum silofs_ltype ltype);

bool silofs_ltype_isdata4k(enum silofs_ltype ltype);

bool silofs_ltype_isdatabk(enum silofs_ltype ltype);

bool silofs_ltype_isunode(enum silofs_ltype ltype);

bool silofs_ltype_isvnode(enum silofs_ltype ltype);

bool silofs_ltype_isdata(enum silofs_ltype ltype);

uint32_t silofs_ltype_size(enum silofs_ltype ltype);

ssize_t silofs_ltype_ssize(enum silofs_ltype ltype);

size_t silofs_ltype_nkbs(enum silofs_ltype ltype);

#ifdef SILOFS_USE_PRIVATE
#define ltype_size(lt)          silofs_ltype_size(lt)
#define ltype_isnone(lt)        silofs_ltype_isnone(lt)
#define ltype_isbootrec(lt)     silofs_ltype_isbootrec(lt)
#define ltype_issuper(lt)       silofs_ltype_issuper(lt)
#define ltype_isspnode(lt)      silofs_ltype_isspnode(lt)
#define ltype_isspleaf(lt)      silofs_ltype_isspleaf(lt)
#define ltype_isunode(lt)       silofs_ltype_isunode(lt)
#define ltype_isvnode(lt)       silofs_ltype_isvnode(lt)
#define ltype_isinode(lt)       silofs_ltype_isinode(lt)
#define ltype_isxanode(lt)      silofs_ltype_isxanode(lt)
#define ltype_issymval(lt)      silofs_ltype_issymval(lt)
#define ltype_isdtnode(lt)      silofs_ltype_isdtnode(lt)
#define ltype_isftnode(lt)      silofs_ltype_isftnode(lt)
#define ltype_isdata(lt)        silofs_ltype_isdata(lt)
#define ltype_isdata1k(lt)      silofs_ltype_isdata1k(lt)
#define ltype_isdata4k(lt)      silofs_ltype_isdata4k(lt)
#define ltype_isdatabk(lt)      silofs_ltype_isdatabk(lt)
#endif

#endif /* SILOFS_LTYPE_H_ */
