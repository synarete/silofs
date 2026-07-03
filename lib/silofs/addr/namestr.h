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
#ifndef SILOFS_NAMESTR_H_
#define SILOFS_NAMESTR_H_

#include <silofs/str.h>

/* name-string: a pair of string-view and (optional) 64-bits hash */
struct silofs_namestr {
	struct silofs_strview sv;
	uint64_t              hash;
};

int silofs_namestr_init(struct silofs_namestr *nstr, const char *s);

int silofs_namestr_init_by(struct silofs_namestr       *nstr,
                           const struct silofs_strview *sv);

int silofs_namestr_calc_hash(struct silofs_namestr          *nstr,
                             const struct silofs_mdigest_hd *md,
                             enum silofs_namehfn nhfn, uint64_t seed);

int silofs_check_fsname(const struct silofs_namestr *nstr);

#endif /* SILOFS_NAMESTR_H_ */
