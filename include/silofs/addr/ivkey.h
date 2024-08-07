/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#ifndef SILOFS_IVKEY_H_
#define SILOFS_IVKEY_H_

#include <silofs/defs.h>
#include <stdlib.h>
#include <stdbool.h>

/* encryption tuple (IV, key, cipher-algo, mode) */
struct silofs_ivkey {
	struct silofs_key       key;
	struct silofs_iv        iv;
	unsigned int            algo;
	unsigned int            mode;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_iv_reset(struct silofs_iv *iv);

void silofs_iv_mkrand(struct silofs_iv *iv);

void silofs_iv_assign(struct silofs_iv *iv, const struct silofs_iv *iv_other);

bool silofs_iv_isequal(const struct silofs_iv *iv,
                       const struct silofs_iv *iv_other);

long silofs_iv_compare(const struct silofs_iv *iv,
                       const struct silofs_iv *iv_other);

void silofs_iv_xor_with(struct silofs_iv *iv,
                        const struct silofs_iv *iv_other);

void silofs_iv_xor_with2(struct silofs_iv *iv,
                         const struct silofs_iv *iv1,
                         const struct silofs_iv *iv2);

void silofs_gen_random_ivs(struct silofs_iv *ivs, size_t nivs);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ivkey_init(struct silofs_ivkey *ivkey);

void silofs_ivkey_fini(struct silofs_ivkey *ivkey);

void silofs_ivkey_assign(struct silofs_ivkey *ivkey,
                         const struct silofs_ivkey *other);

#endif /* SILOFS_IVKEY_H_ */
