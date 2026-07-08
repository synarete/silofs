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
#ifndef SILOFS_IVKEY_H_
#define SILOFS_IVKEY_H_

/* encryption IV-key pair */
struct silofs_civkey {
	struct silofs_ckey key;
	struct silofs_civ  iv;
};

void silofs_civ_reset(struct silofs_civ *iv);

void silofs_civ_assign(struct silofs_civ       *iv,
                       const struct silofs_civ *iv_other);

void silofs_civ_mkrand(struct silofs_civ *iv);

bool silofs_civ_isequal(const struct silofs_civ *iv,
                        const struct silofs_civ *iv_other);

long silofs_civ_compare(const struct silofs_civ *iv,
                        const struct silofs_civ *iv_other);

void silofs_civ_xor_with(struct silofs_civ *iv, const void *buf, size_t len);

void silofs_civ_xor_with1(struct silofs_civ *iv, const struct silofs_civ *iv1);

void silofs_civ_xor_with2(struct silofs_civ *iv, const struct silofs_civ *iv1,
                          const struct silofs_civ *iv2);

void silofs_gen_random_iv(struct silofs_civ *iv);

void silofs_gen_random_ivs(struct silofs_civ *ivs, size_t nivs);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ckey_reset(struct silofs_ckey *key);

void silofs_ckey_assign(struct silofs_ckey       *key,
                        const struct silofs_ckey *other);

bool silofs_ckey_isequal(const struct silofs_ckey *key,
                         const struct silofs_ckey *other);

void silofs_ckey_mkrand(struct silofs_ckey *key);

void silofs_ckey_xor_with(struct silofs_ckey *key, const void *buf,
                          size_t len);

void silofs_ckey_xor_with2(struct silofs_ckey       *key,
                           const struct silofs_ckey *key1);

void silofs_generate_keys(struct silofs_ckey *keys, size_t nkeys);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_civkey_init(struct silofs_civkey *civkey);

void silofs_civkey_reset(struct silofs_civkey *civkey);

void silofs_civkey_setup(struct silofs_civkey     *civkey,
                         const struct silofs_ckey *key,
                         const struct silofs_civ  *iv);

void silofs_civkey_assign(struct silofs_civkey       *civkey,
                          const struct silofs_civkey *other);

bool silofs_civkey_isequal(const struct silofs_civkey *civkey,
                           const struct silofs_civkey *other);

void silofs_civkey_xor_with(struct silofs_civkey       *civkey,
                            const struct silofs_civkey *other);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ctag_reset(struct silofs_ctag *ctag);

void silofs_ctag_init(struct silofs_ctag *ctag);

void silofs_ctag_assign(struct silofs_ctag       *ctag,
                        const struct silofs_ctag *other);

bool silofs_ctag_isequal(const struct silofs_ctag *ctag,
                         const struct silofs_ctag *other);

#endif /* SILOFS_IVKEY_H_ */
