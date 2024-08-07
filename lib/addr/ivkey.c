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
#include <silofs/configs.h>
#include <silofs/infra.h>
#include <silofs/addr.h>
#include <gcrypt.h>


static void randomize(void *ptr, size_t len, bool very_strong)
{
	const enum gcry_random_level random_level =
	        very_strong ? GCRY_VERY_STRONG_RANDOM : GCRY_STRONG_RANDOM;

	gcry_randomize(ptr, len, random_level);
}

void silofs_iv_reset(struct silofs_iv *iv)
{
	memset(iv, 0, sizeof(*iv));
}

void silofs_iv_assign(struct silofs_iv *iv, const struct silofs_iv *iv_other)
{
	memcpy(iv, iv_other, sizeof(*iv));
}

bool silofs_iv_isequal(const struct silofs_iv *iv,
                       const struct silofs_iv *iv_other)
{
	return silofs_iv_compare(iv, iv_other) == 0;
}

long silofs_iv_compare(const struct silofs_iv *iv,
                       const struct silofs_iv *iv_other)
{
	return memcmp(iv->iv, iv_other->iv, sizeof(iv->iv));
}

void silofs_iv_xor_with(struct silofs_iv *iv, const struct silofs_iv *iv_other)
{
	for (size_t i = 0; i < ARRAY_SIZE(iv->iv); ++i) {
		iv->iv[i] ^= iv_other->iv[i];
	}
}

void silofs_iv_xor_with2(struct silofs_iv *iv,
                         const struct silofs_iv *iv1,
                         const struct silofs_iv *iv2)
{
	for (size_t i = 0; i < ARRAY_SIZE(iv->iv); ++i) {
		iv->iv[i] ^= (iv1->iv[i] ^ iv2->iv[i]);
	}
}

void silofs_iv_mkrand(struct silofs_iv *iv)
{
	randomize(iv->iv, sizeof(iv->iv), false);
}

void silofs_gen_random_iv(struct silofs_iv *iv)
{
	silofs_gen_random_ivs(iv, 1);
}

void silofs_gen_random_ivs(struct silofs_iv *ivs, size_t nivs)
{
	randomize(ivs, nivs * sizeof(*ivs), false);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ivkey_init(struct silofs_ivkey *ivkey)
{
	memset(ivkey, 0, sizeof(*ivkey));
	ivkey->algo = SILOFS_CIPHER_AES256;
	ivkey->mode = SILOFS_CIPHER_MODE_XTS;
}

void silofs_ivkey_fini(struct silofs_ivkey *ivkey)
{
	memset(ivkey, 0xC3, sizeof(*ivkey));
}

void silofs_ivkey_assign(struct silofs_ivkey *ivkey,
                         const struct silofs_ivkey *other)
{
	memcpy(ivkey, other, sizeof(*ivkey));
}
