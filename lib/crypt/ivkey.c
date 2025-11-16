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
#include "configs.h"
#include <gcrypt.h>
#include "infra.h"
#include "gcry.h"
#include "ivkey.h"

static enum gcry_random_level random_level(bool strong)
{
	return strong ? GCRY_VERY_STRONG_RANDOM : GCRY_STRONG_RANDOM;
}

static void randomize_by_gcry(void *ptr, size_t len, bool strong)
{
	gcry_randomize(ptr, len, random_level(strong));
}

static void randomize(void *ptr, size_t len, bool strong)
{
	randomize_by_gcry(ptr, len, strong);
}

void silofs_gcrypt_random(void *ptr, size_t len)
{
	randomize_by_gcry(ptr, len, false);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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

void silofs_iv_xor_with(struct silofs_iv *iv, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	const size_t n = silofs_min(len, ARRAY_SIZE(iv->iv));

	for (size_t i = 0; i < n; ++i) {
		iv->iv[i] ^= p[i];
	}
}

void silofs_iv_xor_with1(struct silofs_iv *iv, const struct silofs_iv *iv1)
{
	for (size_t i = 0; i < ARRAY_SIZE(iv->iv); ++i) {
		iv->iv[i] ^= iv1->iv[i];
	}
}

void silofs_iv_xor_with2(struct silofs_iv *iv, const struct silofs_iv *iv1,
                         const struct silofs_iv *iv2)
{
	for (size_t i = 0; i < ARRAY_SIZE(iv->iv); ++i) {
		iv->iv[i] ^= (iv1->iv[i] ^ iv2->iv[i]);
	}
}

void silofs_iv_mkrand(struct silofs_iv *iv)
{
	silofs_gen_random_ivs(iv, 1);
}

static void randomize_ivs(struct silofs_iv *ivs, size_t nivs)
{
	randomize(ivs, nivs * sizeof(*ivs), false);
}

void silofs_gen_random_ivs(struct silofs_iv *ivs, size_t nivs)
{
	randomize_ivs(ivs, nivs);
}

void silofs_derive_iv_by_hash256(struct silofs_iv *iv,
                                 const struct silofs_hash256 *hash)
{
	STATICASSERT_LE(ARRAY_SIZE(iv->iv), ARRAY_SIZE(hash->hash));

	silofs_iv_reset(iv);
	for (size_t i = 0; i < ARRAY_SIZE(hash->hash); ++i) {
		iv->iv[i % ARRAY_SIZE(iv->iv)] ^= hash->hash[i];
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_key_reset(struct silofs_key *key)
{
	memset(key, 0xff, sizeof(*key));
}

void silofs_key_assign(struct silofs_key *key, const struct silofs_key *other)
{
	memcpy(key, other, sizeof(*key));
}

void silofs_key_mkrand(struct silofs_key *key)
{
	randomize(key->key, sizeof(key->key), true);
}

void silofs_key_xor_with(struct silofs_key *key, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	const size_t n = silofs_min(len, ARRAY_SIZE(key->key));

	for (size_t i = 0; i < n; ++i) {
		key->key[i] ^= p[i];
	}
}

void silofs_key_xor_with1(struct silofs_key *key,
                          const struct silofs_key *key1)
{
	for (size_t i = 0; i < ARRAY_SIZE(key->key); ++i) {
		key->key[i] ^= key1->key[i];
	}
}

static void key_rerandomize(struct silofs_key *key, size_t i)
{
	/* add pseudo-randomness as protection from poor gcry_randomize */
	silofs_prand_by_hash(key->key, key->key, sizeof(key->key));
	key->key[i % ARRAY_SIZE(key->key)] ^= (uint8_t)i;
}

void silofs_generate_keys(struct silofs_key *keys, size_t nkeys, bool extra)
{
	for (size_t i = 0; i < nkeys; ++i) {
		silofs_key_mkrand(&keys[i]);
		if (extra) {
			key_rerandomize(&keys[i], i);
		}
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ivkey_init(struct silofs_ivkey *ivkey)
{
	memset(ivkey, 0, sizeof(*ivkey));
}

void silofs_ivkey_reset(struct silofs_ivkey *ivkey)
{
	silofs_key_reset(&ivkey->key);
	silofs_iv_reset(&ivkey->iv);
}

void silofs_ivkey_mkrand(struct silofs_ivkey *ivkey)
{
	silofs_key_mkrand(&ivkey->key);
	silofs_iv_mkrand(&ivkey->iv);
}

void silofs_ivkey_setup(struct silofs_ivkey *ivkey,
                        const struct silofs_key *key,
                        const struct silofs_iv *iv)
{
	silofs_key_assign(&ivkey->key, key);
	silofs_iv_assign(&ivkey->iv, iv);
}

void silofs_ivkey_assign(struct silofs_ivkey *ivkey,
                         const struct silofs_ivkey *other)
{
	silofs_ivkey_setup(ivkey, &other->key, &other->iv);
}

void silofs_ivkey_xor_with(struct silofs_ivkey *ivkey,
                           const struct silofs_ivkey *other)
{
	silofs_key_xor_with1(&ivkey->key, &other->key);
	silofs_iv_xor_with1(&ivkey->iv, &other->iv);
}
