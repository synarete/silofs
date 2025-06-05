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
#include "private.h"

static void randomize_by_gcry(void *ptr, size_t len, bool very_strong)
{
	enum gcry_random_level level = very_strong ? GCRY_VERY_STRONG_RANDOM :
	                                             GCRY_STRONG_RANDOM;

	gcry_randomize(ptr, len, level);
}

static void randomize(void *ptr, size_t len, bool very_strong)
{
	randomize_by_gcry(ptr, len, very_strong);
}

/* add pseudo-randomness as protection from poor gcry_randomize */
void silofs_prandomize_with(void *ptr, size_t len, uint64_t seed)
{
	uint64_t u[6];
	uint64_t *itr = ptr;
	uint64_t xx = *itr;
	const size_t ns = len / sizeof(*itr);
	const size_t nu = ARRAY_SIZE(u);
	struct timespec t;

	silofs_mclock_now(&t);
	u[0] = (uint64_t)t.tv_sec;
	u[1] = (uint64_t)t.tv_nsec;
	u[2] = (uint64_t)gettid();
	silofs_rclock_now(&t);
	u[3] = (uint64_t)t.tv_sec;
	u[4] = (uint64_t)t.tv_nsec;
	u[5] = seed;

	for (uint32_t i = 0; i < ns; ++i) {
		u[(i + 1) % nu] ^= silofs_twang_mix64(xx);
		u[(i + 2) % nu] ^= xx / (i | 1);
		u[(i + 3) % nu] ^= ~xx + i;
		u[(i + 4) % nu] ^= silofs_lrotate64(xx, i % 61);

		xx = silofs_hash_xxh64(u, sizeof(u), xx);
		*itr++ ^= xx;
	}
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

void silofs_generate_keys(struct silofs_key *keys, size_t nkeys, bool extra)
{
	for (size_t i = 0; i < nkeys; ++i) {
		struct silofs_key *key = &keys[i];

		silofs_key_mkrand(key);
		if (extra) {
			silofs_prandomize_with(key->key, sizeof(key->key), i);
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
