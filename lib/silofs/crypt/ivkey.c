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
#include <silofs/configs.h>
#include <gcrypt.h>

#include <silofs/base.h>
#include <silofs/crypt.h>

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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_civ_reset(struct silofs_civ *iv)
{
	memset(iv, 0, sizeof(*iv));
}

void silofs_civ_assign(struct silofs_civ *iv,
                       const struct silofs_civ *iv_other)
{
	memcpy(iv, iv_other, sizeof(*iv));
}

bool silofs_civ_isequal(const struct silofs_civ *iv,
                        const struct silofs_civ *iv_other)
{
	return silofs_civ_compare(iv, iv_other) == 0;
}

long silofs_civ_compare(const struct silofs_civ *iv,
                        const struct silofs_civ *iv_other)
{
	return memcmp(iv->iv, iv_other->iv, sizeof(iv->iv));
}

void silofs_civ_xor_with(struct silofs_civ *iv, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	const size_t n   = silofs_min(len, ARRAY_SIZE(iv->iv));

	for (size_t i = 0; i < n; ++i) {
		iv->iv[i] ^= p[i];
	}
}

void silofs_civ_xor_with1(struct silofs_civ *iv, const struct silofs_civ *iv1)
{
	for (size_t i = 0; i < ARRAY_SIZE(iv->iv); ++i) {
		iv->iv[i] ^= iv1->iv[i];
	}
}

void silofs_civ_xor_with2(struct silofs_civ *iv, const struct silofs_civ *iv1,
                          const struct silofs_civ *iv2)
{
	for (size_t i = 0; i < ARRAY_SIZE(iv->iv); ++i) {
		iv->iv[i] ^= (iv1->iv[i] ^ iv2->iv[i]);
	}
}

void silofs_civ_mkrand(struct silofs_civ *iv)
{
	silofs_gen_random_ivs(iv, 1);
}

static void randomize_ivs(struct silofs_civ *ivs, size_t nivs)
{
	randomize(ivs, nivs * sizeof(*ivs), false);
}

void silofs_gen_random_ivs(struct silofs_civ *ivs, size_t nivs)
{
	randomize_ivs(ivs, nivs);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ckey_reset(struct silofs_ckey *key)
{
	memset(key, 0, sizeof(*key));
}

void silofs_ckey_assign(struct silofs_ckey *key,
                        const struct silofs_ckey *other)
{
	memcpy(key, other, sizeof(*key));
}

bool silofs_ckey_isequal(const struct silofs_ckey *key,
                         const struct silofs_ckey *other)
{
	return memcmp(key, other, sizeof(*key)) == 0;
}

void silofs_ckey_mkrand(struct silofs_ckey *key)
{
	randomize(key->key, sizeof(key->key), true);
}

void silofs_ckey_xor_with(struct silofs_ckey *key, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	const size_t n   = silofs_min(len, ARRAY_SIZE(key->key));

	for (size_t i = 0; i < n; ++i) {
		key->key[i] ^= p[i];
	}
}

void silofs_ckey_xor_with2(struct silofs_ckey *key,
                           const struct silofs_ckey *key2)
{
	for (size_t i = 0; i < ARRAY_SIZE(key->key); ++i) {
		key->key[i] ^= key2->key[i];
	}
}

void silofs_generate_keys(struct silofs_ckey *keys, size_t nkeys)
{
	for (size_t i = 0; i < nkeys; ++i) {
		silofs_ckey_mkrand(&keys[i]);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_civkey_init(struct silofs_civkey *civkey)
{
	memset(civkey, 0, sizeof(*civkey));
}

void silofs_civkey_reset(struct silofs_civkey *civkey)
{
	silofs_ckey_reset(&civkey->key);
	silofs_civ_reset(&civkey->iv);
}

void silofs_civkey_setup(struct silofs_civkey *civkey,
                         const struct silofs_ckey *key,
                         const struct silofs_civ *iv)
{
	silofs_ckey_assign(&civkey->key, key);
	silofs_civ_assign(&civkey->iv, iv);
}

void silofs_civkey_assign(struct silofs_civkey *civkey,
                          const struct silofs_civkey *other)
{
	silofs_civkey_setup(civkey, &other->key, &other->iv);
}

bool silofs_civkey_isequal(const struct silofs_civkey *civkey,
                           const struct silofs_civkey *other)
{
	return silofs_civ_isequal(&civkey->iv, &other->iv) &&
	       silofs_ckey_isequal(&civkey->key, &other->key);
}

void silofs_civkey_xor_with(struct silofs_civkey *civkey,
                            const struct silofs_civkey *other)
{
	silofs_ckey_xor_with2(&civkey->key, &other->key);
	silofs_civ_xor_with1(&civkey->iv, &other->iv);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_ctag_reset(struct silofs_ctag *ctag)
{
	memset(ctag->tag, 0, sizeof(ctag->tag));
}

void silofs_ctag_init(struct silofs_ctag *ctag)
{
	silofs_ctag_reset(ctag);
}

void silofs_ctag_assign(struct silofs_ctag *ctag,
                        const struct silofs_ctag *other)
{
	memcpy(ctag->tag, other->tag, sizeof(ctag->tag));
}

bool silofs_ctag_isequal(const struct silofs_ctag *ctag,
                         const struct silofs_ctag *other)
{
	return memcmp(ctag->tag, other->tag, sizeof(ctag->tag)) == 0;
}
