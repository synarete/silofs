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
#include <silofs/crypt.h>
#include <silofs/addr.h>

static void take_grandom(void *p, size_t n)
{
	silofs_gcrypt_random(p, n);
}

static void take_prandom(struct silofs_prandgen *prng, void *p, size_t n)
{
	silofs_prandgen_take(prng, p, n);
}

static void feed_prandom(struct silofs_prandgen *prng, void *p, size_t n)
{
	silofs_prandgen_feed(prng, p, n);
}

void silofs_generate_civ(struct silofs_prandgen *prng,
                         struct silofs_civ *out_civ)
{
	take_prandom(prng, out_civ->iv, sizeof(out_civ->iv));
}

void silofs_generate_ckey(struct silofs_prandgen *prng,
                          struct silofs_ckey *out_ckey)
{
	constexpr size_t n = sizeof(out_ckey->key);
	uint8_t *p         = out_ckey->key;

	STATICASSERT_GT(sizeof(out_ckey->key), 16);

	take_grandom(p, 16);
	take_prandom(prng, p + 16, n - 16);
	feed_prandom(prng, p, 16);
}

void silofs_generate_uniqid(struct silofs_prandgen *prng,
                            struct silofs_uniqid *out_uniqid)
{
	take_prandom(prng, out_uniqid->id, sizeof(out_uniqid->id));
}

void silofs_generate_layerid(struct silofs_prandgen *prng,
                             struct silofs_layerid *out_layerid)
{
	take_prandom(prng, out_layerid->id, sizeof(out_layerid->id));
}
