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
#include "genid.h"

static void make_prandom(struct silofs_prandgen *prng, void *p, size_t n)
{
	silofs_prandgen_take(prng, p, n);
}

static void
make_prandom_ckey(struct silofs_prandgen *prng, struct silofs_ckey *out_ckey)
{
	make_prandom(prng, out_ckey->key, sizeof(out_ckey->key));
}

static void
make_prandom_civ(struct silofs_prandgen *prng, struct silofs_civ *out_civ)
{
	make_prandom(prng, out_civ->iv, sizeof(out_civ->iv));
}

void silofs_generate_civkey(struct silofs_prandgen *prng,
                            struct silofs_civkey *out_civkey)
{
	make_prandom_ckey(prng, &out_civkey->key);
	make_prandom_civ(prng, &out_civkey->iv);
}

void silofs_generate_uniqid(struct silofs_prandgen *prng,
                            struct silofs_uniqid *out_uniqid)
{
	make_prandom(prng, out_uniqid->u.raw, sizeof(out_uniqid->u.raw));
}

void silofs_generate_layerid(struct silofs_prandgen *prng,
                             struct silofs_layerid *out_layerid)
{
	make_prandom(prng, out_layerid->id, sizeof(out_layerid->id));
}
