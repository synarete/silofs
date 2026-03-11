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
#include "htox.h"
#include "paddr.h"
#include "nmeta.h"

static const struct silofs_nmeta s_nmeta_none = {
	.ciargs.algo = SILOFS_CIPHER_NONE,
	.ciargs.mode = SILOFS_CIPHER_MODE_NONE,
};

const struct silofs_nmeta *silofs_nmeta_none(void)
{
	return &s_nmeta_none;
}

void silofs_nmeta_setup(struct silofs_nmeta *nmeta,
                        const struct silofs_civkey *civkey)
{
	silofs_civkey_assign(&nmeta->civkey, civkey);
	silofs_ciargs_assign(&nmeta->ciargs, silofs_ciargs_default());
}

void silofs_nmeta_reset(struct silofs_nmeta *nmeta)
{
	silofs_civkey_reset(&nmeta->civkey);
	silofs_ciargs_reset(&nmeta->ciargs);
}

void silofs_nmeta_assign(struct silofs_nmeta *nmeta,
                         const struct silofs_nmeta *other)
{
	silofs_civkey_assign(&nmeta->civkey, &other->civkey);
	silofs_ciargs_assign(&nmeta->ciargs, &other->ciargs);
}

bool silofs_nmeta_isequal(const struct silofs_nmeta *nmeta,
                          const struct silofs_nmeta *other)
{
	return silofs_ciargs_isequal(&nmeta->ciargs, &other->ciargs) &&
	       silofs_civkey_isequal(&nmeta->civkey, &other->civkey);
}

void silofs_nmeta128b_htox(struct silofs_nmeta128b *nmeta128,
                           const struct silofs_nmeta *nmeta)
{
	const uint16_t algo = (uint16_t)(nmeta->ciargs.algo);
	const uint16_t mode = (uint16_t)(nmeta->ciargs.mode);

	memset(nmeta128, 0, sizeof(*nmeta128));
	silofs_ckey_assign(&nmeta128->nm_cipher_key, &nmeta->civkey.key);
	silofs_civ_assign(&nmeta128->nm_cipher_iv, &nmeta->civkey.iv);
	nmeta128->nm_cipher_algo = silofs_cpu_to_le16(algo);
	nmeta128->nm_cipher_mode = silofs_cpu_to_le16(mode);
}

void silofs_nmeta128b_xtoh(const struct silofs_nmeta128b *nmeta128,
                           struct silofs_nmeta *nmeta)
{
	const uint16_t algo = silofs_le16_to_cpu(nmeta128->nm_cipher_algo);
	const uint16_t mode = silofs_le16_to_cpu(nmeta128->nm_cipher_mode);

	silofs_ckey_assign(&nmeta->civkey.key, &nmeta128->nm_cipher_key);
	silofs_civ_assign(&nmeta->civkey.iv, &nmeta128->nm_cipher_iv);
	nmeta->ciargs.algo = (enum silofs_cipher_algo)algo;
	nmeta->ciargs.mode = (enum silofs_cipher_mode)mode;
}
