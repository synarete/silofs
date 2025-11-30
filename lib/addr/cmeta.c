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
#include <stdio.h>
#include "crypt.h"
#include "htox.h"
#include "paddr.h"
#include "cmeta.h"

static const struct silofs_cmeta s_cmeta_none = {
	.ciargs.algo = SILOFS_CIPHER_NONE,
	.ciargs.mode = SILOFS_CIPHER_MODE_NONE,
};

const struct silofs_cmeta *silofs_cmeta_none(void)
{
	return &s_cmeta_none;
}

void silofs_cmeta_setup(struct silofs_cmeta *cmeta,
                        const struct silofs_civkey *civkey)
{
	silofs_civkey_assign(&cmeta->civkey, civkey);
	silofs_ciargs_assign(&cmeta->ciargs, silofs_ciargs_default());
}

void silofs_cmeta_reset(struct silofs_cmeta *cmeta)
{
	silofs_civkey_reset(&cmeta->civkey);
	silofs_ciargs_reset(&cmeta->ciargs);
}

void silofs_cmeta_assign(struct silofs_cmeta *cmeta,
                         const struct silofs_cmeta *other)
{
	silofs_civkey_assign(&cmeta->civkey, &other->civkey);
	silofs_ciargs_assign(&cmeta->ciargs, &other->ciargs);
}

void silofs_cmeta96b_htox(struct silofs_cmeta96b *cmeta96,
                          const struct silofs_cmeta *cmeta)
{
	const uint16_t algo = (uint16_t)(cmeta->ciargs.algo);
	const uint16_t mode = (uint16_t)(cmeta->ciargs.mode);

	memset(cmeta96, 0, sizeof(*cmeta96));
	silofs_ckey_assign(&cmeta96->cm_cipher_key, &cmeta->civkey.key);
	silofs_civ_assign(&cmeta96->cm_cipher_iv, &cmeta->civkey.iv);
	cmeta96->cm_cipher_algo = silofs_cpu_to_le16(algo);
	cmeta96->cm_cipher_mode = silofs_cpu_to_le16(mode);
}

void silofs_cmeta96b_xtoh(const struct silofs_cmeta96b *cmeta96,
                          struct silofs_cmeta *cmeta)
{
	const uint16_t algo = silofs_le16_to_cpu(cmeta96->cm_cipher_algo);
	const uint16_t mode = silofs_le16_to_cpu(cmeta96->cm_cipher_mode);

	silofs_ckey_assign(&cmeta->civkey.key, &cmeta96->cm_cipher_key);
	silofs_civ_assign(&cmeta->civkey.iv, &cmeta96->cm_cipher_iv);
	cmeta->ciargs.algo = (enum silofs_cipher_algo)algo;
	cmeta->ciargs.mode = (enum silofs_cipher_mode)mode;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_pmeta s_pmeta_none = {
	.cmeta.ciargs.algo = SILOFS_CIPHER_NONE,
	.cmeta.ciargs.mode = SILOFS_CIPHER_MODE_NONE,
};

const struct silofs_pmeta *silofs_pmeta_none(void)
{
	return &s_pmeta_none;
}

void silofs_pmeta_setup(struct silofs_pmeta *pmeta,
                        const struct silofs_paddr *paddr,
                        const struct silofs_civkey *civkey)
{
	silofs_paddr_assign(&pmeta->paddr, paddr);
	silofs_cmeta_setup(&pmeta->cmeta, civkey);
}

void silofs_pmeta_reset(struct silofs_pmeta *pmeta)
{
	silofs_paddr_reset(&pmeta->paddr);
	silofs_cmeta_reset(&pmeta->cmeta);
}

void silofs_pmeta_assign(struct silofs_pmeta *pmeta,
                         const struct silofs_pmeta *other)
{
	silofs_paddr_assign(&pmeta->paddr, &other->paddr);
	silofs_cmeta_assign(&pmeta->cmeta, &other->cmeta);
}

bool silofs_pmeta_isnull(const struct silofs_pmeta *pmeta)
{
	return silofs_paddr_isnull(&pmeta->paddr);
}

void silofs_pmeta192b_htox(struct silofs_pmeta192b *pmeta192,
                           const struct silofs_pmeta *pmeta)
{
	memset(pmeta192, 0, sizeof(*pmeta192));
	silofs_paddr64b_htox(&pmeta192->pm_paddr, &pmeta->paddr);
	silofs_cmeta96b_htox(&pmeta192->pm_cmeta, &pmeta->cmeta);
}

void silofs_pmeta192b_xtoh(const struct silofs_pmeta192b *pmeta192,
                           struct silofs_pmeta *pmeta)
{
	silofs_paddr64b_xtoh(&pmeta192->pm_paddr, &pmeta->paddr);
	silofs_cmeta96b_xtoh(&pmeta192->pm_cmeta, &pmeta->cmeta);
}
