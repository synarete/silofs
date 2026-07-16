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

#include <silofs/exec.h>

void silofs_relax_caches(const struct silofs_exec_ctx *ectx, int flags)
{
	silofs_pcache_relax(ectx->pcache, flags);
	silofs_lcache_relax(ectx->lcache, flags);
	if (flags & SILOFS_CTLF_IDLE) {
		silofs_dstor_relax(ectx->dstor);
	}
}

void silofs_drop_caches(const struct silofs_exec_ctx *ectx)
{
	silofs_pspools_drop(ectx->pspools);
	silofs_lspools_drop(ectx->lspools);
	silofs_pcache_drop(ectx->pcache);
	silofs_lcache_drop(ectx->lcache);
	silofs_dstor_drop(ectx->dstor);
}

int silofs_reinit_ciphers(const struct silofs_exec_ctx *ectx)
{
	const struct silofs_mbr_meta *mbr_meta = &ectx->fsroot->mbr_meta;
	const struct silofs_ciargs *ciargs     = &mbr_meta->nmeta.ciargs;
	int err;

	err = silofs_cipher_reinit(ectx->enc_ci_hd, ciargs);
	return_if_err(err);

	err = silofs_cipher_reinit(ectx->dec_ci_hd, ciargs);
	return_if_err(err);

	return 0;
}
