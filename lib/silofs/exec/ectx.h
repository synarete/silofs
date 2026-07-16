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
#ifndef SILOFS_ECTX_H_
#define SILOFS_ECTX_H_

#include <silofs/infra.h>
#include <silofs/crypt.h>
#include <silofs/nodes.h>

struct silofs_exec_ctx {
	struct silofs_alloc        *alloc;
	struct silofs_lblock       *nilbk;
	struct silofs_prandgen     *prng;
	struct silofs_mdigest_hd   *md_hd;
	struct silofs_cipher_hd    *enc_ci_hd;
	struct silofs_cipher_hd    *dec_ci_hd;
	struct silofs_fsroot       *fsroot;
	struct silofs_dstor        *dstor;
	struct silofs_pcache       *pcache;
	struct silofs_pspools      *pspools;
	struct silofs_lcache       *lcache;
	struct silofs_lspools      *lspools;
	struct silofs_uber_info    *ubi;
	const struct silofs_idsmap *idsmap;
};

void silofs_relax_caches(const struct silofs_exec_ctx *ectx, int flags);

void silofs_drop_caches(const struct silofs_exec_ctx *ectx);

int silofs_reinit_ciphers(const struct silofs_exec_ctx *ectx);

#endif /* SILOFS_ECTX_H_ */
