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
#ifndef SILOFS_COREFS_H_
#define SILOFS_COREFS_H_

#include <silofs/infra.h>
#include <silofs/crypt.h>
#include <silofs/nodes.h>

struct silofs_core_refs {
	struct silofs_alloc        *alloc;
	struct silofs_lblock       *nilbk;
	struct silofs_prandgen     *prng;
	struct silofs_mdigest_hd   *md_hd;
	struct silofs_cipher_hd    *enc_ci_hd;
	struct silofs_cipher_hd    *dec_ci_hd;
	struct silofs_fsroot       *fsroot;
	struct silofs_dstor        *dstor;
	struct silofs_repo         *repo;
	struct silofs_pcache       *pcache;
	struct silofs_pspools      *pspools;
	struct silofs_lcache       *lcache;
	struct silofs_lspools      *lspools;
	struct silofs_iis_predq    *iis_predq;
	struct silofs_uber_info    *ubi;
	const struct silofs_idsmap *idsmap;
	const struct silofs_uconv  *uconv;
};

int silofs_sanitize_status_code(int status);

void silofs_relax_caches(const struct silofs_core_refs *corefs, int flags);

void silofs_drop_caches(const struct silofs_core_refs *corefs);

int silofs_reinit_ciphers(const struct silofs_core_refs *corefs);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_new_core_obj(size_t objsz, void **out_obj);

void silofs_del_core_obj(void *obj, size_t objsz);

#endif /* SILOFS_COREFS_H_ */
