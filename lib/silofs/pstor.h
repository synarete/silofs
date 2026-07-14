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
#ifndef SILOFS_PSTOR_H_
#define SILOFS_PSTOR_H_

#include <silofs/infra.h>
#include <silofs/crypt.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>
#include <silofs/exec.h>

/* pv-layer execution-context */
struct silofs_pexec_ctx {
	struct silofs_alloc      *alloc;
	struct silofs_prandgen   *prng;
	struct silofs_dstor      *dstor;
	struct silofs_pcache     *pcache;
	struct silofs_pspools    *pspools;
	struct silofs_mdigest_hd *md_hd;
	struct silofs_cipher_hd  *enc_ci_hd;
	struct silofs_cipher_hd  *dec_ci_hd;
	struct silofs_fsroot     *fsroot;
	struct silofs_lcache     *lcache;
	struct silofs_lspools    *lspools;
};

#include <silofs/pstor/uber.h>
#include <silofs/pstor/bldesc.h>
#include <silofs/pstor/btnode.h>
#include <silofs/pstor/btree.h>
#include <silofs/pstor/stage.h>
#include <silofs/pstor/carve.h>
#include <silofs/pstor/encdec.h>
#include <silofs/pstor/mapping.h>
#include <silofs/pstor/spnode.h>

#endif /* SILOFS_PSTOR_H_ */
