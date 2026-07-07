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
	struct silofs_uber_ref   *ubref;

	struct silofs_lcache  *lcache;
	struct silofs_lspools *lspools;
};

#include <silofs/pstor/dstor.h>
#include <silofs/pstor/repo.h>
#include <silofs/pstor/uber.h>
#include <silofs/pstor/bldesc.h>
#include <silofs/pstor/btnode.h>
#include <silofs/pstor/btree.h>
#include <silofs/pstor/stage.h>
#include <silofs/pstor/carve.h>
#include <silofs/pstor/encdec.h>

#include <silofs/pstor/spnode.h>

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* trans */

int silofs_stage_lnode_at(const struct silofs_pexec_ctx *pexec,
                          const struct silofs_laddr     *laddr,
                          struct silofs_lnode_info     **out_lni);

int silofs_create_ltop_mapping(const struct silofs_pexec_ctx *pexec,
                               const struct silofs_laddr     *laddr,
                               struct silofs_pnptr           *out_pnptr);

int silofs_spawn_lnode2_at(const struct silofs_pexec_ctx *pexec,
                           const struct silofs_laddr     *laddr,
                           struct silofs_lnode_info     **out_lni);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_reclaim_lnode_mapping(const struct silofs_pexec_ctx *pexec,
                                 const struct silofs_laddr     *laddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_stage_spnode_by(const struct silofs_pexec_ctx *pexec,
                           const struct silofs_laddr     *ref_laddr,
                           struct silofs_spnode_info    **out_spi);

#endif /* SILOFS_PSTOR_H_ */
