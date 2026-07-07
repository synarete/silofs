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

#include <silofs/pstor/spnode.h>

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* carve */

int silofs_carve_base_ubspace(const struct silofs_pexec_ctx *pexec,
                              struct silofs_pnptr           *out_pnptr);

int silofs_carve_base_btspace(const struct silofs_pexec_ctx *pexec,
                              enum silofs_ltype              ltype,
                              struct silofs_pnptr           *out_pnptr);

int silofs_carve_base_lspace(const struct silofs_pexec_ctx *pexec,
                             enum silofs_ltype              ltype,
                             struct silofs_paddr           *out_paddr);

int silofs_carve_btspace_pnptr(const struct silofs_pexec_ctx *pexec,
                               enum silofs_ltype              ltype,
                               struct silofs_pnptr           *out_pnptr);

int silofs_carve_lspace_pnptr(const struct silofs_pexec_ctx *pexec,
                              enum silofs_ltype              ltype,
                              struct silofs_pnptr           *out_pnptr);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* encdec */

int silofs_encrypt_pnode(const struct silofs_pexec_ctx  *pexec,
                         const struct silofs_pnode_info *pni,
                         struct silofs_ctag             *out_ctag);

int silofs_decrypt_pnode(const struct silofs_pexec_ctx  *pexec,
                         const struct silofs_pnode_info *pni,
                         const struct silofs_ctag       *ctag);

int silofs_encrypt_lnode(const struct silofs_pexec_ctx  *pexec,
                         const struct silofs_lnode_info *lni,
                         const struct silofs_pnptr      *pnptr,
                         struct silofs_ctag             *out_ctag);

int silofs_decrypt_lnode(const struct silofs_pexec_ctx  *pexec,
                         const struct silofs_lnode_info *lni,
                         const struct silofs_pnptr      *pnptr,
                         const struct silofs_ctag       *ctag);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* stage */

int silofs_spawn_uber(const struct silofs_pexec_ctx *pexec,
                      const struct silofs_pnptr     *pnptr,
                      struct silofs_uber_info      **out_ubi);

int silofs_stage_uber(const struct silofs_pexec_ctx *pexec,
                      const struct silofs_pnptr     *pnptr,
                      struct silofs_uber_info      **out_ubi);

int silofs_spawn_bldesc(const struct silofs_pexec_ctx *pexec,
                        const struct silofs_pnptr     *pnptr,
                        struct silofs_bldesc_info    **out_bdi);

int silofs_stage_bldesc(const struct silofs_pexec_ctx *pexec,
                        const struct silofs_pnptr     *pnptr,
                        struct silofs_bldesc_info    **out_bdi);

int silofs_spawn_btnode(const struct silofs_pexec_ctx *pexec,
                        const struct silofs_pnptr     *pnptr,
                        struct silofs_btnode_info    **out_bti);

int silofs_stage_btnode(const struct silofs_pexec_ctx *pexec,
                        const struct silofs_pnptr     *pnptr,
                        struct silofs_btnode_info    **out_bti);

int silofs_spawn_lnode2_with(const struct silofs_pexec_ctx *pexec,
                             const struct silofs_laddr     *laddr,
                             const struct silofs_pnptr     *pnptr,
                             struct silofs_lnode_info     **out_lni);

int silofs_claim_lnode_pspace(const struct silofs_pexec_ctx *pexec,
                              const struct silofs_laddr     *laddr,
                              const struct silofs_pnptr     *pnptr);

int silofs_stage_lnode_with(const struct silofs_pexec_ctx *pexec,
                            const struct silofs_laddr     *laddr,
                            const struct silofs_pnptr     *pnptr,
                            enum silofs_lspacef            spacef,
                            struct silofs_lnode_info     **out_lni);

int silofs_detach_lnode_at(const struct silofs_pexec_ctx *pexec,
                           const struct silofs_laddr     *laddr,
                           const struct silofs_pnptr     *pnptr);

int silofs_require_paddr(const struct silofs_pexec_ctx *pexec,
                         const struct silofs_paddr     *paddr);

int silofs_destage_dirty_nodes(const struct silofs_pexec_ctx *pexec);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* vspace */

int silofs_probe_lspace_ref(const struct silofs_pexec_ctx *pexec,
                            const struct silofs_laddr     *laddr,
                            struct silofs_lspace_ref      *out_vspref);

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

int silofs_spawn_spnode2_by(const struct silofs_pexec_ctx *pexec,
                            const struct silofs_laddr     *ref_laddr,
                            struct silofs_spnode_info    **out_spi);

int silofs_require_spnode2_by(const struct silofs_pexec_ctx *pexec,
                              const struct silofs_laddr     *ref_laddr,
                              struct silofs_spnode_info    **out_spi);

#endif /* SILOFS_PSTOR_H_ */
