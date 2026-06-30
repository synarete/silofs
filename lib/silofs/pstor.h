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

#include <silofs/pstor/dstor.h>
#include <silofs/pstor/repo.h>

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* bldesc */

void silofs_bdi_setdirty(struct silofs_bldesc_info *bdi);

void silofs_bdi_cleardirty(struct silofs_bldesc_info *bdi);

void silofs_bdi_ignite(struct silofs_bldesc_info *bdi);

void silofs_bdi_ignite2(struct silofs_bldesc_info  *bdi,
                        const struct silofs_blobid *blobid);

int silofs_bdi_find_free(const struct silofs_bldesc_info *bdi,
                         struct silofs_paddr             *out_paddr);

int silofs_bdi_test_free(const struct silofs_bldesc_info *bdi,
                         const struct silofs_paddr       *paddr);

int silofs_bdi_mark_free(struct silofs_bldesc_info *bdi,
                         const struct silofs_paddr *paddr);

int silofs_bdi_mark_used(struct silofs_bldesc_info *bdi,
                         const struct silofs_paddr *paddr);

int silofs_validate_bldesc(const struct silofs_bldesc_info *bdi);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* btnode */

#define SILOFS_BTREE_KEY_NULL UINT64_MAX

const struct silofs_pnptr *
silofs_bti_self(const struct silofs_btnode_info *bti);

void silofs_bti_incref(struct silofs_btnode_info *bti);

void silofs_bti_decref(struct silofs_btnode_info *bti);

void silofs_bti_setdirty(struct silofs_btnode_info *bti);

void silofs_bti_cleardirty(struct silofs_btnode_info *bti);

bool silofs_bti_isfull(const struct silofs_btnode_info *bti);

void silofs_bti_update_spawned(struct silofs_btnode_info *bti);

enum silofs_vtype silofs_bti_vspace(const struct silofs_btnode_info *bti);

void silofs_bti_set_vspace(struct silofs_btnode_info *bti,
                           enum silofs_vtype          vspace);

void silofs_bti_mark_root(struct silofs_btnode_info *bti, bool root);

bool silofs_bti_marked_root(const struct silofs_btnode_info *bti);

size_t silofs_bti_height(const struct silofs_btnode_info *bti);

void silofs_bti_set_height(struct silofs_btnode_info *bti, size_t height);

uint64_t silofs_bti_minkey(const struct silofs_btnode_info *bti);

int silofs_bti_resolve(const struct silofs_btnode_info *bti, uint64_t key,
                       struct silofs_pnptr *out_pnptr);

int silofs_bti_insert(struct silofs_btnode_info *bti, uint64_t key,
                      const struct silofs_pnptr *pnptr);

int silofs_bti_update(struct silofs_btnode_info *bti, uint64_t key,
                      const struct silofs_pnptr *pnptr);

int silofs_bti_remove(struct silofs_btnode_info *bti, uint64_t key);

int silofs_bti_relink(struct silofs_btnode_info *bti,
                      const struct silofs_pnptr *cur,
                      const struct silofs_pnptr *alt);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_validate_btnode(const struct silofs_btnode_info *bti);

uint64_t silofs_split_btnode(struct silofs_btnode_info *curr,
                             struct silofs_btnode_info *next);

void silofs_rebind_btchilds(struct silofs_btnode_info *parent,
                            const struct silofs_pnptr *left,
                            const struct silofs_pnptr *right, uint64_t key);

void silofs_clone_btnode(const struct silofs_btnode_info *bti,
                         struct silofs_btnode_info       *bti_other);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* uber */
#include <silofs/pstor/uber.h>
/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* spnode */

#include <silofs/pstor/spnode.h>

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

/* pv-layer execution-context */
struct silofs_pexec_ctx {
	struct silofs_alloc      *alloc;
	struct silofs_prandgen   *prng;
	struct silofs_dstor      *dstor;
	struct silofs_pcache     *pcache;
	struct silofs_vcache     *vcache;
	struct silofs_freevsqs   *fvsqs;
	struct silofs_freepaqs   *fpaqs;
	struct silofs_mdigest_hd *md_hd;
	struct silofs_cipher_hd  *enc_ci_hd;
	struct silofs_cipher_hd  *dec_ci_hd;
	struct silofs_uber_ref   *ubref;
};

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* btree (mapping) */

struct silofs_btree_path {
	struct silofs_btnode_info *bti[SILOFS_BTREE_HEIGHT_MAX];
	unsigned int               cnt;
};

int silofs_resolve_vtop_bpath(struct silofs_pexec_ctx   *pexec,
                              const struct silofs_vaddr *vaddr,
                              struct silofs_btree_path  *out_bpath);

int silofs_resolve_vtop_parent(struct silofs_pexec_ctx   *pexec,
                               const struct silofs_vaddr *vaddr,
                               const struct silofs_paddr *paddr,
                               struct silofs_pnptr       *out_pnptr);

int silofs_resolve_vtop_btleaf(struct silofs_pexec_ctx   *pexec,
                               const struct silofs_vaddr *vaddr,
                               struct silofs_pnptr       *out_pnptr);

int silofs_resolve_vtop_mapping(struct silofs_pexec_ctx   *pexec,
                                const struct silofs_vaddr *vaddr,
                                struct silofs_pnptr       *out_pnptr);

int silofs_create_vtop_mapping(struct silofs_pexec_ctx   *pexec,
                               const struct silofs_vaddr *vaddr,
                               const struct silofs_pnptr *pnptr);

int silofs_update_vtop_mapping(struct silofs_pexec_ctx   *pexec,
                               const struct silofs_vaddr *vaddr,
                               const struct silofs_pnptr *pnptr);

int silofs_remove_vtop_mapping(struct silofs_pexec_ctx   *pexec,
                               const struct silofs_vaddr *vaddr);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* carve */

int silofs_carve_base_ubspace(const struct silofs_pexec_ctx *pexec,
                              struct silofs_pnptr           *out_pnptr);

int silofs_carve_base_btspace(const struct silofs_pexec_ctx *pexec,
                              enum silofs_vtype              vtype,
                              struct silofs_pnptr           *out_pnptr);

int silofs_carve_base_vspace(const struct silofs_pexec_ctx *pexec,
                             enum silofs_vtype              vtype,
                             struct silofs_paddr           *out_paddr);

int silofs_carve_btspace(const struct silofs_pexec_ctx *pexec,
                         enum silofs_vtype              vtype,
                         struct silofs_pnptr           *out_pnptr);

int silofs_carve_vspace(const struct silofs_pexec_ctx *pexec,
                        enum silofs_vtype              vtype,
                        struct silofs_pnptr           *out_pnptr);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* encdec */

int silofs_encrypt_pnode(const struct silofs_pexec_ctx  *pexec,
                         const struct silofs_pnode_info *pni,
                         struct silofs_ctag             *out_ctag);

int silofs_decrypt_pnode(const struct silofs_pexec_ctx  *pexec,
                         const struct silofs_pnode_info *pni,
                         const struct silofs_ctag       *ctag);

int silofs_encrypt_vnode(const struct silofs_pexec_ctx  *pexec,
                         const struct silofs_vnode_info *vni,
                         const struct silofs_pnptr      *pnptr,
                         struct silofs_ctag             *out_ctag);

int silofs_decrypt_vnode(const struct silofs_pexec_ctx  *pexec,
                         const struct silofs_vnode_info *vni,
                         const struct silofs_pnptr      *pnptr,
                         const struct silofs_ctag       *ctag);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* stage */

int silofs_spawn_uber(struct silofs_pexec_ctx   *pexec,
                      const struct silofs_pnptr *pnptr,
                      struct silofs_uber_info  **out_ubi);

int silofs_stage_uber(struct silofs_pexec_ctx   *pexec,
                      const struct silofs_pnptr *pnptr,
                      struct silofs_uber_info  **out_ubi);

int silofs_spawn_bldesc(struct silofs_pexec_ctx    *pexec,
                        const struct silofs_pnptr  *pnptr,
                        struct silofs_bldesc_info **out_bdi);

int silofs_stage_bldesc(struct silofs_pexec_ctx    *pexec,
                        const struct silofs_pnptr  *pnptr,
                        struct silofs_bldesc_info **out_bdi);

int silofs_spawn_btnode(struct silofs_pexec_ctx    *pexec,
                        const struct silofs_pnptr  *pnptr,
                        struct silofs_btnode_info **out_bti);

int silofs_stage_btnode(struct silofs_pexec_ctx    *pexec,
                        const struct silofs_pnptr  *pnptr,
                        struct silofs_btnode_info **out_bti);

int silofs_spawn_vnode2_with(struct silofs_pexec_ctx   *pexec,
                             const struct silofs_vaddr *vaddr,
                             const struct silofs_pnptr *pnptr,
                             struct silofs_vnode_info **out_vni);

int silofs_claim_vnode2_space2(struct silofs_pexec_ctx   *pexec,
                               const struct silofs_vaddr *vaddr,
                               const struct silofs_pnptr *pnptr);

int silofs_stage_vnode2_with(struct silofs_pexec_ctx   *pexec,
                             const struct silofs_vaddr *vaddr,
                             const struct silofs_pnptr *pnptr,
                             enum silofs_spacef         spacef,
                             struct silofs_vnode_info **out_vni);

int silofs_detach_vnode2_at(struct silofs_pexec_ctx   *pexec,
                            const struct silofs_vaddr *vaddr,
                            const struct silofs_pnptr *pnptr);

int silofs_require_paddr(struct silofs_pexec_ctx   *pexec,
                         const struct silofs_paddr *paddr);

int silofs_destage_dirty_nodes(struct silofs_pexec_ctx *pexec);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* vspace */

int silofs_claim_free_vspace(struct silofs_pexec_ctx *pexec,
                             enum silofs_vtype        vtype,
                             struct silofs_vaddr     *out_vaddr);

int silofs_update_used_vspace(struct silofs_pexec_ctx   *pexec,
                              const struct silofs_vaddr *vaddr, bool incref);

int silofs_probe_vspace_ref(struct silofs_pexec_ctx   *pexec,
                            const struct silofs_vaddr *vaddr,
                            struct silofs_vspace_ref  *out_vspref);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* trans */

int silofs_probe_vnode2_at(struct silofs_pexec_ctx   *pexec,
                           const struct silofs_vaddr *vaddr);

int silofs_stage_vnode2_at(struct silofs_pexec_ctx   *pexec,
                           const struct silofs_vaddr *vaddr,
                           struct silofs_vnode_info **out_vni);

int silofs_spawn_vnode2(struct silofs_pexec_ctx   *pexec,
                        enum silofs_vtype          vtype,
                        struct silofs_vnode_info **out_vni);

int silofs_spawn_vnode2_at(struct silofs_pexec_ctx   *pexec,
                           const struct silofs_vaddr *vaddr,
                           struct silofs_vnode_info **out_vni);

int silofs_claim_vnode2_space(struct silofs_pexec_ctx *pexec,
                              enum silofs_vtype        vtype,
                              struct silofs_vaddr     *out_vaddr);

int silofs_isshared_vnode2_at(struct silofs_pexec_ctx   *pexec,
                              const struct silofs_vaddr *vaddr, bool *out_res);

int silofs_share_vnode2_at(struct silofs_pexec_ctx   *pexec,
                           const struct silofs_vaddr *vaddr);

int silofs_unshare_vnode2_at(struct silofs_pexec_ctx   *pexec,
                             const struct silofs_vaddr *vaddr, bool *out_last);

int silofs_reclaim_vnode2_at(struct silofs_pexec_ctx   *pexec,
                             const struct silofs_vaddr *vaddr, bool *out_last);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_stage_spnode2_by(struct silofs_pexec_ctx     *pexec,
                            const struct silofs_vaddr   *ref_vaddr,
                            struct silofs_spnode_info2 **out_spi);

int silofs_spawn_spnode2_by(struct silofs_pexec_ctx     *pexec,
                            const struct silofs_vaddr   *ref_vaddr,
                            struct silofs_spnode_info2 **out_spi);

int silofs_require_spnode2_by(struct silofs_pexec_ctx     *pexec,
                              const struct silofs_vaddr   *ref_vaddr,
                              struct silofs_spnode_info2 **out_spi);

int silofs_mark_unwritten_at2(struct silofs_pexec_ctx   *pexec,
                              const struct silofs_vaddr *ref_vaddr);

int silofs_clear_unwritten_at2(struct silofs_pexec_ctx   *pexec,
                               const struct silofs_vaddr *ref_vaddr);

int silofs_test_unwritten_at2(struct silofs_pexec_ctx   *pexec,
                              const struct silofs_vaddr *ref_vaddr,
                              bool                      *out_unwritten);

int silofs_test_vtop_mapping(struct silofs_pexec_ctx   *pexec,
                             const struct silofs_vaddr *vaddr,
                             bool                      *out_exists);

#endif /* SILOFS_PSTOR_H_ */
