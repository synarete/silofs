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
#ifndef SILOFS_PV_H_
#define SILOFS_PV_H_

#include <silofs/base.h>
#include <silofs/crypt.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* dstor */

/* hash-map + LRU-queue of open blob-refs */
struct silofs_dstor_hq {
	struct silofs_listq      dsq_lru;
	struct silofs_list_head *dsq_htb;
	size_t                   dsq_htb_nelems;
};

/* blob-storage using regular files within flat directory */
struct silofs_dstor {
	struct silofs_dstor_hq   ds_hq;
	struct silofs_mdigest_hd ds_md;
	struct silofs_alloc     *ds_alloc;
	int                      ds_dfd;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_dstor_init(struct silofs_dstor *dstor, struct silofs_alloc *alloc);

void silofs_dstor_fini(struct silofs_dstor *dstor);

int silofs_dstor_open(struct silofs_dstor *dstor, int root_dfd);

void silofs_dstor_close(struct silofs_dstor *dstor);

void silofs_dstor_relax(struct silofs_dstor *dstor);

void silofs_dstor_drop(struct silofs_dstor *dstor);

int silofs_dstor_sync(const struct silofs_dstor *dstor);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_dstor_spawn_blob(struct silofs_dstor        *dstor,
                            const struct silofs_blobid *blobid);

int silofs_dstor_stage_blob(struct silofs_dstor        *dstor,
                            const struct silofs_blobid *blobid);

int silofs_dstor_stat_blob(struct silofs_dstor        *dstor,
                           const struct silofs_blobid *blobid,
                           struct stat                *out_st);

int silofs_dstor_require_blob(struct silofs_dstor        *dstor,
                              const struct silofs_blobid *blobid);

int silofs_dstor_require_blob_at(struct silofs_dstor        *dstor,
                                 const struct silofs_blobid *blobid,
                                 off_t                       pos);

int silofs_dstor_access_blob_at(struct silofs_dstor        *dstor,
                                const struct silofs_blobid *blobid, off_t pos);

int silofs_dstor_remove_blob(struct silofs_dstor        *dstor,
                             const struct silofs_blobid *blobid);

int silofs_dstor_flush_blob(struct silofs_dstor        *dstor,
                            const struct silofs_blobid *blobid);

int silofs_dstor_punch_blob(struct silofs_dstor        *dstor,
                            const struct silofs_blobid *blobid);

int silofs_dstor_read_blob_at(struct silofs_dstor        *dstor,
                              const struct silofs_blobid *blobid, off_t pos,
                              void *buf, size_t len);

int silofs_dstor_write_blob_at(struct silofs_dstor        *dstor,
                               const struct silofs_blobid *blobid, off_t pos,
                               const void *buf, size_t len);

int silofs_dstor_writev_blob_at(struct silofs_dstor        *dstor,
                                const struct silofs_blobid *blobid, off_t pos,
                                const struct iovec *iov, size_t n);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_dstor_stat_mbr(struct silofs_dstor       *dstor,
                          const struct silofs_mbref *mbref,
                          struct stat               *out_st);

int silofs_dstor_save_mbr(struct silofs_dstor       *dstor,
                          const struct silofs_mbref *mbref, const void *buf,
                          size_t len);

int silofs_dstor_load_mbr(struct silofs_dstor       *dstor,
                          const struct silofs_mbref *mbref, void *buf,
                          size_t len);

int silofs_dstor_unref_mbr(struct silofs_dstor       *dstor,
                           const struct silofs_mbref *mbref);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* repo */

/* repository logical-segments-file hash-map */
struct silofs_repo_htbl {
	size_t                   rh_size;
	size_t                   rh_nelems;
	struct silofs_list_head *rh_arr;
};

/* repository */
struct silofs_repo {
	struct silofs_mutex      re_mutex;
	struct silofs_repo_htbl  re_htbl;
	struct silofs_listq      re_lruq;
	struct silofs_mdigest_hd re_md_hd;
	struct silofs_dstor      re_dstor;
	struct silofs_alloc     *re_alloc;

	int  re_root_dfd;
	int  re_dots_dfd;
	int  re_blobs_dfd;
	bool re_rdonly;
	bool re_opened;

	const struct silofs_repo_defs *re_defs;
};

int silofs_repo_init(struct silofs_repo *repo, struct silofs_alloc *alloc);

void silofs_repo_fini(struct silofs_repo *repo);

int silofs_repo_format(struct silofs_repo *repo, const char *rootdir);

int silofs_repo_open(struct silofs_repo *repo, const char *rootdir,
                     enum silofs_flags flags);

int silofs_repo_close(struct silofs_repo *repo);

int silofs_repo_fsync_all(struct silofs_repo *repo);

void silofs_repo_drop_some(struct silofs_repo *repo);

void silofs_repo_relax(struct silofs_repo *repo);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repo_stat_lseg(struct silofs_repo       *repo,
                          const struct silofs_lsid *lsid, bool allow_cache,
                          struct stat *out_st);

int silofs_repo_spawn_lseg(struct silofs_repo       *repo,
                           const struct silofs_lsid *lsid);

int silofs_repo_stage_lseg(struct silofs_repo *repo, bool rw,
                           const struct silofs_lsid *lsid);

int silofs_repo_remove_lseg(struct silofs_repo       *repo,
                            const struct silofs_lsid *lsid);

int silofs_repo_punch_lseg(struct silofs_repo       *repo,
                           const struct silofs_lsid *lsid);

int silofs_repo_require_lseg(struct silofs_repo       *repo,
                             const struct silofs_lsid *lsid);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repo_require_laddr(struct silofs_repo        *repo,
                              const struct silofs_laddr *laddr);

int silofs_repo_writev_at(struct silofs_repo        *repo,
                          const struct silofs_laddr *laddr,
                          const struct iovec *iov, size_t cnt);

int silofs_repo_write_at(struct silofs_repo        *repo,
                         const struct silofs_laddr *laddr, const void *buf,
                         size_t len);

int silofs_repo_read_at(struct silofs_repo        *repo,
                        const struct silofs_laddr *laddr, void *buf,
                        size_t len);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* bldesc */

void silofs_bdi_markdirty(struct silofs_bldesc_info *bdi);

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

void silofs_bti_markdirty(struct silofs_btnode_info *bti);

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

/* uber stat per sub-type */
struct silofs_uber_stat {
	size_t bn;
	size_t vn;
};

struct silofs_uber_stats {
	struct silofs_uber_stat st[SILOFS_VTYPE_LAST];
};

const struct silofs_pnptr *silofs_ubi_self(const struct silofs_uber_info *ubi);

const struct silofs_layerid *
silofs_ubi_layerid(const struct silofs_uber_info *ubi);

void silofs_ubi_incref(struct silofs_uber_info *ubi);

void silofs_ubi_decref(struct silofs_uber_info *ubi);

void silofs_ubi_markdirty(struct silofs_uber_info *ubi);

void silofs_ubi_cleardirty(struct silofs_uber_info *ubi);

void silofs_ubi_update_spawned(struct silofs_uber_info *ubi);

bool silofs_ubi_has_btroot(const struct silofs_uber_info *ubi,
                           const struct silofs_pnptr     *pnptr);

void silofs_ubi_set_btroot(struct silofs_uber_info   *ubi,
                           const struct silofs_pnptr *pnptr);

void silofs_ubi_set_btroot_by(struct silofs_uber_info         *ubi,
                              const struct silofs_btnode_info *bti);

void silofs_ubi_btroot_of(const struct silofs_uber_info *ubi,
                          enum silofs_vtype              vtype,
                          struct silofs_pnptr           *out_pnptr);

void silofs_ubi_spdesc_of(const struct silofs_uber_info *ubi,
                          const struct silofs_stype     *stype,
                          struct silofs_spdesc          *out_spdesc);

void silofs_ubi_start_spdesc(struct silofs_uber_info   *ubi,
                             const struct silofs_paddr *paddr);

void silofs_ubi_update_spdesc(struct silofs_uber_info    *ubi,
                              const struct silofs_spdesc *spdesc);

void silofs_ubi_inc_count_by(struct silofs_uber_info    *ubi,
                             const struct silofs_blobid *blobid);

void silofs_ubi_dec_count_by(struct silofs_uber_info    *ubi,
                             const struct silofs_blobid *blobid);

void silofs_ubi_stat_of(const struct silofs_uber_info *ubi,
                        enum silofs_vtype              vtype,
                        struct silofs_uber_stat       *out_stat);

void silofs_ubi_collect_stats(const struct silofs_uber_info *ubi,
                              struct silofs_uber_stats      *out_stats);

bool silofs_ubi_onsame_layer(const struct silofs_uber_info   *ubi,
                             const struct silofs_btnode_info *bti);

int silofs_validate_uber(const struct silofs_uber_info *ubi);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_uber_ref {
	struct silofs_uber_info *ubi;
};

void silofs_ubref_init(struct silofs_uber_ref *ubref);

void silofs_ubref_fini(struct silofs_uber_ref *ubref);

void silofs_ubref_update(struct silofs_uber_ref  *ubref,
                         struct silofs_uber_info *ubi);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* spnode */

struct silofs_vspace_ref {
	size_t             refcnt;
	enum silofs_spacef flags;
};

struct silofs_space_info *silofs_spi_from_vni(struct silofs_vnode_info *vni);

void silofs_spi_incref(struct silofs_space_info *spi);

void silofs_spi_decref(struct silofs_space_info *spi);

void silofs_spi_setup_spawned(struct silofs_space_info  *spi,
                              const struct silofs_vaddr *ref_vaddr);

void silofs_spi_setup_staged(struct silofs_space_info *spi);

int silofs_spi_find_free(const struct silofs_space_info *spi,
                         struct silofs_vaddr            *out_vaddr);

void silofs_spi_inc_allocated(struct silofs_space_info  *spi,
                              const struct silofs_vaddr *vaddr);

void silofs_spi_dec_allocated(struct silofs_space_info  *spi,
                              const struct silofs_vaddr *vaddr);

void silofs_spi_clear_unwritten(struct silofs_space_info  *spi,
                                const struct silofs_vaddr *vaddr);

void silofs_spi_vspace_ref(const struct silofs_space_info *spi,
                           const struct silofs_vaddr      *vaddr,
                           struct silofs_vspace_ref       *out_vspref);

void silofs_spi_clone_from(struct silofs_space_info       *spi,
                           const struct silofs_space_info *spi_other);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* vspmap */

/* vspace address span */
struct silofs_vspan {
	off_t  off;
	size_t len;
};

/* queue of previously-allocated now-free vspace addresses */
struct silofs_vsp_queue {
	struct silofs_vspan vsq[64];
	uint32_t            vsq_count;
	uint32_t            vsq_objsz;
};

/* vspace mapping range entry in AVL tree */
struct silofs_vsp_entry {
	struct silofs_avl_node vspe_an;
	struct silofs_vspan    vspe_span;
};

/* vspace free addresses in-memory mapping */
struct silofs_vspmap {
	struct silofs_vsp_queue vspq;
	struct silofs_avl       avl;
	struct silofs_alloc    *alloc;
};

/* vspace free addresses by vtype */
struct silofs_vspmaps {
	struct silofs_vspmap vspm[SILOFS_VTYPE_LAST - 1];
};

int silofs_vspmaps_init(struct silofs_vspmaps *vspms,
                        struct silofs_alloc   *alloc);

void silofs_vspmaps_fini(struct silofs_vspmaps *vspms);

int silofs_vspmaps_push(struct silofs_vspmaps     *vspms,
                        const struct silofs_vaddr *vaddr);

int silofs_vspmaps_pull(struct silofs_vspmaps *vspms, enum silofs_vtype vtype,
                        struct silofs_vaddr *out_vaddr);

int silofs_vspmaps_base(const struct silofs_vspmaps *vspms,
                        enum silofs_vtype vtype, off_t off, off_t *out_base);

void silofs_vspmaps_drop(struct silofs_vspmaps *vspms);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

/* pv-layer execution-context */
struct silofs_pexec_ctx {
	struct silofs_alloc      *alloc;
	struct silofs_prandgen   *prng;
	struct silofs_dstor      *dstor;
	struct silofs_pcache     *pcache;
	struct silofs_vcache     *vcache;
	struct silofs_vspmaps    *vspmaps;
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
                              enum silofs_vtype              vspace,
                              struct silofs_pnptr           *out_pnptr);

int silofs_carve_base_vspace(const struct silofs_pexec_ctx *pexec,
                             enum silofs_vtype              vtype,
                             struct silofs_paddr           *out_paddr);

int silofs_carve_next_btspace(const struct silofs_pexec_ctx *pexec,
                              enum silofs_vtype              vtype,
                              struct silofs_pnptr           *out_pnptr);

int silofs_carve_next_vspace(const struct silofs_pexec_ctx *pexec,
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

int silofs_spawn_vnode2(struct silofs_pexec_ctx   *pexec,
                        const struct silofs_vaddr *vaddr,
                        const struct silofs_pnptr *pnptr,
                        struct silofs_vnode_info **out_vni);

int silofs_stage_vnode2(struct silofs_pexec_ctx   *pexec,
                        const struct silofs_vaddr *vaddr,
                        const struct silofs_pnptr *pnptr,
                        struct silofs_vnode_info **out_vni);

int silofs_detach_vnode2(struct silofs_pexec_ctx   *pexec,
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

int silofs_probe_vnode2(struct silofs_pexec_ctx   *pexec,
                        const struct silofs_vaddr *vaddr);

int silofs_fetch_vnode2(struct silofs_pexec_ctx   *pexec,
                        const struct silofs_vaddr *vaddr,
                        struct silofs_vnode_info **out_vni);

int silofs_create_vnode2(struct silofs_pexec_ctx   *pexec,
                         enum silofs_vtype          vtype,
                         struct silofs_vnode_info **out_vni);

int silofs_claim_vnode2_space(struct silofs_pexec_ctx *pexec,
                              enum silofs_vtype        vtype,
                              struct silofs_vaddr     *out_vaddr);

int silofs_reclaim_vnode2(struct silofs_pexec_ctx  *pexec,
                          struct silofs_vnode_info *vni);

int silofs_isshared_vnode2_at(struct silofs_pexec_ctx   *pexec,
                              const struct silofs_vaddr *vaddr, bool *out_res);

int silofs_share_vnode2_at(struct silofs_pexec_ctx   *pexec,
                           const struct silofs_vaddr *vaddr);

int silofs_unshare_vnode2_at(struct silofs_pexec_ctx   *pexec,
                             const struct silofs_vaddr *vaddr);

int silofs_reclaim_vnode2_at(struct silofs_pexec_ctx   *pexec,
                             const struct silofs_vaddr *vaddr);

int silofs_fetch_spnode2_of(struct silofs_pexec_ctx   *pexec,
                            const struct silofs_vaddr *ref_vaddr,
                            struct silofs_space_info **out_spi);

int silofs_require_spnode2_of(struct silofs_pexec_ctx   *pexec,
                              const struct silofs_vaddr *ref_vaddr,
                              struct silofs_space_info **out_spi);

int silofs_clear_unwritten_at2(struct silofs_pexec_ctx   *pexec,
                               const struct silofs_vaddr *ref_vaddr);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* format */

int silofs_format_pv(struct silofs_pexec_ctx *pexec,
                     struct silofs_pnptr     *out_pnptr);

int silofs_reload_pv(struct silofs_pexec_ctx   *pexec,
                     const struct silofs_pnptr *pnptr);

#endif /* SILOFS_PV_H_ */
