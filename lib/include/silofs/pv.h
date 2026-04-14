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
#include <silofs/crypto.h>
#include <silofs/addr.h>
#include <silofs/nodes.h>

struct silofs_pexec_ctx;

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

void silofs_bdi_dirtify(struct silofs_bldesc_info *bdi);

void silofs_bdi_undirtify(struct silofs_bldesc_info *bdi);

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

void silofs_bti_self(const struct silofs_btnode_info *bti,
                     struct silofs_btnptr            *out_btnptr);

void silofs_bti_incref(struct silofs_btnode_info *bti);

void silofs_bti_decref(struct silofs_btnode_info *bti);

void silofs_bti_dirtify(struct silofs_btnode_info *bti);

void silofs_bti_undirtify(struct silofs_btnode_info *bti);

bool silofs_bti_isfull(const struct silofs_btnode_info *bti);

void silofs_bti_ignite(struct silofs_btnode_info *bti);

enum silofs_vtype silofs_bti_vspace(const struct silofs_btnode_info *bti);

void silofs_bti_set_vspace(struct silofs_btnode_info *bti,
                           enum silofs_vtype          vspace);

void silofs_bti_mark_root(struct silofs_btnode_info *bti);

bool silofs_bti_marked_root(const struct silofs_btnode_info *bti);

size_t silofs_bti_height(const struct silofs_btnode_info *bti);

void silofs_bti_set_height(struct silofs_btnode_info *bti, size_t height);

int silofs_bti_resolve(const struct silofs_btnode_info *bti, uint64_t key,
                       struct silofs_btnptr *out_btnptr);

int silofs_bti_insert(struct silofs_btnode_info *bti, uint64_t key,
                      const struct silofs_btnptr *btnptr);

int silofs_bti_update(struct silofs_btnode_info *bti, uint64_t key,
                      const struct silofs_btnptr *btnptr);

int silofs_bti_remove(struct silofs_btnode_info *bti, uint64_t key);

int silofs_bti_relink(struct silofs_btnode_info  *bti,
                      const struct silofs_btnptr *cur,
                      const struct silofs_btnptr *alt);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_validate_btnode(const struct silofs_btnode_info *bti);

uint64_t silofs_split_btnode(struct silofs_btnode_info *curr,
                             struct silofs_btnode_info *next);

void silofs_rebind_btchilds(struct silofs_btnode_info  *parent,
                            const struct silofs_btnptr *left,
                            const struct silofs_btnptr *right, uint64_t key);

void silofs_clone_btnode(const struct silofs_btnode_info *bti,
                         struct silofs_btnode_info       *bti_other);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* btree */

int silofs_resolve_vtop(struct silofs_pexec_ctx   *pexec,
                        const struct silofs_vaddr *vaddr,
                        struct silofs_pnptr       *out_pnptr);

int silofs_insert_vtop(struct silofs_pexec_ctx   *pexec,
                       const struct silofs_vaddr *vaddr,
                       const struct silofs_pnptr *pnptr);

int silofs_update_vtop(struct silofs_pexec_ctx   *pexec,
                       const struct silofs_vaddr *vaddr,
                       const struct silofs_pnptr *pnptr);

int silofs_remove_vtop(struct silofs_pexec_ctx   *pexec,
                       const struct silofs_vaddr *vaddr);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* uber */

const struct silofs_layerid *
silofs_ubi_layerid(const struct silofs_uber_info *ubi);

void silofs_ubi_incref(struct silofs_uber_info *ubi);

void silofs_ubi_decref(struct silofs_uber_info *ubi);

void silofs_ubi_dirtify(struct silofs_uber_info *ubi);

void silofs_ubi_undirtify(struct silofs_uber_info *ubi);

void silofs_ubi_update_spawned(struct silofs_uber_info *ubi);

void silofs_ubi_set_btroot_by(struct silofs_uber_info         *ubi,
                              const struct silofs_btnode_info *bti);

void silofs_ubi_btroot_of(const struct silofs_uber_info *ubi,
                          enum silofs_vtype              vtype,
                          struct silofs_btnptr          *out_btnptr);

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
/* space */

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

size_t silofs_spi_get_allocated(const struct silofs_space_info *spi,
                                const struct silofs_vaddr      *vaddr);

bool silofs_spi_test_unwritten(const struct silofs_space_info *spi,
                               const struct silofs_vaddr      *vaddr);

void silofs_spi_clear_unwritten(struct silofs_space_info  *spi,
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

int silofs_require_paddr(struct silofs_pexec_ctx   *pexec,
                         const struct silofs_paddr *paddr);

int silofs_destage_dirty(struct silofs_pexec_ctx *pexec);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/
/* pexec */

/* pv-layer execution-context */
struct silofs_pexec_ctx {
	struct silofs_alloc      *alloc;
	struct silofs_prandgen   *prng;
	struct silofs_dstor      *dstor;
	struct silofs_pcache     *pcache;
	struct silofs_vcache     *vcache;
	struct silofs_mdigest_hd *md_hd;
	struct silofs_cipher_hd  *enc_ci_hd;
	struct silofs_cipher_hd  *dec_ci_hd;
	struct silofs_uber_ref   *ubref;
};

int silofs_format_pv(struct silofs_pexec_ctx *pexec,
                     struct silofs_pnptr     *out_pnptr);

int silofs_reload_pv(struct silofs_pexec_ctx   *pexec,
                     const struct silofs_pnptr *pnptr);

int silofs_spawn_vnode2_at(struct silofs_pexec_ctx   *pexec,
                           const struct silofs_vaddr *vaddr,
                           struct silofs_vnode_info **out_vni);

int silofs_stage_vnode2_at(struct silofs_pexec_ctx   *pexec,
                           const struct silofs_vaddr *vaddr,
                           struct silofs_vnode_info **out_vni);

int silofs_spawn_spnode2_of(struct silofs_pexec_ctx   *pexec,
                            const struct silofs_vaddr *ref_vaddr,
                            struct silofs_space_info **out_spi);

int silofs_stage_spnode2_of(struct silofs_pexec_ctx   *pexec,
                            const struct silofs_vaddr *ref_vaddr,
                            struct silofs_space_info **out_spi);

#endif /* SILOFS_PV_H_ */
