/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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
#ifndef SILOFS_REPO_H_
#define SILOFS_REPO_H_

/* forward declarations */
struct silofs_sb_info;
struct silofs_spnode_info;
struct silofs_spleaf_info;

/* blob-reference using file-descriptor and fixed-size */
struct silofs_blob_fdsz {
	int fd;
	size_t sz;
};

/* blob-reference cache-entry */
struct silofs_blob_info {
	struct silofs_blobid     blobid;
	struct silofs_xiovref    bl_xior;
	struct silofs_cache_elem bl_ce;
	struct silofs_blob_fdsz  bl_fdsz;
	unsigned long            bl_hkey;
};

/* blobs repository */
struct silofs_repo {
	const struct silofs_repo_defs *re_defs;
	struct silofs_crypto    *re_crypto;
	struct silofs_alloc_if  *re_alif;
	struct silofs_cache      re_cache;
	const char              *re_root_dir;
	int                      re_root_dfd;
	int                      re_dots_dfd;
	int                      re_objs_dfd;
	bool                     re_rw;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_blob_info *
silofs_bli_new(struct silofs_alloc_if *alif,
               const struct silofs_blobid *blobid);

void silofs_bli_del(struct silofs_blob_info *bli,
                    struct silofs_alloc_if *alif);

int silofs_bli_store(const struct silofs_blob_info *bli,
                     const struct silofs_oaddr *oaddr,
                     const struct silofs_bytebuf *bb);

int silofs_bli_storev(const struct silofs_blob_info *bli,
                      const struct silofs_oaddr *oaddr,
                      const struct iovec *iov, size_t cnt);

int silofs_bli_load(const struct silofs_blob_info *bli,
                    const struct silofs_oaddr *oaddr,
                    struct silofs_bytebuf *bb);

int silofs_bli_load_bk(const struct silofs_blob_info *bli,
                       const struct silofs_oaddr *oaddr,
                       struct silofs_block *bk);

int silofs_bli_store_bk(const struct silofs_blob_info *bli,
                        const struct silofs_oaddr *oaddr,
                        struct silofs_block *bk);

int silofs_bli_flock(struct silofs_blob_info *bli);

int silofs_bli_funlock(struct silofs_blob_info *bli);

int silofs_bli_resolve(struct silofs_blob_info *bli,
                       const struct silofs_oaddr *oaddr,
                       struct silofs_xiovec *xiov);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repo_init(struct silofs_repo *repo, struct silofs_alloc_if *alif,
                     struct silofs_crypto *crypto, const char *base,
                     size_t memsz_hint, bool rw);

void silofs_repo_fini(struct silofs_repo *repo);

int silofs_repo_format(struct silofs_repo *repo);

int silofs_repo_open(struct silofs_repo *repo);

int silofs_repo_close(struct silofs_repo *repo);

void silofs_repo_drop_cache(struct silofs_repo *repo);

void silofs_repo_relax_cache(struct silofs_repo *repo, int flags);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repo_lookup_blob(struct silofs_repo *repo,
                            const struct silofs_blobid *blobid);

int silofs_repo_spawn_blob(struct silofs_repo *repo,
                           const struct silofs_blobid *blobid,
                           struct silofs_blob_info **out_bli);

int silofs_repo_stage_blob(struct silofs_repo *repo,
                           const struct silofs_blobid *blobid,
                           struct silofs_blob_info **out_bli);

int silofs_repo_remove_blob(struct silofs_repo *repo,
                            const struct silofs_blobid *blobid);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repo_stage_ubk(struct silofs_repo *repo,
                          const struct silofs_oaddr *oaddr,
                          struct silofs_ubk_info **out_ubi);

int silofs_repo_spawn_ubk(struct silofs_repo *repo,
                          const struct silofs_oaddr *oaddr,
                          struct silofs_ubk_info **out_ubi);

int silofs_repo_stage_super(struct silofs_repo *repo,
                            const struct silofs_uaddr *uaddr,
                            struct silofs_sb_info **out_sbi);

int silofs_repo_spawn_super(struct silofs_repo *repo,
                            const struct silofs_uaddr *uaddr,
                            struct silofs_sb_info **out_sbi);

int silofs_repo_ghost_super(struct silofs_repo *repo,
                            const struct silofs_uaddr *uaddr,
                            struct silofs_sb_info **out_sbi);

int silofs_repo_stage_spnode(struct silofs_repo *repo,
                             const struct silofs_uaddr *uaddr,
                             struct silofs_spnode_info **out_sni);

int silofs_repo_spawn_spnode(struct silofs_repo *repo,
                             const struct silofs_uaddr *uaddr,
                             struct silofs_spnode_info **out_sni);

int silofs_repo_ghost_spnode(struct silofs_repo *repo,
                             const struct silofs_uaddr *uaddr,
                             struct silofs_spnode_info **out_sni);

int silofs_repo_stage_spleaf(struct silofs_repo *repo,
                             const struct silofs_uaddr *uaddr,
                             struct silofs_spleaf_info **out_sli);

int silofs_repo_spawn_spleaf(struct silofs_repo *repo,
                             const struct silofs_uaddr *uaddr,
                             struct silofs_spleaf_info **out_sli);

int silofs_repo_ghost_spleaf(struct silofs_repo *repo,
                             const struct silofs_uaddr *uaddr,
                             struct silofs_spleaf_info **out_sli);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repo_load_bsec(const struct silofs_repo *repo,
                          const struct silofs_namestr *nstr,
                          struct silofs_bootsec *out_bsec);

int silofs_repo_save_bsec(const struct silofs_repo *repo,
                          const struct silofs_bootsec *bsec,
                          const struct silofs_namestr *nstr);

int silofs_repo_remove_bsec(const struct silofs_repo *repo,
                            const struct silofs_namestr *nstr);

int silofs_repo_lock_bsec(const struct silofs_repo *repo,
                          const struct silofs_namestr *nstr, int *out_fd);

int silofs_repo_unlock_bsec(const struct silofs_repo *repo,
                            const struct silofs_namestr *nstr, int *pfd);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repo_collect_flush(struct silofs_repo *repo, int flags);


#endif /* SILOFS_REPO_H_ */
