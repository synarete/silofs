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
struct silofs_blobref_info {
	struct silofs_blobid            br_blobid;
	struct silofs_xiovref           br_xior;
	struct silofs_cache_elem        br_ce;
	struct silofs_blob_fdsz         br_fdsz;
	unsigned long                   br_hkey;
};

/* blobs repository */
struct silofs_repo {
	const struct silofs_repo_defs  *re_defs;
	struct silofs_bootldr           re_bootldr;
	struct silofs_bootpath          re_bootpath;
	struct silofs_alloc            *re_alloc;
	struct silofs_cache             re_cache;
	const char                     *re_root_dir;
	int                             re_dots_dfd;
	int                             re_objs_dfd;
	bool                            re_inited;
	bool                            re_rw;

};

/* a pair of warm-cold repositories */
struct silofs_repos {
	struct silofs_repo repo_warm;
	struct silofs_repo repo_cold;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_blobref_info *
silofs_bri_new(struct silofs_alloc *alloc,
               const struct silofs_blobid *blobid);

void silofs_bri_del(struct silofs_blobref_info *bri,
                    struct silofs_alloc *alloc);

int silofs_bri_storev(const struct silofs_blobref_info *bri,
                      const struct silofs_oaddr *oaddr,
                      const struct iovec *iov, size_t cnt);

int silofs_bri_storev2(const struct silofs_blobref_info *bri, loff_t off,
                       const struct iovec *iov, size_t cnt);

int silofs_bri_pwriten(const struct silofs_blobref_info *bri, loff_t off,
                       const void *buf, size_t len);

int silofs_bri_preadn(const struct silofs_blobref_info *bri,
                      loff_t off, void *buf, size_t len);

int silofs_bri_load_bk(const struct silofs_blobref_info *bri,
                       const struct silofs_bkaddr *bkaddr,
                       struct silofs_block *bk);

int silofs_bri_store_bk(const struct silofs_blobref_info *bri,
                        const struct silofs_bkaddr *bkaddr,
                        const struct silofs_block *bk);

int silofs_bri_trim(const struct silofs_blobref_info *bri);

int silofs_bri_flock(struct silofs_blobref_info *bri);

int silofs_bri_funlock(struct silofs_blobref_info *bri);

int silofs_bri_resolve(struct silofs_blobref_info *bri,
                       const struct silofs_oaddr *oaddr,
                       struct silofs_xiovec *xiov);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repo_init(struct silofs_repo *repo, struct silofs_alloc *alloc,
                     const struct silofs_bootpath *bpath, size_t msz, bool rw);

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
                           struct silofs_blobref_info **out_bri);

int silofs_repo_stage_blob(struct silofs_repo *repo,
                           const struct silofs_blobid *blobid,
                           struct silofs_blobref_info **out_bri);

int silofs_repo_remove_blob(struct silofs_repo *repo,
                            const struct silofs_blobid *blobid);

int silofs_repo_require_blob(struct silofs_repo *repo,
                             const struct silofs_blobid *blobid,
                             struct silofs_blobref_info **out_bri);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repo_stage_ubk(struct silofs_repo *repo,
                          const struct silofs_bkaddr *bkaddr,
                          struct silofs_ubk_info **out_ubki);

int silofs_repo_spawn_ubk(struct silofs_repo *repo,
                          const struct silofs_bkaddr *bkaddr,
                          struct silofs_ubk_info **out_ubki);

#endif /* SILOFS_REPO_H_ */
