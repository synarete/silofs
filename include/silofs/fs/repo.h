/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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


struct silofs_qalloc;
struct silofs_oaddr;
struct silofs_fiovec;
struct silofs_blob_info;


/* blob-reference using file-descriptor and fixed-size */
struct silofs_blob_fdsz {
	int fd;
	int sz;
};

/* blob-reference cache-entry */
struct silofs_blob_info {
	struct silofs_blobid     bl_bid;
	struct silofs_cache_elem bl_ce;
	struct silofs_fiovref    bl_fir;
	struct silofs_blob_fdsz  bl_fdsz;
	unsigned long            bl_hkey;
};

/* local repository of file-system's blobs */
struct silofs_repo {
	struct silofs_cache     *re_cache;
	const char              *re_base_dir;
	int                      re_base_dfd;
	const char              *re_lock_name;
	int                      re_lock_fd;
	const char              *re_objs_name;
	unsigned int             re_objs_nsubs;
	int                      re_objs_dfd;
	const char              *re_refs_name;
	int                      re_refs_dfd;
	bool                     re_rw;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_blob_info *
silofs_bli_new(struct silofs_alloc_if *alif, const struct silofs_blobid *bid);

void silofs_bli_del(struct silofs_blob_info *bli,
                    struct silofs_alloc_if *alif);


void silofs_bli_init(struct silofs_blob_info *bli,
                     const struct silofs_blobid *bid);

void silofs_bli_fini(struct silofs_blob_info *bli);

int silofs_bli_store(struct silofs_blob_info *bli,
                     const struct silofs_oaddr *oaddr, const void *obj);

int silofs_bli_storev(struct silofs_blob_info *bli,
                      const struct silofs_oaddr *oaddr,
                      const struct iovec *iov, size_t cnt);

int silofs_bli_load(struct silofs_blob_info *bli,
                    const struct silofs_oaddr *oaddr, void *bobj);

int silofs_bli_close(struct silofs_blob_info *bli);

int silofs_bli_load_bk(struct silofs_blob_info *bli, struct silofs_block *bk,
                       const struct silofs_oaddr *oaddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repo_init(struct silofs_repo *repo,
                     struct silofs_cache *cache,
                     const char *basedir, bool rw);

void silofs_repo_fini(struct silofs_repo *repo);

int silofs_repo_format(struct silofs_repo *repo);

int silofs_repo_open(struct silofs_repo *repo);

int silofs_repo_close(struct silofs_repo *repo);

int silofs_repo_save_ref(const struct silofs_repo *repo,
                         const struct silofs_namestr *namestr,
                         const struct silofs_main_bootrec *mbr);

int silofs_repo_load_ref(const struct silofs_repo *repo,
                         const struct silofs_namestr *namestr,
                         struct silofs_main_bootrec *mbr);

int silofs_repo_spawn_blob(const struct silofs_repo *repo,
                           const struct silofs_blobid *bid,
                           struct silofs_blob_info **out_bli);

int silofs_repo_stage_blob(const struct silofs_repo *repo,
                           const struct silofs_blobid *bid,
                           struct silofs_blob_info **out_bli);

int silofs_repo_clone_blob(const struct silofs_repo *repo,
                           const struct silofs_blob_info *bli_src,
                           const struct silofs_blobid *bid_dst,
                           struct silofs_blob_info **out_bli_dst);

int silofs_repo_collect_flush(struct silofs_repo *repo, int flags);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_resolve_sb_path(const struct silofs_main_bootrec *mbr,
                           struct silofs_namebuf *out_nb);
#endif /* SILOFS_REPO_H_ */
