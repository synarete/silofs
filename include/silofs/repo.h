/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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


/* repository control flags */
#define SILOFS_REPOF_RDONLY     (1)

/* blob control file */
struct silofs_blobf {
	struct silofs_namebuf           b_name;
	struct silofs_cache_elem        b_ce;
	struct silofs_blobid            b_blobid;
	long                            b_size;
	int                             b_fd;
	bool                            b_flocked;
	bool                            b_rdonly;
};

/* blob repository base config */
struct silofs_repo_base {
	struct silofs_bootpath          bootpath;
	struct silofs_alloc            *alloc;
	struct silofs_cache            *cache;
	long                            flags;
};

/* blobs repository */
struct silofs_repo {
	struct silofs_repo_base         re;
	struct silofs_mdigest           re_mdigest;
	int                             re_root_dfd;
	int                             re_dots_dfd;
	int                             re_blobs_dfd;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_blobf *
silofs_blobf_new(struct silofs_alloc *alloc,
                 const struct silofs_blobid *blobid);

void silofs_blobf_del(struct silofs_blobf *blobf,
                      struct silofs_alloc *alloc);

int silofs_blobf_pwriten(struct silofs_blobf *blobf, loff_t off,
                         const void *buf, size_t len, bool sync);

int silofs_blobf_pwritevn(struct silofs_blobf *blobf, loff_t off,
                          const struct iovec *iov, size_t cnt, bool sync);

int silofs_blobf_load_bk(struct silofs_blobf *blobf,
                         const struct silofs_bkaddr *bkaddr,
                         struct silofs_lbk_info *lbki);

int silofs_blobf_trim_nbks(struct silofs_blobf *blobf,
                           const struct silofs_bkaddr *bkaddr, size_t cnt);

int silofs_blobf_require_bk(struct silofs_blobf *blobf,
                            const struct silofs_bkaddr *bkaddr);

int silofs_blobf_check_bk(struct silofs_blobf *blobf,
                          const struct silofs_bkaddr *bkaddr);

int silofs_blobf_resolve(struct silofs_blobf *blobf,
                         const struct silofs_oaddr *oaddr,
                         struct silofs_iovec *iov);

int silofs_blobf_flock(struct silofs_blobf *blobf);

int silofs_blobf_funlock(struct silofs_blobf *blobf);

int silofs_blobf_fsync(struct silofs_blobf *blobf);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_repo_init(struct silofs_repo *repo,
                     const struct silofs_repo_base *repo_base);

void silofs_repo_fini(struct silofs_repo *repo);

int silofs_repo_format(struct silofs_repo *repo);

int silofs_repo_open(struct silofs_repo *repo);

int silofs_repo_close(struct silofs_repo *repo);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repo_save_bootrec(struct silofs_repo *repo,
                             const struct silofs_uuid *uuid,
                             const struct silofs_bootrec *brec);

int silofs_repo_load_bootrec(struct silofs_repo *repo,
                             const struct silofs_uuid *uuid,
                             struct silofs_bootrec *out_brec);

int silofs_repo_stat_bootrec(struct silofs_repo *repo,
                             const struct silofs_uuid *uuid,
                             struct stat *out_st);

int silofs_repo_unlink_bootrec(struct silofs_repo *repo,
                               const struct silofs_uuid *uuid);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repo_stat_blob(struct silofs_repo *repo,
                          const struct silofs_blobid *blobid,
                          struct stat *out_st);

int silofs_repo_lookup_blob(struct silofs_repo *repo,
                            const struct silofs_blobid *blobid);

int silofs_repo_spawn_blob(struct silofs_repo *repo,
                           const struct silofs_blobid *blobid,
                           struct silofs_blobf **out_blobf);

int silofs_repo_stage_blob(struct silofs_repo *repo, bool rw,
                           const struct silofs_blobid *blobid,
                           struct silofs_blobf **out_blobf);

int silofs_repo_remove_blob(struct silofs_repo *repo,
                            const struct silofs_blobid *blobid);

int silofs_repo_require_blob(struct silofs_repo *repo,
                             const struct silofs_blobid *blobid,
                             struct silofs_blobf **out_blobf);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repo_stage_ubk(struct silofs_repo *repo, bool rw,
                          const struct silofs_bkaddr *bkaddr,
                          struct silofs_ubk_info **out_ubki);

int silofs_repo_spawn_ubk(struct silofs_repo *repo, bool rw,
                          const struct silofs_bkaddr *bkaddr,
                          struct silofs_ubk_info **out_ubki);

int silofs_repo_require_ubk(struct silofs_repo *repo,
                            const struct silofs_bkaddr *bkaddr,
                            struct silofs_ubk_info **out_ubki);

#endif /* SILOFS_REPO_H_ */
