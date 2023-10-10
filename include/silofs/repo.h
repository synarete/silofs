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

/* logical-extent control file */
struct silofs_lextf {
	struct silofs_namebuf           lex_name;
	struct silofs_repo             *lex_repo;
	struct silofs_list_head         lex_htb_lh;
	struct silofs_list_head         lex_lsq_lh;
	struct silofs_lextid            lex_id;
	long                            lex_size;
	int                             lex_fd;
	int                             lex_refcnt;
	bool                            lex_flocked;
	bool                            lex_rdonly;
};

/* repository base config */
struct silofs_repo_base {
	struct silofs_bootpath          bootpath;
	struct silofs_alloc            *alloc;
	long                            flags;
};

/* repository logical-extents-file hash-map */
struct silofs_repo_htbl {
	size_t                          rh_size;
	size_t                          rh_nelems;
	struct silofs_list_head        *rh_arr;
};

/* repository */
struct silofs_repo {
	struct silofs_repo_base         re;
	struct silofs_mdigest           re_mdigest;
	int                             re_root_dfd;
	int                             re_dots_dfd;
	int                             re_lexts_dfd;
	struct silofs_repo_htbl         re_htbl;
	struct silofs_listq             re_lstq;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_lextf *
silofs_lextf_new(struct silofs_alloc *alloc,
                 const struct silofs_lextid *lextid);

void silofs_lextf_del(struct silofs_lextf *lextf,
                      struct silofs_alloc *alloc);

void silofs_lextf_incref(struct silofs_lextf *lextf);

void silofs_lextf_decref(struct silofs_lextf *lextf);

int silofs_lextf_stat(struct silofs_lextf *lextf, struct stat *out_st);

int silofs_lextf_pwriten(struct silofs_lextf *lextf, loff_t off,
                         const void *buf, size_t len, bool sync);

int silofs_lextf_pwritevn(struct silofs_lextf *lextf, loff_t off,
                          const struct iovec *iov, size_t cnt, bool sync);

int silofs_lextf_load_bk(struct silofs_lextf *lextf,
                         const struct silofs_laddr *laddr,
                         struct silofs_lbk_info *lbki);

int silofs_lextf_require(struct silofs_lextf *lextf,
                         const struct silofs_laddr *laddr);

int silofs_lextf_require_bk_of(struct silofs_lextf *lextf,
                               const struct silofs_bkaddr *bkaddr);

int silofs_lextf_check(struct silofs_lextf *lextf,
                       const struct silofs_laddr *laddr);

int silofs_lextf_resolve(struct silofs_lextf *lextf,
                         const struct silofs_laddr *laddr,
                         struct silofs_iovec *iov);

int silofs_lextf_trim(struct silofs_lextf *lextf);


int silofs_lextf_flock(struct silofs_lextf *lextf);

int silofs_lextf_funlock(struct silofs_lextf *lextf);

int silofs_lextf_fsync(struct silofs_lextf *lextf);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_repo_init(struct silofs_repo *repo,
                     const struct silofs_repo_base *repo_base);

void silofs_repo_fini(struct silofs_repo *repo);

int silofs_repo_format(struct silofs_repo *repo);

int silofs_repo_open(struct silofs_repo *repo);

int silofs_repo_close(struct silofs_repo *repo);

int silofs_repo_fsync_all(struct silofs_repo *repo);

void silofs_repo_drop_some(struct silofs_repo *repo);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repo_save_bootrec(struct silofs_repo *repo,
                             const struct silofs_laddr *laddr,
                             const struct silofs_bootrec1k *brec1k);

int silofs_repo_load_bootrec(struct silofs_repo *repo,
                             const struct silofs_laddr *laddr,
                             struct silofs_bootrec1k *brec1k);

int silofs_repo_stat_bootrec(struct silofs_repo *repo,
                             const struct silofs_laddr *laddr,
                             struct stat *out_st);

int silofs_repo_unlink_bootrec(struct silofs_repo *repo,
                               const struct silofs_laddr *laddr);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_repo_stat_lext(const struct silofs_repo *repo,
                          const struct silofs_lextid *lextid,
                          bool allow_cache, struct stat *out_st);

int silofs_repo_spawn_lext(struct silofs_repo *repo,
                           const struct silofs_lextid *lextid,
                           struct silofs_lextf **out_lextf);

int silofs_repo_stage_lext(struct silofs_repo *repo, bool rw,
                           const struct silofs_lextid *lextid,
                           struct silofs_lextf **out_lextf);

int silofs_repo_remove_lext(struct silofs_repo *repo,
                            const struct silofs_lextid *lextid);

#endif /* SILOFS_REPO_H_ */
