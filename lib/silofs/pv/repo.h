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
#ifndef SILOFS_REPO_H_
#define SILOFS_REPO_H_

#include <silofs/infra.h>
#include <silofs/crypto.h>
#include <silofs/addr.h>
#include "dstor.h"

/* repository logical-segments-file hash-map */
struct silofs_repo_htbl {
	size_t                   rh_size;
	size_t                   rh_nelems;
	struct silofs_list_head *rh_arr;
};

/* repository */
struct silofs_repo {
	const struct silofs_repo_defs *re_defs;
	struct silofs_mutex            re_mutex;
	struct silofs_repo_htbl        re_htbl;
	struct silofs_listq            re_lruq;
	struct silofs_mdigest_hd       re_md_hd;
	struct silofs_dstor            re_dstor;
	struct silofs_alloc           *re_alloc;
	int                            re_root_dfd;
	int                            re_dots_dfd;
	int                            re_blobs_dfd;
	bool                           re_rdonly;
	bool                           re_opened;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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

#endif /* SILOFS_REPO_H_ */
