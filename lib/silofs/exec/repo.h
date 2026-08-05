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
#include <silofs/exec/dstor.h>

/* repository */
struct silofs_repo {
	struct silofs_mutex  re_mutex;
	struct silofs_dstor  re_dstor;
	struct silofs_alloc *re_alloc;
	int                  re_root_dfd;
	int                  re_dots_dfd;
	int                  re_blobs_dfd;
	bool                 re_rdonly;
	bool                 re_opened;
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

#endif /* SILOFS_REPO_H_ */
