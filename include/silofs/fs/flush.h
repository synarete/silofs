/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#ifndef SILOFS_FLUSH_H_
#define SILOFS_FLUSH_H_

#include <silofs/infra.h>
#include <silofs/fs/task.h>

struct silofs_dset {
	struct silofs_lnode_info       *ds_preq;
	struct silofs_lnode_info       *ds_postq;
	struct silofs_avl               ds_avl;
};

struct silofs_flusher {
	struct silofs_submit_ref        sref[SILOFS_SQENT_NREFS_MAX];
	struct silofs_dset              dset[3];
	struct silofs_listq             txq;
	struct silofs_submitq          *submitq;
	struct silofs_task             *task;
	struct silofs_inode_info       *ii;
	uint32_t                        tx_count;
	int                             flags;
} silofs_aligned64;

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_flusher_init(struct silofs_flusher *flusher,
                        struct silofs_submitq *submitq);

void silofs_flusher_fini(struct silofs_flusher *flusher);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_flush_dirty(struct silofs_task *task,
                       struct silofs_inode_info *ii, int flags);

int silofs_flush_dirty_now(struct silofs_task *task);

#endif /* SILOFS_FLUSH_H_ */
