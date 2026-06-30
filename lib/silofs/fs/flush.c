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
#include <silofs/configs.h>
#include <silofs/fs.h>
#include <silofs/run.h>

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static size_t flush_threshold_of(int flags)
{
	size_t threshold;

	if (flags & (SILOFS_CTLF_NOW | SILOFS_CTLF_IDLE | SILOFS_CTLF_FSYNC)) {
		threshold = 0;
	} else if (flags & SILOFS_CTLF_RELEASE) {
		threshold = SILOFS_LSEG_SIZE_MAX / 2;
	} else if (flags & SILOFS_CTLF_INTERN) {
		threshold = SILOFS_LSEG_SIZE_MAX;
	} else if (flags & SILOFS_CTLF_OPSTART) {
		threshold = 2 * SILOFS_LSEG_SIZE_MAX;
	} else {
		threshold = 4 * SILOFS_LSEG_SIZE_MAX;
	}
	return threshold;
}

static bool need_flush_now(const struct silofs_task_ctx *task, int flags)
{
	struct silofs_alloc_stat alst = {
		.nbytes_use = 0,
		.nbytes_max = 0,
	};
	size_t flush_threshold;

	if (flags & SILOFS_CTLF_NOW) {
		return true;
	}
	silofs_memstat(task->env->alloc, &alst);
	if (alst.nbytes_use > (alst.nbytes_max / 2)) {
		return true;
	}
	flush_threshold = flush_threshold_of(flags); /* XXX CRAP FIXME */
	if (flush_threshold == 0) {
		return true;
	}
	return false;
}

static bool need_flush_by(const struct silofs_task_ctx *task,
                          const struct silofs_inode_info *ii, int flags)
{
	silofs_unused(ii);
	return need_flush_now(task, flags);
}

static int do_flush_dirty(struct silofs_task_ctx *task,
                          struct silofs_inode_info *ii, int flags)
{
	/* XXX TODO FIXME */
	silofs_unused(task);
	silofs_unused(ii);
	silofs_unused(flags);

	return 0;
}

int silofs_flush_dirty(struct silofs_task_ctx *task,
                       struct silofs_inode_info *ii, int flags)
{
	int err = 0;

	if (need_flush_by(task, ii, flags)) {
		silofs_ii_incref(ii);
		err = do_flush_dirty(task, ii, flags);
		silofs_ii_decref(ii);
	}
	return err;
}

int silofs_flush_dirty_now(struct silofs_task_ctx *task)
{
	return silofs_destage_dirty_by(task);
}

int silofs_destage_dirty_by(struct silofs_task_ctx *task)
{
	struct silofs_pexec_ctx pexec;

	silofs_make_pexec(task, &pexec);
	return silofs_destage_dirty_nodes(&pexec);
}
