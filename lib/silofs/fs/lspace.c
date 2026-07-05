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

#include <silofs/infra.h>
#include <silofs/addr.h>
#include <silofs/pstor.h>
#include <silofs/fs.h>

int silofs_mark_unwritten_at(const struct silofs_task_ctx *task,
                             const struct silofs_laddr *ref_laddr)
{
	struct silofs_spnode_info *spi = nullptr;
	int err;

	err = silofs_stage_spnode_by(&task->pexec, ref_laddr, &spi);
	return_if_err(err);

	silofs_spi_mark_unwritten(spi, ref_laddr);
	return 0;
}

int silofs_clear_unwritten_at(const struct silofs_task_ctx *task,
                              const struct silofs_laddr *ref_laddr)
{
	struct silofs_spnode_info *spi = nullptr;
	int err;

	err = silofs_stage_spnode_by(&task->pexec, ref_laddr, &spi);
	return_if_err(err);

	silofs_spi_clear_unwritten(spi, ref_laddr);
	return 0;
}

int silofs_test_unwritten_at(const struct silofs_task_ctx *task,
                             const struct silofs_laddr *ref_laddr,
                             bool *out_unwritten)
{
	struct silofs_vspace_ref vspref = {};
	int err;

	err = silofs_probe_lspace_ref(&task->pexec, ref_laddr, &vspref);
	return_if_err(err);

	*out_unwritten = (vspref.flags & SILOFS_SPACEF_UNWRITTEN) > 0;
	return 0;
}
