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

#include <silofs/exec.h>

void silofs_relax_caches(const struct silofs_exec_ctx *ectx, int flags)
{
	silofs_pcache_relax(ectx->pcache, flags);
	silofs_lcache_relax(ectx->lcache, flags);
	if (flags & SILOFS_CTLF_IDLE) {
		silofs_dstor_relax(ectx->dstor);
	}
}

void silofs_drop_caches(const struct silofs_exec_ctx *ectx)
{
	silofs_pspools_drop(ectx->pspools);
	silofs_lspools_drop(ectx->lspools);
	silofs_pcache_drop(ectx->pcache);
	silofs_lcache_drop(ectx->lcache);
	silofs_dstor_drop(ectx->dstor);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_sense_mbr(const struct silofs_exec_ctx *ectx,
                     const struct silofs_mbref *mbref)
{
	return silofs_stat_mbr_at(ectx->dstor, mbref);
}

static int
save_mbr_at(struct silofs_dstor *dstor, const struct silofs_mbref *mbref,
            const struct silofs_mbr1k *mbr1k)
{
	size_t msz;
	int err;

	msz = sizeof(*mbr1k);
	err = silofs_dstor_save_mbr(dstor, mbref, mbr1k, msz);
	if (err) {
		log_dbg("failed to save mbr: msz=%zu err=%d", msz, err);
		return err;
	}
	return 0;
}

static int
commit_mbr(const struct silofs_exec_ctx *ectx, struct silofs_mbref *out_mbref)
{
	struct silofs_mbr1k mbr1k = {
		.mbr_magic = UINT64_MAX,
	};
	int err;

	err = silofs_fsroot_export_mbr1k(ectx->fsroot, out_mbref, &mbr1k);
	return_if_err(err);

	err = save_mbr_at(ectx->dstor, out_mbref, &mbr1k);
	return_if_err(err);

	silofs_fsroot_set_mbref(ectx->fsroot, out_mbref);

	return 0;
}

int silofs_commit_mbr(const struct silofs_exec_ctx *ectx,
                      struct silofs_mbref *out_mbref)
{
	int err;

	err = commit_mbr(ectx, out_mbref);
	silofs_burnstack();
	return err;
}

static int
load_mbr_at(struct silofs_dstor *dstor, const struct silofs_mbref *mbref,
            struct silofs_mbr1k *out_mbr1k)
{
	size_t msz;
	int err;

	msz = sizeof(*out_mbr1k);
	err = silofs_dstor_load_mbr(dstor, mbref, out_mbr1k, msz);
	if (err) {
		log_dbg("failed to load mbr: msz=%zu err=%d", msz, err);
		return (err == -ENOENT) ? -SILOFS_ENOMBR : err;
	}
	return 0;
}

static int reload_mbr(const struct silofs_exec_ctx *ectx,
                      const struct silofs_mbref *mbref)
{
	struct silofs_mbr1k mbr1k = {
		.mbr_magic = UINT64_MAX,
	};
	int err;

	err = silofs_stat_mbr_at(ectx->dstor, mbref);
	return_if_err(err);

	err = load_mbr_at(ectx->dstor, mbref, &mbr1k);
	return_if_err(err);

	err = silofs_fsroot_import_mbr1k(ectx->fsroot, mbref, &mbr1k);
	return_if_err(err);

	silofs_fsroot_set_mbref(ectx->fsroot, mbref);
	return 0;
}

int silofs_reload_mbr(const struct silofs_exec_ctx *ectx,
                      const struct silofs_mbref *mbref)
{
	int err;

	err = reload_mbr(ectx, mbref);
	silofs_burnstack();
	return err;
}

static int
unref_mbr_at(struct silofs_dstor *dstor, const struct silofs_mbref *mbref)
{
	int err;

	err = silofs_dstor_unref_mbr(dstor, mbref);
	if (err) {
		log_err("failed to unref mbr: err=%d", err);
		return err;
	}
	return 0;
}

static int
unref_mbr(const struct silofs_exec_ctx *ectx, const struct silofs_mbref *mbref)
{
	int err;

	err = silofs_reload_mbr(ectx, mbref);
	return_if_err(err);

	err = unref_mbr_at(ectx->dstor, mbref);
	return_if_err(err);

	silofs_fsroot_reset_mbref(ectx->fsroot);
	return 0;
}

int silofs_unref_mbr(const struct silofs_exec_ctx *ectx,
                     const struct silofs_mbref *mbref)
{
	int err;

	err = unref_mbr(ectx, mbref);
	silofs_burnstack();
	return err;
}
