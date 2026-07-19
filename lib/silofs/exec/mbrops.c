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
#include <sys/stat.h>

#include <silofs/infra.h>
#include <silofs/nodes.h>
#include <silofs/exec.h>

static void log_mbr_failure(const struct silofs_mbref *mbref, int err,
                            const char *message_prefix)
{
	char str[80] = "";

	silofs_mbref_to_str(mbref, str, sizeof(str));
	log_dbg("mbr: %s: mbref='%s' err=%d", message_prefix, str, err);
}

static int
stat_mbr_at(struct silofs_dstor *dstor, const struct silofs_mbref *mbref)
{
	struct stat st;
	int err;

	err = silofs_dstor_stat_blob_by(dstor, &mbref->bx, &st);
	if (err) {
		log_mbr_failure(mbref, err, "no stat");
		return (err == -ENOENT) ? -SILOFS_ENOMBR : err;
	}
	if (st.st_size != SILOFS_MBR_SIZE) {
		log_mbr_failure(mbref, err, "bad stat size");
		return -SILOFS_EBADMBR;
	}
	return 0;
}

static int
save_mbr_at(struct silofs_dstor *dstor, const struct silofs_mbref *mbref,
            const struct silofs_mbr1k *mbr1k)
{
	constexpr size_t msz = sizeof(*mbr1k);
	int err;

	err = silofs_dstor_save_blob_by(dstor, &mbref->bx, mbr1k, msz);
	if (err) {
		log_mbr_failure(mbref, err, "save failure");
		return err;
	}
	return 0;
}

static int
load_mbr_at(struct silofs_dstor *dstor, const struct silofs_mbref *mbref,
            struct silofs_mbr1k *out_mbr1k)
{
	constexpr size_t msz = sizeof(*out_mbr1k);
	int err;

	err = silofs_dstor_load_blob_by(dstor, &mbref->bx, out_mbr1k, msz);
	if (err) {
		log_mbr_failure(mbref, err, "load failure");
		return (err == -ENOENT) ? -SILOFS_ENOMBR : err;
	}
	return 0;
}

static int
unref_mbr_at(struct silofs_dstor *dstor, const struct silofs_mbref *mbref)
{
	int err;

	err = silofs_dstor_unref_blob_by(dstor, &mbref->bx);
	if (err) {
		log_mbr_failure(mbref, err, "unref failure");
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_sense_mbr(const struct silofs_core_refs *corefs,
                     const struct silofs_mbref *mbref)
{
	return stat_mbr_at(corefs->dstor, mbref);
}

static int commit_mbr(const struct silofs_core_refs *corefs,
                      struct silofs_mbref *out_mbref)
{
	struct silofs_mbr1k mbr1k = {
		.mbr_magic = UINT64_MAX,
	};
	int err;

	err = silofs_fsroot_export_mbr1k(corefs->fsroot, out_mbref, &mbr1k);
	return_if_err(err);

	err = save_mbr_at(corefs->dstor, out_mbref, &mbr1k);
	return_if_err(err);

	silofs_fsroot_set_mbref(corefs->fsroot, out_mbref);

	return 0;
}

int silofs_commit_mbr(const struct silofs_core_refs *corefs,
                      struct silofs_mbref *out_mbref)
{
	int err;

	err = commit_mbr(corefs, out_mbref);
	silofs_burnstack();

	return err;
}

static int reload_mbr(const struct silofs_core_refs *corefs,
                      const struct silofs_mbref *mbref)
{
	struct silofs_mbr1k mbr1k = {
		.mbr_magic = UINT64_MAX,
	};
	int err;

	err = stat_mbr_at(corefs->dstor, mbref);
	return_if_err(err);

	err = load_mbr_at(corefs->dstor, mbref, &mbr1k);
	return_if_err(err);

	err = silofs_fsroot_import_mbr1k(corefs->fsroot, mbref, &mbr1k);
	return_if_err(err);

	silofs_fsroot_set_mbref(corefs->fsroot, mbref);
	return 0;
}

int silofs_reload_mbr(const struct silofs_core_refs *corefs,
                      const struct silofs_mbref *mbref)
{
	int err;

	err = reload_mbr(corefs, mbref);
	silofs_burnstack();

	return err;
}

static int unref_mbr(const struct silofs_core_refs *corefs,
                     const struct silofs_mbref *mbref)
{
	int err;

	err = reload_mbr(corefs, mbref);
	return_if_err(err);

	err = unref_mbr_at(corefs->dstor, mbref);
	return_if_err(err);

	silofs_fsroot_reset_mbref(corefs->fsroot);
	return 0;
}

int silofs_unref_mbr(const struct silofs_core_refs *corefs,
                     const struct silofs_mbref *mbref)
{
	int err;

	err = unref_mbr(corefs, mbref);
	silofs_burnstack();

	return err;
}
