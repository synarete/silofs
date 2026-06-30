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
#include <silofs/errors.h>
#include <silofs/infra.h>
#include <silofs/addr.h>

void silofs_fsmeta_setup(struct silofs_fsmeta *fsmeta)
{
	const char *version = silofs_sw_version_string;

	silofs_memzero(fsmeta, sizeof(*fsmeta));
	strlcpy(fsmeta->version, version, sizeof(fsmeta->version));
	fsmeta->timestamp = (uint64_t)silofs_time_real_now();
	fsmeta->fmtvers   = SILOFS_FMT_VERSION;
}

static void fsref_reset(struct silofs_fsref *fsref)
{
	silofs_memzero(fsref, sizeof(*fsref));
}

static void fsref_setup_meta(struct silofs_fsref *fsref)
{
	silofs_fsmeta_setup(&fsref->fsmeta);
}

static void fsref_encode_mbref(struct silofs_fsref *fsref,
                               const struct silofs_mbref *mbref)
{
	silofs_mbref_to_str(mbref, fsref->mbaddr.mba,
	                    sizeof(fsref->mbaddr.mba) - 1);
}

void silofs_fsref_export(struct silofs_fsref *fsref,
                         const struct silofs_mbref *mbref)
{
	fsref_reset(fsref);
	fsref_setup_meta(fsref);
	fsref_encode_mbref(fsref, mbref);
}

static int fsref_check_meta(const struct silofs_fsref *fsref)
{
	const struct silofs_fsmeta *meta = &fsref->fsmeta;

	if (meta->fmtvers != SILOFS_FMT_VERSION) {
		return -SILOFS_EINVAL;
	}
	if ((int64_t)meta->timestamp < 0) {
		return -SILOFS_EINVAL;
	}
	return 0;
}

static int fsref_decode_mbref(const struct silofs_fsref *fsref,
                              struct silofs_mbref *out_mbref)
{
	size_t len;
	int err = -SILOFS_EINVAL;

	len = silofs_str_nlength(fsref->mbaddr.mba, sizeof(fsref->mbaddr.mba));
	if (len && (len < sizeof(fsref->mbaddr.mba))) {
		err = silofs_mbref_from_str(out_mbref, fsref->mbaddr.mba, len);
	}
	return err;
}

int silofs_fsref_import(const struct silofs_fsref *fsref,
                        struct silofs_mbref *out_mbref)
{
	int err;

	err = fsref_check_meta(fsref);
	if (err) {
		return err;
	}
	err = fsref_decode_mbref(fsref, out_mbref);
	if (err) {
		return err;
	}
	return 0;
}

void silofs_fsrefs_export(struct silofs_fsrefs *fsrefs,
                          const struct silofs_mbrefs *mbrefs)
{
	silofs_fsref_export(&fsrefs->main, &mbrefs->main);
	silofs_fsref_export(&fsrefs->base, &mbrefs->base);
	silofs_fsref_export(&fsrefs->fork, &mbrefs->fork);
}
