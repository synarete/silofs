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
#include "obs.h"
#include "fs.h"
#include "mbr.h"
#include "env.h"

static int
env_reinit_ciphers(struct silofs_env *env, const struct silofs_ciargs *ciargs)
{
	int err;

	err = silofs_cipher_reinit(&env->enc_ci_hd, ciargs);
	if (err) {
		return err;
	}
	err = silofs_cipher_reinit(&env->dec_ci_hd, ciargs);
	if (err) {
		return err;
	}
	return 0;
}

static int env_reinit_ciphers_by_mbr(struct silofs_env *env)
{
	const struct silofs_mbr_info *fs_mbi = &env->mbis.fs_mbi;

	return env_reinit_ciphers(env, &fs_mbi->mb_meta.nmeta.ciargs);
}

int silofs_env_setup_fs_mbr(struct silofs_env *env)
{
	int err;

	err = env_reinit_ciphers_by_mbr(env);
	if (err) {
		return err;
	}
	return 0;
}

static int
env_save_mbr_at(struct silofs_env *env, const struct silofs_mbref *mbref,
                const struct silofs_mbr1k *mbr1k)
{
	int err;

	err = silofs_dstor_save_mbr(env->base.dstor, mbref, mbr1k,
	                            sizeof(*mbr1k));
	if (err) {
		log_dbg("failed to save mbr: err=%d", err);
		return err;
	}
	return 0;
}

static int
env_load_mbr_at(const struct silofs_env *env, const struct silofs_mbref *mbref,
                struct silofs_mbr1k *out_mbr1k)
{
	int err;

	err = silofs_dstor_load_mbr(env->base.dstor, mbref, out_mbr1k,
	                            sizeof(*out_mbr1k));
	if (err) {
		log_dbg("failed to load mbr: err=%d", err);
		return (err == -ENOENT) ? -SILOFS_ENOMBR : err;
	}
	return 0;
}

int silofs_env_commit_fs_mbr(struct silofs_env *env,
                             struct silofs_mbref *out_mbref)
{
	struct silofs_mbr1k mbr1k = {
		.mbr_magic = UINT64_MAX,
	};
	int err;

	err = silofs_env_export_fs_mbr(env, out_mbref, &mbr1k);
	if (err) {
		return err;
	}
	err = env_save_mbr_at(env, out_mbref, &mbr1k);
	if (err) {
		log_err("failed to save mbr: err=%d", err);
		return err;
	}
	return 0;
}

static int
env_stat_mbr_at(const struct silofs_env *env, const struct silofs_mbref *mbref)
{
	struct stat st;
	int err;

	err = silofs_dstor_stat_mbr(env->base.dstor, mbref, &st);
	if (err) {
		return err;
	}
	if (st.st_size != SILOFS_MBR_SIZE) {
		log_warn("bad mbr: size=%zd", st.st_size);
		return -SILOFS_EBADMBR;
	}
	return 0;
}

int silofs_env_sense_mbr(struct silofs_env *env,
                         const struct silofs_mbref *mbref)
{
	return env_stat_mbr_at(env, mbref);
}

static int
env_import_fs_mbr(struct silofs_env *env, const struct silofs_mbref *mbref,
                  const struct silofs_mbr1k *mbr1k)
{
	return silofs_mbi_import(&env->mbis.fs_mbi, mbref, mbr1k);
}

int silofs_env_reload_fs_mbr(struct silofs_env *env,
                             const struct silofs_mbref *mbref)
{
	struct silofs_mbr1k mbr1k = {
		.mbr_magic = UINT64_MAX,
	};
	int err;

	err = env_stat_mbr_at(env, mbref);
	if (err) {
		return err;
	}
	err = env_load_mbr_at(env, mbref, &mbr1k);
	if (err) {
		return err;
	}
	err = env_import_fs_mbr(env, mbref, &mbr1k);
	if (err) {
		return err;
	}
	return 0;
}

static int
env_import_ar_mbr(struct silofs_env *env, const struct silofs_mbref *mbref,
                  const struct silofs_mbr1k *mbr1k)
{
	return silofs_mbi_import(&env->mbis.ar_mbi, mbref, mbr1k);
}

int silofs_env_reload_ar_mbr(struct silofs_env *env,
                             const struct silofs_mbref *mbref)
{
	struct silofs_mbr1k mbr1k = {
		.mbr_magic = UINT64_MAX,
	};
	int err;

	err = env_stat_mbr_at(env, mbref);
	if (err) {
		return err;
	}
	err = env_load_mbr_at(env, mbref, &mbr1k);
	if (err) {
		return err;
	}
	err = env_import_ar_mbr(env, mbref, &mbr1k);
	if (err) {
		return err;
	}
	return 0;
}

static int env_unlink_mbr_at(const struct silofs_env *env,
                             const struct silofs_mbref *mbref)
{
	int err;

	err = silofs_dstor_unref_mbr(env->base.dstor, mbref);
	if (err) {
		log_err("failed to unref mbr: err=%d", err);
		return err;
	}
	return 0;
}

int silofs_env_unlink_mbr(struct silofs_env *env,
                          const struct silofs_mbref *mbref)
{
	struct silofs_mbr1k mbr1k = {
		.mbr_magic = UINT64_MAX,
	};
	int err;

	err = env_stat_mbr_at(env, mbref);
	if (err) {
		return err;
	}
	err = env_load_mbr_at(env, mbref, &mbr1k);
	if (err) {
		return err;
	}
	env_unlink_mbr_at(env, mbref);
	return 0;
}
