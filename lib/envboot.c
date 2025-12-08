/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#include "configs.h"
#include "bstore.h"
#include "fs.h"
#include "mbr.h"
#include "env.h"

static int
env_reinit_ciphers(struct silofs_env *env, const struct silofs_ciargs *ciargs)
{
	int err;

	err = silofs_cipher_reinit(&env->enc_cipher, ciargs);
	if (err) {
		return err;
	}
	err = silofs_cipher_reinit(&env->dec_cipher, ciargs);
	if (err) {
		return err;
	}
	return 0;
}

static int env_reinit_ciphers_by_mbr(struct silofs_env *env)
{
	const struct silofs_mbr_info *fs_mbi = &env->mbis.fs_mbi;

	return env_reinit_ciphers(env, &fs_mbi->mb_nmeta.ciargs);
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
env_save_mbr_at(struct silofs_env *env, const struct silofs_paddr *paddr,
                const struct silofs_mbr1k *mbr1k)
{
	const struct silofs_rovec rovec = {
		.rov_base = mbr1k,
		.rov_len = sizeof(*mbr1k),
	};
	int err;

	err = silofs_repo_save_bseg(env->base.repo, paddr, &rovec);
	if (err) {
		log_dbg("failed to save mbr: err=%d", err);
		return err;
	}
	return 0;
}

static int
env_load_mbr_at(const struct silofs_env *env, const struct silofs_paddr *paddr,
                struct silofs_mbr1k *out_mbr1k)
{
	struct silofs_rwvec rwvec = {
		.rwv_base = out_mbr1k,
		.rwv_len = sizeof(*out_mbr1k),
	};
	int err;

	err = silofs_repo_load_bseg(env->base.repo, paddr, &rwvec);
	if (err) {
		log_dbg("failed to load mbr: err=%d", err);
		return (err == -ENOENT) ? -SILOFS_ENOMBR : err;
	}
	return 0;
}

static int
env_export_fs_mbr(struct silofs_env *env, struct silofs_paddr *out_mbref,
                  struct silofs_mbr1k *out_mbr1k)
{
	return silofs_mbi_export(&env->mbis.fs_mbi, out_mbref, out_mbr1k);
}

int silofs_env_commit_fs_mbr(struct silofs_env *env,
                             struct silofs_paddr *out_mbref)
{
	struct silofs_mbr1k mbr1k = {
		.mbr_magic = UINT64_MAX,
	};
	int err;

	err = env_export_fs_mbr(env, out_mbref, &mbr1k);
	if (err) {
		return err;
	}
	err = silofs_repo_spawn_blob(env->base.repo, &out_mbref->blobid);
	if (err) {
		log_err("failed to create mbr blob: err=%d", err);
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
env_stat_mbr_at(const struct silofs_env *env, const struct silofs_paddr *paddr)
{
	struct stat st = { .st_size = -1 };
	size_t mbr_size = 0;
	int err;

	err = silofs_repo_stat_blob(env->base.repo, &paddr->blobid, &st);
	if (err) {
		return err;
	}
	mbr_size = (size_t)st.st_size;
	if (mbr_size != SILOFS_MBR_SIZE) {
		log_warn("bad mbr: size=%zu", mbr_size);
		return -SILOFS_EBADMBR;
	}
	return 0;
}

int silofs_env_sense_mbr(struct silofs_env *env,
                         const struct silofs_paddr *paddr)
{
	return env_stat_mbr_at(env, paddr);
}

static int
env_import_fs_mbr(struct silofs_env *env, const struct silofs_paddr *mbref,
                  const struct silofs_mbr1k *mbr1k)
{
	return silofs_mbi_import(&env->mbis.fs_mbi, mbref, mbr1k);
}

int silofs_env_reload_fs_mbr(struct silofs_env *env,
                             const struct silofs_paddr *paddr)
{
	struct silofs_mbr1k mbr1k = {
		.mbr_magic = UINT64_MAX,
	};
	int err;

	err = env_stat_mbr_at(env, paddr);
	if (err) {
		return err;
	}
	err = env_load_mbr_at(env, paddr, &mbr1k);
	if (err) {
		return err;
	}
	err = env_import_fs_mbr(env, paddr, &mbr1k);
	if (err) {
		return err;
	}
	return 0;
}

static int
env_import_ar_mbr(struct silofs_env *env, const struct silofs_paddr *mbref,
                  const struct silofs_mbr1k *mbr1k)
{
	return silofs_mbi_import(&env->mbis.ar_mbi, mbref, mbr1k);
}

int silofs_env_reload_ar_mbr(struct silofs_env *env,
                             const struct silofs_paddr *paddr)
{
	struct silofs_mbr1k mbr1k = {
		.mbr_magic = UINT64_MAX,
	};
	int err;

	err = env_stat_mbr_at(env, paddr);
	if (err) {
		return err;
	}
	err = env_load_mbr_at(env, paddr, &mbr1k);
	if (err) {
		return err;
	}
	err = env_import_ar_mbr(env, paddr, &mbr1k);
	if (err) {
		return err;
	}
	return 0;
}

static int env_unlink_mbr_at(const struct silofs_env *env,
                             const struct silofs_paddr *paddr)
{
	int err;

	err = silofs_repo_remove_blob(env->base.repo, &paddr->blobid);
	if (err) {
		log_err("failed to unlink mbr: err=%d", err);
		return err;
	}
	return 0;
}

int silofs_env_unlink_mbr(struct silofs_env *env,
                          const struct silofs_paddr *paddr)
{
	struct silofs_mbr1k mbr1k = {
		.mbr_magic = UINT64_MAX,
	};
	int err;

	err = env_stat_mbr_at(env, paddr);
	if (err) {
		return err;
	}
	err = env_load_mbr_at(env, paddr, &mbr1k);
	if (err) {
		return err;
	}
	env_unlink_mbr_at(env, paddr);
	return 0;
}
