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
#include "bs.h"
#include "fs.h"
#include "mbr.h"
#include "env.h"

static int env_reinit_ciphers(struct silofs_env *env, int algo, int mode)
{
	int err;

	err = silofs_cipher_reinit(&env->enc_cipher, algo, mode);
	if (err) {
		return err;
	}
	err = silofs_cipher_reinit(&env->dec_cipher, algo, mode);
	if (err) {
		return err;
	}
	return 0;
}

static int env_reinit_ciphers_by_mbr(struct silofs_env *env)
{
	const struct silofs_mbr *mbr = &env->mbri.fs_mbr;
	const int algo = mbr->cipher_algo;
	const int mode = mbr->cipher_mode;

	return env_reinit_ciphers(env, algo, mode);
}

int silofs_env_setup_fs_mbr(struct silofs_env *env)
{
	int err;

	err = silofs_mbri_regenerate_fs_mbr(&env->mbri);
	if (err) {
		return err;
	}
	err = env_reinit_ciphers_by_mbr(env);
	if (err) {
		return err;
	}
	return 0;
}

static int env_save_mbr(struct silofs_env *env, struct silofs_baddr *out_mref)
{
	struct silofs_mbr1k mbr1k = {
		.mbr_magic = UINT64_MAX,
	};
	const struct silofs_rovec rovec = {
		.rov_base = &mbr1k,
		.rov_len = sizeof(mbr1k),
	};
	int err;

	err = silofs_mbri_encode_mbr(&env->mbri, SILOFS_MBR_FS, out_mref,
	                             &mbr1k);
	if (err) {
		return err;
	}
	err = silofs_repo_spawn_blob(env->base.repo, &out_mref->blobid);
	if (err) {
		log_err("failed to create mbr blob: err=%d", err);
		return err;
	}
	err = silofs_repo_save_bseg(env->base.repo, out_mref, &rovec);
	if (err) {
		log_err("failed to save mbr: err=%d", err);
		return err;
	}
	return 0;
}

static void env_pre_commit_fs_mbr(struct silofs_env *env)
{
	const struct silofs_uaddr *sb_uaddr = nullptr;

	silofs_assert_not_null(env->sbi);

	sb_uaddr = silofs_sbi_uaddr(env->sbi);
	silofs_mbri_update_sb_addr(&env->mbri, sb_uaddr);
}

int silofs_env_commit_fs_mbr(struct silofs_env *env,
                             struct silofs_baddr *out_mref)
{
	int err;

	env_pre_commit_fs_mbr(env);
	err = env_save_mbr(env, out_mref);
	if (err) {
		return err;
	}
	return 0;
}

static int
env_stat_mbr_at(const struct silofs_env *env, const struct silofs_baddr *baddr)
{
	struct stat st = { .st_size = -1 };
	size_t mbr_size = 0;
	int err;

	err = silofs_repo_stat_blob(env->base.repo, &baddr->blobid, &st);
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
                         const struct silofs_baddr *baddr)
{
	return env_stat_mbr_at(env, baddr);
}

static int
env_load_mbr_at(const struct silofs_env *env, const struct silofs_baddr *baddr,
                struct silofs_mbr1k *out_mbr1k)
{
	struct silofs_rwvec rwvec = {
		.rwv_base = out_mbr1k,
		.rwv_len = sizeof(*out_mbr1k),
	};
	int err;

	err = env_stat_mbr_at(env, baddr);
	if (err) {
		log_dbg("failed to lookup ref: err=%d", err);
		return (err == -ENOENT) ? -SILOFS_ENOMBR : err;
	}
	err = silofs_repo_load_bseg(env->base.repo, baddr, &rwvec);
	if (err) {
		log_dbg("failed to load mbr: err=%d", err);
		return (err == -ENOENT) ? -SILOFS_ENOMBR : err;
	}
	return 0;
}

static int
env_decode_fs_mbr(struct silofs_env *env, const struct silofs_baddr *mref,
                  const struct silofs_mbr1k *mbr1k)
{
	return silofs_mbri_decode_mbr(&env->mbri, SILOFS_MBR_FS, mref, mbr1k);
}

int silofs_env_reload_fs_mbr(struct silofs_env *env,
                             const struct silofs_baddr *baddr)
{
	struct silofs_mbr1k mbr1k = {
		.mbr_magic = UINT64_MAX,
	};
	int err;

	err = env_stat_mbr_at(env, baddr);
	if (err) {
		return err;
	}
	err = env_load_mbr_at(env, baddr, &mbr1k);
	if (err) {
		return err;
	}
	err = env_decode_fs_mbr(env, baddr, &mbr1k);
	if (err) {
		return err;
	}
	return 0;
}

static int
env_decode_ar_mbr(struct silofs_env *env, const struct silofs_baddr *mref,
                  const struct silofs_mbr1k *mbr1k)
{
	return silofs_mbri_decode_mbr(&env->mbri, SILOFS_MBR_AR, mref, mbr1k);
}

int silofs_env_reload_ar_mbr(struct silofs_env *env,
                             const struct silofs_baddr *baddr)
{
	struct silofs_mbr1k mbr1k = {
		.mbr_magic = UINT64_MAX,
	};
	int err;

	err = env_stat_mbr_at(env, baddr);
	if (err) {
		return err;
	}
	err = env_load_mbr_at(env, baddr, &mbr1k);
	if (err) {
		return err;
	}
	err = env_decode_ar_mbr(env, baddr, &mbr1k);
	if (err) {
		return err;
	}
	return 0;
}

static int env_unlink_mbr_at(const struct silofs_env *env,
                             const struct silofs_baddr *baddr)
{
	int err;

	err = silofs_repo_remove_blob(env->base.repo, &baddr->blobid);
	if (err) {
		log_err("failed to unlink mbr: err=%d", err);
		return err;
	}
	return 0;
}

int silofs_env_unlink_mbr(struct silofs_env *env,
                          const struct silofs_baddr *baddr)
{
	struct silofs_mbr1k mbr1k = {
		.mbr_magic = UINT64_MAX,
	};
	int err;

	err = env_stat_mbr_at(env, baddr);
	if (err) {
		return err;
	}
	err = env_load_mbr_at(env, baddr, &mbr1k);
	if (err) {
		return err;
	}
	env_unlink_mbr_at(env, baddr);
	if (err) {
		return err;
	}
	return 0;
}
