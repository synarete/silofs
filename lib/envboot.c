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

static int env_generate_mbr(struct silofs_env *env)
{
	return silofs_mbri_regen(&env->mbri);
}

int silofs_env_setup_mbr(struct silofs_env *env)
{
	int err;

	err = env_generate_mbr(env);
	if (err) {
		return err;
	}
	err = env_reinit_ciphers_by_mbr(env);
	if (err) {
		return err;
	}
	return 0;
}

static int env_pre_commit_mbr(struct silofs_env *env)
{
	return silofs_mbri_update_sb(&env->mbri, silofs_sbi_uaddr(env->sbi));
}

static int env_save_mbr(struct silofs_env *env, struct silofs_caddr *out_mref)
{
	struct silofs_mbr1k mbr1k = {
		.mbr_magic = UINT64_MAX,
	};
	const struct silofs_rovec rovec = {
		.rov_base = &mbr1k,
		.rov_len = sizeof(mbr1k),
	};
	int err;

	err = silofs_mbri_encode_fs(&env->mbri, out_mref, &mbr1k);
	if (err) {
		return err;
	}
	err = silofs_repo_save_cobj(env->base.repo, out_mref, &rovec);
	if (err) {
		log_err("failed to save mbr: err=%d", err);
		return err;
	}
	err = silofs_repo_create_ref(env->base.repo, out_mref);
	if (err) {
		log_err("failed to create ref: err=%d", err);
		return err;
	}
	return 0;
}

int silofs_env_commit_mbr(struct silofs_env *env,
                          struct silofs_caddr *out_mref)
{
	int err;

	err = env_pre_commit_mbr(env);
	if (err) {
		return err;
	}
	err = env_save_mbr(env, out_mref);
	if (err) {
		return err;
	}
	return 0;
}

static int
env_stat_mbr_at(const struct silofs_env *env, const struct silofs_caddr *caddr)
{
	size_t mbr_size = 0;
	int err;

	err = silofs_repo_stat_cobj(env->base.repo, caddr, &mbr_size);
	if (err) {
		return err;
	}
	if (mbr_size != SILOFS_MBR_SIZE) {
		log_warn("bad mbr: size=%zu", mbr_size);
		return -SILOFS_EBADMBR;
	}
	return 0;
}

int silofs_env_sense_mbr(struct silofs_env *env,
                         const struct silofs_caddr *caddr)
{
	return env_stat_mbr_at(env, caddr);
}

static int
env_load_mbr_at(const struct silofs_env *env, const struct silofs_caddr *caddr,
                struct silofs_mbr1k *out_mbr1k)
{
	struct silofs_rwvec rwvec = {
		.rwv_base = out_mbr1k,
		.rwv_len = sizeof(*out_mbr1k),
	};
	int err;

	err = env_stat_mbr_at(env, caddr);
	if (err) {
		log_dbg("failed to lookup ref: err=%d", err);
		return (err == -ENOENT) ? -SILOFS_ENOREF : err;
	}
	err = silofs_repo_load_cobj(env->base.repo, caddr, &rwvec);
	if (err) {
		log_dbg("failed to load mbr: err=%d", err);
		return (err == -ENOENT) ? -SILOFS_ENOMBR : err;
	}
	return 0;
}

static int
env_decode_mbr(struct silofs_env *env, const struct silofs_caddr *mref,
               const struct silofs_mbr1k *mbr1k)
{
	return silofs_mbri_decode_fs(&env->mbri, mref, mbr1k);
}

int silofs_env_reload_mbr(struct silofs_env *env,
                          const struct silofs_caddr *caddr)
{
	struct silofs_mbr1k mbr1k = {
		.mbr_magic = UINT64_MAX,
	};
	int err;

	err = env_stat_mbr_at(env, caddr);
	if (err) {
		return err;
	}
	err = env_load_mbr_at(env, caddr, &mbr1k);
	if (err) {
		return err;
	}
	err = env_decode_mbr(env, caddr, &mbr1k);
	if (err) {
		return err;
	}
	return 0;
}

static int env_unlink_mbr_at(const struct silofs_env *env,
                             const struct silofs_caddr *caddr)
{
	int err;

	err = silofs_repo_unlink_cobj(env->base.repo, caddr);
	if (err) {
		log_err("failed to unlink mbr: err=%d", err);
		return err;
	}
	err = silofs_repo_remove_ref(env->base.repo, caddr);
	if (err) {
		log_err("failed to unlink ref: err=%d", err);
		return err;
	}
	return 0;
}

int silofs_env_unlink_mbr(struct silofs_env *env,
                          const struct silofs_caddr *caddr)
{
	struct silofs_mbr1k mbr1k = {
		.mbr_magic = UINT64_MAX,
	};
	int err;

	err = env_stat_mbr_at(env, caddr);
	if (err) {
		return err;
	}
	err = env_load_mbr_at(env, caddr, &mbr1k);
	if (err) {
		return err;
	}
	env_unlink_mbr_at(env, caddr);
	if (err) {
		return err;
	}
	return 0;
}
