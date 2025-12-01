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
#include "vfs.h"
#include "gbr.h"
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

static int env_reinit_ciphers_by_gbr(struct silofs_env *env)
{
	const struct silofs_gbr *gbr = &env->gbrs.fs_gbr;

	return env_reinit_ciphers(env, &gbr->root.cmeta.ciargs);
}

int silofs_env_setup_fs_gbr(struct silofs_env *env)
{
	int err;

	err = env_reinit_ciphers_by_gbr(env);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_env_commit_fs_gbr(struct silofs_env *env,
                             struct silofs_paddr *out_gbref)
{
	struct silofs_gbr1k gbr1k = {
		.gbr_magic = UINT64_MAX,
	};
	const struct silofs_rovec rovec = {
		.rov_base = &gbr1k,
		.rov_len = sizeof(gbr1k),
	};
	int err;

	err = silofs_gbr_encode_by(&env->gbrs.fs_gbr, &env->gbrs.cmeta,
	                           out_gbref, &gbr1k);
	if (err) {
		return err;
	}
	err = silofs_repo_spawn_blob(env->base.repo, &out_gbref->blobid);
	if (err) {
		log_err("failed to create gbr blob: err=%d", err);
		return err;
	}
	err = silofs_repo_save_bseg(env->base.repo, out_gbref, &rovec);
	if (err) {
		log_err("failed to save gbr: err=%d", err);
		return err;
	}
	return 0;
}

static int
env_stat_gbr_at(const struct silofs_env *env, const struct silofs_paddr *paddr)
{
	struct stat st = { .st_size = -1 };
	size_t gbr_size = 0;
	int err;

	err = silofs_repo_stat_blob(env->base.repo, &paddr->blobid, &st);
	if (err) {
		return err;
	}
	gbr_size = (size_t)st.st_size;
	if (gbr_size != SILOFS_MBR_SIZE) {
		log_warn("bad gbr: size=%zu", gbr_size);
		return -SILOFS_EBADMBR;
	}
	return 0;
}

int silofs_env_sense_gbr(struct silofs_env *env,
                         const struct silofs_paddr *paddr)
{
	return env_stat_gbr_at(env, paddr);
}

static int
env_load_gbr_at(const struct silofs_env *env, const struct silofs_paddr *paddr,
                struct silofs_gbr1k *out_gbr1k)
{
	struct silofs_rwvec rwvec = {
		.rwv_base = out_gbr1k,
		.rwv_len = sizeof(*out_gbr1k),
	};
	int err;

	err = env_stat_gbr_at(env, paddr);
	if (err) {
		log_dbg("failed to lookup ref: err=%d", err);
		return (err == -ENOENT) ? -SILOFS_ENOMBR : err;
	}
	err = silofs_repo_load_bseg(env->base.repo, paddr, &rwvec);
	if (err) {
		log_dbg("failed to load gbr: err=%d", err);
		return (err == -ENOENT) ? -SILOFS_ENOMBR : err;
	}
	return 0;
}

static int
env_decode_fs_gbr(struct silofs_env *env, const struct silofs_paddr *gbref,
                  const struct silofs_gbr1k *gbr1k)
{
	return silofs_gbr_decode_by(&env->gbrs.fs_gbr, &env->gbrs.cmeta, gbref,
	                            gbr1k);
}

int silofs_env_reload_fs_gbr(struct silofs_env *env,
                             const struct silofs_paddr *paddr)
{
	struct silofs_gbr1k gbr1k = {
		.gbr_magic = UINT64_MAX,
	};
	int err;

	err = env_stat_gbr_at(env, paddr);
	if (err) {
		return err;
	}
	err = env_load_gbr_at(env, paddr, &gbr1k);
	if (err) {
		return err;
	}
	err = env_decode_fs_gbr(env, paddr, &gbr1k);
	if (err) {
		return err;
	}
	return 0;
}

static int
env_decode_ar_gbr(struct silofs_env *env, const struct silofs_paddr *gbref,
                  const struct silofs_gbr1k *gbr1k)
{
	return silofs_gbr_decode_by(&env->gbrs.ar_gbr, &env->gbrs.cmeta, gbref,
	                            gbr1k);
}

int silofs_env_reload_ar_gbr(struct silofs_env *env,
                             const struct silofs_paddr *paddr)
{
	struct silofs_gbr1k gbr1k = {
		.gbr_magic = UINT64_MAX,
	};
	int err;

	err = env_stat_gbr_at(env, paddr);
	if (err) {
		return err;
	}
	err = env_load_gbr_at(env, paddr, &gbr1k);
	if (err) {
		return err;
	}
	err = env_decode_ar_gbr(env, paddr, &gbr1k);
	if (err) {
		return err;
	}
	return 0;
}

static int env_unlink_gbr_at(const struct silofs_env *env,
                             const struct silofs_paddr *paddr)
{
	int err;

	err = silofs_repo_remove_blob(env->base.repo, &paddr->blobid);
	if (err) {
		log_err("failed to unlink gbr: err=%d", err);
		return err;
	}
	return 0;
}

int silofs_env_unlink_gbr(struct silofs_env *env,
                          const struct silofs_paddr *paddr)
{
	struct silofs_gbr1k gbr1k = {
		.gbr_magic = UINT64_MAX,
	};
	int err;

	err = env_stat_gbr_at(env, paddr);
	if (err) {
		return err;
	}
	err = env_load_gbr_at(env, paddr, &gbr1k);
	if (err) {
		return err;
	}
	env_unlink_gbr_at(env, paddr);
	return 0;
}
