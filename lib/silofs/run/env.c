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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <silofs/pv.h>
#include <silofs/fs.h>
#include <silofs/fuseq.h>

#include <silofs/run/mbr.h>
#include <silofs/run/env.h>

void silofs_env_refresh_root(struct silofs_env *env,
                             const struct silofs_pnptr *pnptr)
{
	silofs_mbi_set_root(&env->mbi, pnptr);
}

static int env_update_repodir(struct silofs_env *env, const char *repodir)
{
	struct silofs_alloc *alloc = env->alloc;
	size_t len;

	if (env->repodir != nullptr) {
		len = silofs_str_length(env->repodir);
		silofs_memfree(alloc, env->repodir, len + 1, 0);
		env->repodir = nullptr;
	}
	if (repodir != nullptr) {
		len          = silofs_str_length(repodir);
		env->repodir = silofs_memdup(alloc, repodir, len + 1, 0);
		if (env->repodir == nullptr) {
			return -SILOFS_ENOMEM;
		}
	}
	return 0;
}

static int
env_setup_owner(struct silofs_env *env, const struct silofs_cred *cred)
{
	if (silofs_uid_isnull(cred->uid)) {
		log_dbg("illegal owner uid: %u", cred->uid);
		return -SILOFS_EINVAL;
	}
	if (silofs_gid_isnull(cred->gid)) {
		log_dbg("illegal owner gid: %u", cred->gid);
		return -SILOFS_EINVAL;
	}
	if (cred->umask == 0) {
		log_dbg("zero umask: uid=%u gid=%u", cred->uid, cred->gid);
		return -SILOFS_EINVAL;
	}
	silofs_cred_assign(&env->owner_cred, cred);
	return 0;
}

static int
env_use_password(struct silofs_env *env, const struct silofs_password *pw,
                 enum silofs_flags flags)
{
	struct silofs_mbr_meta mbr_meta = {};
	int err;

	if ((flags & SILOFS_F_NOPASSWD) != SILOFS_F_NOPASSWD) {
		err = silofs_derive_mbr_meta(pw, &mbr_meta);
		return_if_err(err);

		silofs_mbi_set_meta(&env->mbi, &mbr_meta);
	}

	return 0;
}

static int env_update_fscap(struct silofs_env *env, size_t cap_want)
{
	const size_t align_size = SILOFS_MEGA;
	const size_t fscap      = (cap_want / align_size) * align_size;

	if (cap_want == 0) {
		return 0; /* no-op */
	}
	if ((fscap < SILOFS_CAPACITY_SIZE_MIN) ||
	    (fscap > SILOFS_CAPACITY_SIZE_MAX)) {
		return -SILOFS_EINVAL;
	}
	env->fscap = fscap;
	return 0;
}

static void env_setup_ctlflags(struct silofs_env *env, enum silofs_flags flags)
{
	silofs_ubref_set_ctlflags(&env->ubref, flags);
}

static int env_update_name(struct silofs_env *env, const char *fsname)
{
	struct silofs_namestr nstr;
	int err;

	if (fsname == nullptr) {
		silofs_strbuf_reset(&env->name);
		goto out;
	}

	err = silofs_namestr_init(&nstr, fsname);
	return_if_err(err);

	err = silofs_check_fsname(&nstr);
	return_if_err(err);

	silofs_strbuf_setup(&env->name, &nstr.sv);
out:
	return 0;
}

static size_t env_calc_iopen_limit(const struct silofs_env *env)
{
	struct silofs_alloc_stat st;
	const size_t align = 128;
	size_t lim;

	silofs_memstat(env->alloc, &st);
	lim = (st.nbytes_max / (2 * SILOFS_LBK_SIZE));
	return silofs_div_round_up(lim, align) * align;
}

static void env_update_iopen_max(struct silofs_env *env)
{
	env->opstat.op_iopen_max = env_calc_iopen_limit(env);
}

int silofs_env_setup(struct silofs_env *env, const struct silofs_spec *spec)
{
	int err;

	err = env_update_repodir(env, spec->bref[0].repodir);
	return_if_err(err);

	err = env_update_name(env, spec->bref[0].refname);
	return_if_err(err);

	err = env_setup_owner(env, &spec->fsowner);
	return_if_err(err);

	err = env_use_password(env, &spec->passwd, spec->flags);
	return_if_err(err);

	err = env_update_fscap(env, spec->fscap);
	return_if_err(err);

	env_setup_ctlflags(env, spec->flags);
	env_update_iopen_max(env);

	silofs_env_bind_hooks(env);

	return 0;
}

void silofs_env_bind_fuseq(struct silofs_env *env, struct silofs_fuseq *fq)
{
	if (fq != nullptr) {
		fq->fq_env       = env;
		fq->fq_vfs_hooks = env->vfs_hooks;
	}
	env->fuseq = fq;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void env_init_opstat(struct silofs_env *env)
{
	env->opstat.op_iopen_max = 0;
	env->opstat.op_iopen     = 0;
	env->opstat.op_count     = 0;
	env->opstat.op_iopen_max = 0;
}

static void
env_init_commons(struct silofs_env *env, struct silofs_alloc *alloc)
{
	memset(&env->base, 0, sizeof(env->base));
	silofs_strbuf_reset(&env->name);
	silofs_cred_init(&env->owner_cred);
	silofs_ubref_init(&env->ubref);
	env->init_time = silofs_time_mono_now();
	env->alloc     = alloc;
	env->iconv_set = false;
	env->repodir   = nullptr;
	env->fuseq     = nullptr;
	env->vfs_hooks = nullptr;
}

static void env_fini_commons(struct silofs_env *env)
{
	memset(&env->base, 0, sizeof(env->base));
	silofs_cred_fini(&env->owner_cred);
	silofs_ubref_fini(&env->ubref);
}

static int env_init_mbi(struct silofs_env *env)
{
	silofs_mbi_init(&env->mbi);
	return 0;
}

static void env_fini_mbi(struct silofs_env *env)
{
	silofs_mbi_fini(&env->mbi);
}

static int env_init_locks(struct silofs_env *env)
{
	int err;

	err = silofs_rwlock_init(&env->rwlock);
	if (err) {
		return err;
	}
	err = silofs_mutex_init(&env->mutex);
	if (err) {
		silofs_rwlock_fini(&env->rwlock);
		return err;
	}
	return 0;
}

static void env_fini_locks(struct silofs_env *env)
{
	silofs_mutex_fini(&env->mutex);
	silofs_rwlock_fini(&env->rwlock);
}

static void env_fini_crypto(struct silofs_env *env)
{
	silofs_cipher_fini(&env->dec_ci_hd);
	silofs_cipher_fini(&env->enc_ci_hd);
	silofs_mdigest_fini(&env->md_hd);
}

static int env_init_crypto(struct silofs_env *env)
{
	int err;

	err = silofs_mdigest_init(&env->md_hd);
	if (err) {
		return err;
	}
	err = silofs_cipher_init(&env->enc_ci_hd);
	if (err) {
		goto out_err;
	}
	err = silofs_cipher_init(&env->dec_ci_hd);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	env_fini_crypto(env);
	return err;
}

static int env_init_uconv(struct silofs_env *env)
{
	return silofs_uconv_init(&env->uconv);
}

static void env_fini_uconv(struct silofs_env *env)
{
	silofs_uconv_fini(&env->uconv);
}

int silofs_env_init(struct silofs_env *env, struct silofs_alloc *alloc)
{
	int err;

	env_init_commons(env, alloc);
	env_init_opstat(env);

	err = env_init_mbi(env);
	return_if_err(err);

	err = env_init_locks(env);
	goto_out_if_err(err);

	err = env_init_crypto(env);
	goto_out_if_err(err);

	err = env_init_uconv(env);
	goto_out_if_err(err);

	return 0;
out:
	silofs_env_fini(env);
	return err;
}

void silofs_env_fini(struct silofs_env *env)
{
	env_update_repodir(env, nullptr);
	env_fini_uconv(env);
	env_fini_crypto(env);
	env_fini_locks(env);
	env_fini_mbi(env);
	env_fini_commons(env);
}

void silofs_env_use(struct silofs_env *env, const struct silofs_env_base *base)
{
	memcpy(&env->base, base, sizeof(env->base));
}

void silofs_env_lock(struct silofs_env *env)
{
	silofs_mutex_lock(&env->mutex);
}

void silofs_env_unlock(struct silofs_env *env)
{
	silofs_mutex_unlock(&env->mutex);
}

void silofs_env_rwlock(struct silofs_env *env, bool ex)
{
	if (ex) {
		silofs_rwlock_wrlock(&env->rwlock);
	} else {
		silofs_rwlock_rdlock(&env->rwlock);
	}
}

void silofs_env_rwunlock(struct silofs_env *env)
{
	silofs_rwlock_unlock(&env->rwlock);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

void silofs_env_drop_caches(struct silofs_env *env)
{
	silofs_freepaqs_drop(env->base.fpaqs);
	silofs_freevsqs_drop(env->base.fvsqs);
	silofs_vcache_drop(env->base.vcache);
	silofs_pcache_drop(env->base.pcache);
	silofs_repo_drop_some(env->base.repo);
}

int silofs_env_shut(struct silofs_env *env)
{
	log_dbg("shut env: op_count=%lu", env->opstat.op_count);
	silofs_ubref_update(&env->ubref, nullptr);
	return 0;
}

void silofs_env_relax_caches(const struct silofs_env *env, int flags)
{
	silofs_pcache_relax(env->base.pcache, flags);
	silofs_vcache_relax(env->base.vcache, flags);
	if (flags & SILOFS_CTLF_IDLE) {
		silofs_repo_relax(env->base.repo);
	}
}

void silofs_env_uptime(const struct silofs_env *env, time_t *out_uptime)
{
	const time_t now = silofs_time_mono_now();

	*out_uptime = now - env->init_time;
}

void silofs_env_allocstat(const struct silofs_env *env,
                          struct silofs_alloc_stat *out_alst)
{
	silofs_memstat(env->alloc, out_alst);
}

#if 0
static int env_fork_rebind_super(struct silofs_env *env,
				 const struct silofs_sb_info *sbi_cur,
				 struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = nullptr;
	int err;

	env_drop_uamap(env);
	err = env_spawn_super(env, 0, &sbi);
	if (err) {
		return err;
	}
	silofs_sbi_make_fork_of(sbi, sbi_cur);
	env_update_sb(env, sbi);

	*out_sbi = sbi;
	return 0;
}

static void sbi_mark_fossil(struct silofs_sb_info *sbi)
{
	silofs_sbi_add_flags(sbi, SILOFS_SUPERF_FOSSIL);
}

static void
env_curr_fs_mbref(const struct silofs_env *env, struct silofs_mbref *out_mbref)
{
	silofs_mbref_assign(out_mbref, &env->mbi.mb_ref);
}

static int
env_do_forkfs(struct silofs_env *env, struct silofs_mbrefs *out_mbrefs)
{
	struct silofs_sb_info *sbi_alt = nullptr;
	struct silofs_sb_info *sbi_new = nullptr;
	struct silofs_sb_info *sbi_cur = env->sbi;
	int err;

	env_curr_fs_mbref(env, &out_mbrefs->base);

	err = env_fork_rebind_super(env, sbi_cur, &sbi_alt);
	if (err) {
		return err;
	}

	err = silofs_env_commit_mbr(env, &out_mbrefs->fork);
	if (err) {
		return err;
	}

	err = env_fork_rebind_super(env, sbi_cur, &sbi_new);
	if (err) {
		return err;
	}

	err = silofs_env_commit_mbr(env, &out_mbrefs->main);
	if (err) {
		return err;
	}

	sbi_mark_fossil(sbi_cur);
	return 0;
}
#endif

int silofs_env_forkfs(struct silofs_env *env, struct silofs_mbrefs *out_mbrefs)
{
	int err;

	silofs_memzero(out_mbrefs, sizeof(*out_mbrefs));
	err = -1; /* env_do_forkfs(env, out_mbrefs); */
	(void)env;
	return err;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

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

int silofs_env_reinit_ciphers(struct silofs_env *env)
{
	const struct silofs_mbr_info *fs_mbi = &env->mbi;

	return env_reinit_ciphers(env, &fs_mbi->mb_meta.nmeta.ciargs);
}

int silofs_env_commit_mbr(struct silofs_env *env,
                          struct silofs_mbref *out_mbref)
{
	return silofs_commit_mbr(&env->mbi, env->base.dstor, out_mbref);
}

int silofs_env_sense_mbr(struct silofs_env *env,
                         const struct silofs_mbref *mbref)
{
	return silofs_sense_mbr(env->base.dstor, mbref);
}

int silofs_env_reload_mbr(struct silofs_env *env,
                          const struct silofs_mbref *mbref)
{
	return silofs_reload_mbr(&env->mbi, env->base.dstor, mbref);
}

int silofs_env_unref_mbr(struct silofs_env *env,
                         const struct silofs_mbref *mbref)
{
	return silofs_unref_mbr(&env->mbi, env->base.dstor, mbref);
}
