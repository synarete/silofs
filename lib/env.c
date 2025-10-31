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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include "bs.h"
#include "fs.h"
#include "mbr.h"
#include "env.h"

static void
env_bind_sbi(struct silofs_env *env, struct silofs_sb_info *sbi_new)
{
	struct silofs_sb_info *sbi_cur = env->sbi;

	if (sbi_cur != nullptr) {
		silofs_sbi_decref(sbi_cur);
	}
	if (sbi_new != nullptr) {
		silofs_sbi_incref(sbi_new);
	}
	env->sbi = sbi_new;
}

static void env_update_mbr_sb_addr(struct silofs_env *env)
{
	const struct silofs_uaddr *uaddr = nullptr;

	if (env->sbi != nullptr) {
		uaddr = silofs_sbi_uaddr(env->sbi);
	} else {
		uaddr = silofs_uaddr_none();
	}
	silofs_mbri_update_sb_addr(&env->mbri, uaddr);
}

static void env_rebind_sbi(struct silofs_env *env, struct silofs_sb_info *sbi)
{
	env_bind_sbi(env, sbi);
	env_update_mbr_sb_addr(env);
}

static void env_update_owner(struct silofs_env *env)
{
	const struct silofs_env_args *args = env->base.args;

	env->owner_cred.uid = args->uid;
	env->owner_cred.gid = args->gid;
	env->owner_cred.umask = args->umask;
}

static void env_update_mntflags(struct silofs_env *env)
{
	const enum silofs_flags flags = env->base.args->flags;
	unsigned long ms_flag_with = 0;
	unsigned long ms_flag_dont = 0;

	if (flags & SILOFS_F_LAZYTIME) {
		ms_flag_with |= MS_LAZYTIME;
	} else {
		ms_flag_dont |= MS_LAZYTIME;
	}
	if (flags & SILOFS_F_NOEXEC) {
		ms_flag_with |= MS_NOEXEC;
	} else {
		ms_flag_dont |= MS_NOEXEC;
	}
	if (flags & SILOFS_F_NOSUID) {
		ms_flag_with |= MS_NOSUID;
	} else {
		ms_flag_dont |= MS_NOSUID;
	}
	if (flags & SILOFS_F_NODEV) {
		ms_flag_with |= MS_NODEV;
	} else {
		ms_flag_dont |= MS_NODEV;
	}
	if (flags & SILOFS_F_RDONLY) {
		ms_flag_with |= MS_RDONLY;
	} else {
		ms_flag_dont |= MS_RDONLY;
	}
	env->ms_flags |= ms_flag_with;
	env->ms_flags &= ~ms_flag_dont;
}

static int env_update_by_env_args(struct silofs_env *env)
{
	env_update_owner(env);
	env_update_mntflags(env);
	return 0;
}

static size_t env_calc_iopen_limit(const struct silofs_env *env)
{
	struct silofs_alloc_stat st;
	const size_t align = 128;
	size_t lim;

	silofs_memstat(env->base.alloc, &st);
	lim = (st.nbytes_max / (2 * SILOFS_LBK_SIZE));
	return silofs_div_round_up(lim, align) * align;
}

static void env_init_opstat(struct silofs_env *env)
{
	env->opstat.op_iopen_max = 0;
	env->opstat.op_iopen = 0;
	env->opstat.op_time = silofs_time_real_now();
	env->opstat.op_count = 0;
	env->opstat.op_iopen_max = env_calc_iopen_limit(env);
}

static void
env_init_commons(struct silofs_env *env, const struct silofs_env_base *base)
{
	memcpy(&env->base, base, sizeof(env->base));
	env->init_time = silofs_time_mono_now();
	env->iconv_set = false;
	env->sbi = nullptr;
	env->ms_flags = 0;
}

static void env_fini_commons(struct silofs_env *env)
{
	memset(&env->base, 0, sizeof(env->base));
	env->sbi = nullptr;
	env->ms_flags = 0;
}

static int env_init_mbri(struct silofs_env *env)
{
	int err;

	err = silofs_mbri_init(&env->mbri);
	if (err) {
		return err;
	}
	err = silofs_mbri_derive_ivkey(&env->mbri, env->base.passwd);
	if (err) {
		silofs_mbri_fini(&env->mbri);
		return err;
	}
	return 0;
}

static void env_fini_mbri(struct silofs_env *env)
{
	silofs_mbri_fini(&env->mbri);
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
	silofs_cipher_fini(&env->dec_cipher);
	silofs_cipher_fini(&env->enc_cipher);
	silofs_mdigest_fini(&env->mdigest);
}

static int env_init_crypto(struct silofs_env *env)
{
	int err;

	err = silofs_mdigest_init(&env->mdigest);
	if (err) {
		return err;
	}
	err = silofs_cipher_init(&env->enc_cipher);
	if (err) {
		goto out_err;
	}
	err = silofs_cipher_init(&env->dec_cipher);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	env_fini_crypto(env);
	return err;
}

static int env_init_iconv(struct silofs_env *env)
{
	/* Using UTF32LE to avoid BOM (byte-order-mark) character */
	env->iconv = iconv_open("UTF32LE", "UTF8");
	if (env->iconv == (iconv_t)(-1)) { // NOLINT
		return errno ? -errno : -SILOFS_EOPNOTSUPP;
	}
	env->iconv_set = true;
	return 0;
}

static void env_fini_iconv(struct silofs_env *env)
{
	if (env->iconv_set) {
		iconv_close(env->iconv);
		env->iconv_set = false;
	}
}

int silofs_env_init(struct silofs_env *env, const struct silofs_env_base *base)
{
	int err;

	env_init_commons(env, base);
	env_init_opstat(env);

	err = env_init_mbri(env);
	if (err) {
		return err;
	}
	err = env_update_by_env_args(env);
	if (err) {
		return err;
	}
	err = env_init_locks(env);
	if (err) {
		return err;
	}
	err = env_init_crypto(env);
	if (err) {
		goto out_err;
	}
	err = env_init_iconv(env);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	silofs_env_fini(env);
	return err;
}

void silofs_env_fini(struct silofs_env *env)
{
	env_bind_sbi(env, nullptr);
	env_fini_iconv(env);
	env_fini_crypto(env);
	env_fini_locks(env);
	env_fini_mbri(env);
	env_fini_commons(env);
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

bool silofs_env_hasflag(const struct silofs_env *env, enum silofs_flags f)
{
	return (env->base.args->flags & f) == f;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void make_super_lsid(struct silofs_lsid *out_lsid)
{
	struct silofs_svolid svolid;
	struct silofs_blobid blobid;

	silofs_svolid_generate(&svolid);
	silofs_blobid_setup_raw2(&blobid, &svolid, SILOFS_MTYPE_SUPER,
	                         SILOFS_MTYPE_SUPER, SILOFS_HEIGHT_SUPER);
	silofs_lsid_setup(out_lsid, &blobid, 0);
}

static void make_super_uaddr(const struct silofs_lsid *lsid,
                             struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr_setup(out_uaddr, lsid, 0, 0);
}

static const struct silofs_uaddr *env_sb_addr(const struct silofs_env *env)
{
	return &env->mbri.fs_mbr.sb_addr;
}

static void env_make_super_uaddr(const struct silofs_env *env,
                                 struct silofs_uaddr *out_uaddr)
{
	struct silofs_lsid lsid = { .lsize = 0 };

	make_super_lsid(&lsid);
	make_super_uaddr(&lsid, out_uaddr);
	silofs_unused(env);
}

static void env_resolve_super_uaddr(const struct silofs_env *env,
                                    struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr_assign(out_uaddr, env_sb_addr(env));
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_env_drop_caches(struct silofs_env *env)
{
	silofs_lcache_drop(env->base.lcache);
	silofs_spamaps_drop(env->base.spamaps);
	silofs_bcache_drop(env->base.bcache);
	silofs_repo_drop_some(env->base.repo);
}

static int
env_spawn_super_at(struct silofs_env *env, const struct silofs_uaddr *uaddr,
                   struct silofs_sb_info **out_sbi)
{
	int err;

	err = silofs_spawn_super(env, uaddr, out_sbi);
	if (err) {
		return err;
	}
	silofs_sbi_setup_spawned(*out_sbi);
	return 0;
}

static int
env_spawn_super_of(struct silofs_env *env, struct silofs_sb_info **out_sbi)
{
	struct silofs_uaddr uaddr = { .voff = -1 };

	env_make_super_uaddr(env, &uaddr);
	return env_spawn_super_at(env, &uaddr, out_sbi);
}

static int env_spawn_super(struct silofs_env *env, size_t capacity,
                           struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = nullptr;
	int err;

	err = env_spawn_super_of(env, &sbi);
	if (err) {
		return err;
	}
	silofs_sbst_set_capacity(sbi, capacity);
	*out_sbi = sbi;
	return 0;
}

int silofs_env_format_super(struct silofs_env *env, size_t capacity)
{
	struct silofs_sb_info *sbi = nullptr;
	int err;

	err = env_spawn_super(env, capacity, &sbi);
	if (err) {
		return err;
	}
	silofs_sbst_account_super(sbi);
	env_bind_sbi(env, sbi);
	return 0;
}

static int
env_check_sb(const struct silofs_env *env, const struct silofs_sb_info *sbi)
{
	const struct silofs_super_block *sb = sbi->sb;
	int err;
	bool fossil;
	bool rdonly;

	err = silofs_sb_check_version(sb);
	if (err) {
		log_err("bad sb: magic=%lx version:=%ld err=%d", sb->sb_magic,
		        sb->sb_version, err);
		return err;
	}
	fossil = silofs_sb_test_flags(sb, SILOFS_SUPERF_FOSSIL);
	rdonly = silofs_env_hasflag(env, SILOFS_F_RDONLY);
	if (fossil && !rdonly) {
		log_warn("read-only fs: sb-flags=%08x", (int)sb->sb_flags);
		return -SILOFS_EROFS;
	}
	return 0;
}

int silofs_env_reload_super(struct silofs_env *env)
{
	struct silofs_uaddr uaddr;
	struct silofs_sb_info *sbi = nullptr;
	int err;

	env_resolve_super_uaddr(env, &uaddr);
	err = silofs_stage_super(env, &uaddr, &sbi);
	if (err) {
		return err;
	}
	err = env_check_sb(env, sbi);
	if (err) {
		return err;
	}
	env_bind_sbi(env, sbi);
	return 0;
}

static const struct silofs_lsid *env_sb_lsid(const struct silofs_env *env)
{
	const struct silofs_uaddr *sb_uaddr = env_sb_addr(env);

	return &sb_uaddr->laddr.lsid;
}

int silofs_env_reload_sb_lseg(struct silofs_env *env)
{
	const struct silofs_lsid *lsid = env_sb_lsid(env);
	int err;

	err = silofs_stage_lseg(env, lsid);
	if (err) {
		log_warn("unable to stage sb-lseg: err=%d", err);
		return err;
	}
	return 0;
}

static int env_shut_sb(struct silofs_env *env)
{
	int err;

	err = silofs_sbi_shut(env->sbi);
	if (err) {
		return err;
	}
	env_rebind_sbi(env, nullptr);
	return 0;
}

static int env_shut_bstore(struct silofs_env *env)
{
	// XXX
	silofs_unused(env);
	return 0;
}

int silofs_env_shut(struct silofs_env *env)
{
	int err;

	err = env_shut_sb(env);
	if (err) {
		return err;
	}
	err = env_shut_bstore(env);
	if (err) {
		return err;
	}
	return 0;
}

void silofs_env_relax_caches(const struct silofs_env *env, int flags)
{
	silofs_bcache_relax(env->base.bcache, flags);
	silofs_lcache_relax(env->base.lcache, flags);
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
	silofs_memstat(env->base.alloc, out_alst);
}

static void env_drop_uamap(struct silofs_env *env)
{
	silofs_lcache_drop_uamap(env->base.lcache);
}

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
	env_rebind_sbi(env, sbi);

	*out_sbi = sbi;
	return 0;
}

static void sbi_mark_fossil(struct silofs_sb_info *sbi)
{
	silofs_sbi_add_flags(sbi, SILOFS_SUPERF_FOSSIL);
}

static int
env_recalc_fs_mref(struct silofs_env *env, struct silofs_baddr *out_baddr)
{
	struct silofs_mbr1k mbr1k = { .mbr_magic = UINT64_MAX };

	return silofs_mbri_encode_mbr(&env->mbri, SILOFS_MBR_FS, out_baddr,
	                              &mbr1k);
}

static int
env_do_forkfs(struct silofs_env *env, struct silofs_mrefs *out_mrefs)
{
	struct silofs_sb_info *sbi_alt = nullptr;
	struct silofs_sb_info *sbi_new = nullptr;
	struct silofs_sb_info *sbi_cur = env->sbi;
	int err;

	err = env_recalc_fs_mref(env, &out_mrefs->base);
	if (err) {
		return err;
	}

	err = env_fork_rebind_super(env, sbi_cur, &sbi_alt);
	if (err) {
		return err;
	}
	err = silofs_env_commit_fs_mbr(env, &out_mrefs->fork);
	if (err) {
		return err;
	}

	err = env_fork_rebind_super(env, sbi_cur, &sbi_new);
	if (err) {
		return err;
	}
	err = silofs_env_commit_fs_mbr(env, &out_mrefs->main);
	if (err) {
		return err;
	}

	sbi_mark_fossil(sbi_cur);
	return 0;
}

int silofs_env_forkfs(struct silofs_env *env, struct silofs_mrefs *out_mrefs)
{
	struct silofs_sb_info *sbi = env->sbi;
	int err;

	silofs_sbi_incref(sbi);
	err = env_do_forkfs(env, out_mrefs);
	silofs_sbi_decref(sbi);
	return err;
}

static int check_arix_size(ssize_t sz)
{
	const ssize_t arix_size = silofs_mtype_ssize(SILOFS_MTYPE_ARIX);

	return (arix_size == sz) ? 0 : -SILOFS_EBADARIX;
}

static int
env_arix_addr(const struct silofs_env *env, struct silofs_baddr *out_baddr)
{
	return silofs_mbri_arix_addr(&env->mbri, out_baddr);
}

int silofs_env_sense_ar(struct silofs_env *env)
{
	struct silofs_baddr baddr;
	struct stat st;
	int err;

	err = env_arix_addr(env, &baddr);
	if (err) {
		return err;
	}
	err = silofs_repo_stat_blob(env->base.repo, &baddr.blobid, &st);
	if (err) {
		return err;
	}
	err = check_arix_size(st.st_size);
	if (err) {
		return err;
	}
	return 0;
}
