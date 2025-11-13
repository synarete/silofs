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
#include "gbr.h"
#include "env.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void
env_bind_ubi(struct silofs_env *env, struct silofs_uber_info *ubi_new)
{
	struct silofs_uber_info *ubi_cur = env->ubi;

	if (ubi_cur != nullptr) {
		silofs_ubi_decref(ubi_cur);
	}
	if (ubi_new != nullptr) {
		silofs_ubi_incref(ubi_new);
	}
	env->ubi = ubi_new;
}

static void env_update_root_uber(struct silofs_env *env,
                                 const struct silofs_uber_info *ubi)
{
	const struct silofs_paddr *paddr = nullptr;

	if (ubi != nullptr) {
		paddr = silofs_ubi_paddr(ubi);
		silofs_gbrs_set_root(&env->gbrs, SILOFS_GBR_FS, paddr);
	}
}

static void
env_update_uber(struct silofs_env *env, struct silofs_uber_info *ubi)
{
	env_bind_ubi(env, ubi);
	env_update_root_uber(env, ubi);
}

static inline int env_resolve_root_uber(const struct silofs_env *env,
                                        struct silofs_paddr *out_paddr)
{
	return silofs_gbrs_root(&env->gbrs, SILOFS_GBR_FS, out_paddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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

static void
env_update_root_sb(struct silofs_env *env, const struct silofs_sb_info *sbi)
{
	const struct silofs_uaddr *uaddr = nullptr;

	if (sbi != nullptr) {
		uaddr = silofs_sbi_uaddr(sbi);
		silofs_gbrs_update_sb_addr(&env->gbrs, uaddr);
	}
}

static void env_update_sb(struct silofs_env *env, struct silofs_sb_info *sbi)
{
	env_bind_sbi(env, sbi);
	env_update_root_sb(env, sbi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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
	env->ubi = nullptr;
	env->sbi = nullptr;
	env->ms_flags = 0;
}

static void env_fini_commons(struct silofs_env *env)
{
	memset(&env->base, 0, sizeof(env->base));
	env->ubi = nullptr;
	env->sbi = nullptr;
	env->ms_flags = 0;
}

static int env_init_gbrs(struct silofs_env *env)
{
	int err;

	err = silofs_gbrs_init(&env->gbrs);
	if (err) {
		return err;
	}
	err = silofs_gbrs_derive_ivkey(&env->gbrs, env->base.passwd);
	if (err) {
		silofs_gbrs_fini(&env->gbrs);
		return err;
	}
	return 0;
}

static void env_fini_gbrs(struct silofs_env *env)
{
	silofs_gbrs_fini(&env->gbrs);
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

static int env_init_uconv(struct silofs_env *env)
{
	return silofs_uconv_init(&env->uconv);
}

static void env_fini_uconv(struct silofs_env *env)
{
	silofs_uconv_fini(&env->uconv);
}

int silofs_env_init(struct silofs_env *env, const struct silofs_env_base *base)
{
	int err;

	env_init_commons(env, base);
	env_init_opstat(env);

	err = env_init_gbrs(env);
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
	err = env_init_uconv(env);
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
	env_update_sb(env, nullptr);
	env_update_uber(env, nullptr);
	env_fini_uconv(env);
	env_fini_crypto(env);
	env_fini_locks(env);
	env_fini_gbrs(env);
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

bool silofs_env_isrdonlyfs(const struct silofs_env *env)
{
	bool ret = false;

	if (silofs_env_hasflag(env, SILOFS_F_RDONLY)) {
		ret = true;
	} else if (env->ms_flags & MS_RDONLY) {
		ret = true;
	} else if (silofs_sbi_test_flags(env->sbi, SILOFS_SUPERF_FOSSIL)) {
		ret = true;
	}
	return ret;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void make_uber_addr(struct silofs_paddr *out_paddr)
{
	struct silofs_svolid svolid;
	struct silofs_blobid blobid;

	silofs_svolid_generate(&svolid);
	silofs_blobid_setup_raw(&blobid, &svolid, SILOFS_MTYPE_UBER);
	silofs_paddr_init(out_paddr, &blobid, 0);
}

int silofs_env_format_uber(struct silofs_env *env)
{
	struct silofs_paddr paddr;
	struct silofs_uber_info *ubi = nullptr;
	int err;

	silofs_assert_null(env->ubi);
	make_uber_addr(&paddr);
	err = silofs_spawn_uber(env, &paddr, &ubi);
	if (err) {
		return err;
	}
	env_update_uber(env, ubi);
	return 0;
}

static const struct silofs_paddr *env_gbr_ub_addr(const struct silofs_env *env)
{
	return &env->gbrs.fs_gbr.root;
}

int silofs_env_reload_uber(struct silofs_env *env)
{
	const struct silofs_paddr *ub_addr = env_gbr_ub_addr(env);
	struct silofs_uber_info *ubi = nullptr;
	int err;

	err = silofs_stage_uber(env, ub_addr, &ubi);
	if (err) {
		return err;
	}
	env_update_uber(env, ubi);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void make_super_lsid(struct silofs_lsid *out_lsid)
{
	struct silofs_svolid svolid;
	struct silofs_blobid blobid;

	silofs_svolid_generate(&svolid);
	silofs_blobid_setup_raw2(&blobid, &svolid, SILOFS_MTYPE_SUPER,
	                         SILOFS_MTYPE_SUPER, SILOFS_HEIGHT_SUPER);
	silofs_lsid_setup(out_lsid, &blobid, 0);
}

static void make_super_uaddr(struct silofs_uaddr *out_uaddr)
{
	struct silofs_lsid lsid = { .lsize = 0 };

	make_super_lsid(&lsid);
	silofs_uaddr_setup(out_uaddr, &lsid, 0, 0);
}

static int
env_spawn_super_of(struct silofs_env *env, struct silofs_sb_info **out_sbi)
{
	struct silofs_uaddr uaddr = { .voff = -1 };
	int err;

	make_super_uaddr(&uaddr);
	err = silofs_spawn_super(env, &uaddr, out_sbi);
	if (err) {
		return err;
	}
	silofs_sbi_setup_spawned(*out_sbi);
	return 0;
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
	env_update_sb(env, sbi);
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

static const struct silofs_uaddr *env_gbr_sb_addr(const struct silofs_env *env)
{
	return &env->gbrs.fs_gbr.sb_addr;
}

int silofs_env_reload_super(struct silofs_env *env)
{
	const struct silofs_uaddr *sb_addr = env_gbr_sb_addr(env);
	struct silofs_sb_info *sbi = nullptr;
	int err;

	err = silofs_stage_super(env, sb_addr, &sbi);
	if (err) {
		return err;
	}
	err = env_check_sb(env, sbi);
	if (err) {
		return err;
	}
	env_update_sb(env, sbi);
	return 0;
}

static const struct silofs_lsid *env_sb_lsid(const struct silofs_env *env)
{
	const struct silofs_uaddr *sb_uaddr = env_gbr_sb_addr(env);

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

void silofs_env_drop_caches(struct silofs_env *env)
{
	silofs_lcache_drop(env->base.lcache);
	silofs_spamaps_drop(env->base.spamaps);
	silofs_pcache_drop(env->base.pcache);
	silofs_repo_drop_some(env->base.repo);
}

int silofs_env_shut(struct silofs_env *env)
{
	log_dbg("shut env: op_count=%lu", env->opstat.op_count);
	env_update_sb(env, nullptr);
	env_update_uber(env, nullptr);
	return 0;
}

void silofs_env_relax_caches(const struct silofs_env *env, int flags)
{
	silofs_pcache_relax(env->base.pcache, flags);
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
	env_update_sb(env, sbi);

	*out_sbi = sbi;
	return 0;
}

static void sbi_mark_fossil(struct silofs_sb_info *sbi)
{
	silofs_sbi_add_flags(sbi, SILOFS_SUPERF_FOSSIL);
}

static int
env_recalc_fs_mref(struct silofs_env *env, struct silofs_paddr *out_paddr)
{
	struct silofs_gbr1k gbr1k = { .gbr_magic = UINT64_MAX };

	return silofs_gbrs_encode(&env->gbrs, SILOFS_GBR_FS, out_paddr,
	                          &gbr1k);
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
	err = silofs_env_commit_fs_gbr(env, &out_mrefs->fork);
	if (err) {
		return err;
	}

	err = env_fork_rebind_super(env, sbi_cur, &sbi_new);
	if (err) {
		return err;
	}
	err = silofs_env_commit_fs_gbr(env, &out_mrefs->main);
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
env_arix_addr(const struct silofs_env *env, struct silofs_paddr *out_paddr)
{
	return silofs_gbrs_root(&env->gbrs, SILOFS_GBR_AR, out_paddr);
}

int silofs_env_sense_ar(struct silofs_env *env)
{
	struct silofs_paddr paddr;
	struct stat st;
	int err;

	err = env_arix_addr(env, &paddr);
	if (err) {
		return err;
	}
	err = silofs_repo_stat_blob(env->base.repo, &paddr.blobid, &st);
	if (err) {
		return err;
	}
	err = check_arix_size(st.st_size);
	if (err) {
		return err;
	}
	return 0;
}
