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
#include "obs.h"
#include "fs.h"
#include "mbr.h"
#include "env.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_pmeta *ubi_pmeta(const struct silofs_uber_info *ubi)
{
	return &ubi->ub_pni.pn_meta;
}

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
	if (ubi != nullptr) {
		silofs_mbi_set_root(&env->mbis.fs_mbi, ubi_pmeta(ubi));
	}
}

static void
env_update_uber(struct silofs_env *env, struct silofs_uber_info *ubi)
{
	env_bind_ubi(env, ubi);
	env_update_root_uber(env, ubi);
}

static int env_resolve_root_uber(const struct silofs_env *env,
                                 struct silofs_pmeta *out_pmeta)
{
	return silofs_mbi_uber_root(&env->mbis.fs_mbi, out_pmeta);
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
	if (sbi != nullptr) {
		silofs_mbi_set_sbaddr(&env->mbis.fs_mbi,
		                      silofs_sbi_uaddr(sbi));
	}
}

static void env_update_sb(struct silofs_env *env, struct silofs_sb_info *sbi)
{
	env_bind_sbi(env, sbi);
	env_update_root_sb(env, sbi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_env_update_owner(struct silofs_env *env,
                            const struct silofs_cred *cred)
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

int silofs_env_use_password(struct silofs_env *env,
                            const struct silofs_password *pw)
{
	struct silofs_mbr_meta mbr_meta = {};
	int err;

	err = silofs_derive_mbr_meta(pw, &mbr_meta);
	if (err) {
		return err;
	}
	mbr_meta.mode = SILOFS_MBR_FS;
	err           = silofs_mbi_set_meta(&env->mbis.fs_mbi, &mbr_meta);
	if (err) {
		return err;
	}
	mbr_meta.mode = SILOFS_MBR_AR;
	err           = silofs_mbi_set_meta(&env->mbis.ar_mbi, &mbr_meta);
	if (err) {
		return err;
	}
	return 0;
}

static int env_update_mntflags(struct silofs_env *env, enum silofs_flags flags)
{
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
	return 0;
}

static int env_update_name(struct silofs_env *env, const char *fsname)
{
	struct silofs_namestr nstr;
	int err;

	if (fsname == nullptr) {
		silofs_strbuf_reset(&env->name);
		return 0;
	}
	err = silofs_make_fsnamestr(&nstr, fsname);
	if (err) {
		return err;
	}
	silofs_strbuf_setup(&env->name, &nstr.sv);
	return 0;
}

int silofs_env_update_by_args(struct silofs_env *env,
                              const struct silofs_args *args)
{
	const char *fsname = args->bref[0].refname;
	int err;

	err = env_update_name(env, fsname);
	if (err) {
		return err;
	}
	err = env_update_mntflags(env, args->flags);
	if (err) {
		return err;
	}
	env->flags = args->flags;
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
	env->opstat.op_iopen     = 0;
	env->opstat.op_time      = silofs_time_real_now();
	env->opstat.op_count     = 0;
	env->opstat.op_iopen_max = env_calc_iopen_limit(env);
}

static void
env_init_commons(struct silofs_env *env, const struct silofs_env_base *base)
{
	memcpy(&env->base, base, sizeof(env->base));
	silofs_strbuf_reset(&env->name);
	silofs_cred_init(&env->owner_cred);
	env->init_time = silofs_time_mono_now();
	env->ubi       = nullptr;
	env->sbi       = nullptr;
	env->flags     = 0;
	env->ms_flags  = 0;
	env->iconv_set = false;
}

static void env_fini_commons(struct silofs_env *env)
{
	memset(&env->base, 0, sizeof(env->base));
	silofs_cred_fini(&env->owner_cred);
	env->ubi      = nullptr;
	env->sbi      = nullptr;
	env->ms_flags = 0;
}

static int env_init_mbis(struct silofs_env *env)
{
	silofs_mbi_init(&env->mbis.fs_mbi, SILOFS_MBR_FS);
	silofs_mbi_init(&env->mbis.ar_mbi, SILOFS_MBR_AR);
	return 0;
}

static void env_fini_mbis(struct silofs_env *env)
{
	silofs_mbi_fini(&env->mbis.fs_mbi);
	silofs_mbi_fini(&env->mbis.ar_mbi);
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

int silofs_env_init(struct silofs_env *env, const struct silofs_env_base *base)
{
	int err;

	env_init_commons(env, base);

	env_init_opstat(env);

	err = env_init_mbis(env);
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
	env_fini_mbis(env);
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
	return (env->flags & f) == f;
}

bool silofs_env_isrdonlyfs(const struct silofs_env *env)
{
	return silofs_env_hasflag(env, SILOFS_F_RDONLY) ||
	       silofs_sbi_is_fossil(env->sbi);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void
env_make_uniqid(struct silofs_env *env, struct silofs_uniqid *out_uniqid)
{
	silofs_generate_uniqid(env->base.prng, out_uniqid);
}

static void
env_make_civkey(struct silofs_env *env, struct silofs_civkey *out_civkey)
{
	silofs_generate_civkey(env->base.prng, out_civkey);
}

static void env_make_first_uber_paddr(struct silofs_env *env,
                                      struct silofs_paddr *out_paddr)
{
	struct silofs_svolid svolid;
	struct silofs_uniqid uniqid;
	struct silofs_blobid blobid;

	silofs_svolid_generate(&svolid);
	env_make_uniqid(env, &uniqid);
	silofs_blobid_setup_raw3(&blobid, &svolid, &uniqid, SILOFS_MTYPE_UBER);
	silofs_paddr_init(out_paddr, &blobid, 0);
}

static void env_make_first_uber_pmeta(struct silofs_env *env,
                                      struct silofs_pmeta *out_pmeta)
{
	struct silofs_paddr paddr;
	struct silofs_civkey civkey;

	env_make_first_uber_paddr(env, &paddr);
	env_make_civkey(env, &civkey);
	silofs_pmeta_setup(out_pmeta, &paddr, &civkey);
}

int silofs_env_format_uber(struct silofs_env *env)
{
	struct silofs_pmeta pmeta;
	struct silofs_uber_info *ubi = nullptr;
	int err;

	env_make_first_uber_pmeta(env, &pmeta);
	err = silofs_spawn_uber(env, &pmeta, &ubi);
	if (err) {
		return err;
	}
	env_update_uber(env, ubi);
	return 0;
}

int silofs_env_reload_uber(struct silofs_env *env)
{
	struct silofs_pmeta pmeta;
	struct silofs_uber_info *ubi = nullptr;
	int err;

	err = env_resolve_root_uber(env, &pmeta);
	if (err) {
		return err;
	}
	err = silofs_stage_uber(env, &pmeta, &ubi);
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

static void env_mbr_sb_addr(const struct silofs_env *env,
                            struct silofs_uaddr *out_sb_uabbr)
{
	silofs_mbi_sbaddr(&env->mbis.fs_mbi, out_sb_uabbr);
}

int silofs_env_reload_super(struct silofs_env *env)
{
	struct silofs_uaddr sb_uaddr;
	struct silofs_sb_info *sbi = nullptr;
	int err;

	env_mbr_sb_addr(env, &sb_uaddr);
	err = silofs_stage_super(env, &sb_uaddr, &sbi);
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

int silofs_env_reload_sb_lseg(struct silofs_env *env)
{
	struct silofs_uaddr sb_uaddr;
	int err;

	env_mbr_sb_addr(env, &sb_uaddr);
	err = silofs_stage_lseg(env, &sb_uaddr.laddr.lsid);
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
env_recalc_fs_mbref(struct silofs_env *env, struct silofs_mbref *out_mbref)
{
	struct silofs_mbr1k mbr1k = { .mbr_magic = UINT64_MAX };

	return silofs_env_export_fs_mbr(env, out_mbref, &mbr1k);
}

static int
env_do_forkfs(struct silofs_env *env, struct silofs_mbrefs *out_mbrefs)
{
	struct silofs_sb_info *sbi_alt = nullptr;
	struct silofs_sb_info *sbi_new = nullptr;
	struct silofs_sb_info *sbi_cur = env->sbi;
	int err;

	err = env_recalc_fs_mbref(env, &out_mbrefs->base);
	if (err) {
		return err;
	}

	err = env_fork_rebind_super(env, sbi_cur, &sbi_alt);
	if (err) {
		return err;
	}
	err = silofs_env_commit_fs_mbr(env, &out_mbrefs->fork);
	if (err) {
		return err;
	}

	err = env_fork_rebind_super(env, sbi_cur, &sbi_new);
	if (err) {
		return err;
	}
	err = silofs_env_commit_fs_mbr(env, &out_mbrefs->main);
	if (err) {
		return err;
	}

	sbi_mark_fossil(sbi_cur);
	return 0;
}

int silofs_env_forkfs(struct silofs_env *env, struct silofs_mbrefs *out_mbrefs)
{
	struct silofs_sb_info *sbi = env->sbi;
	int err;

	silofs_sbi_incref(sbi);
	err = env_do_forkfs(env, out_mbrefs);
	silofs_sbi_decref(sbi);
	return err;
}

int silofs_env_export_fs_mbr(struct silofs_env *env,
                             struct silofs_mbref *out_mbref,
                             struct silofs_mbr1k *out_mbr1k)
{
	return silofs_mbi_export(&env->mbis.fs_mbi, out_mbref, out_mbr1k);
}

int silofs_env_export_ar_mbr(struct silofs_env *env,
                             struct silofs_mbref *out_mbref,
                             struct silofs_mbr1k *out_mbr1k)
{
	return silofs_mbi_export(&env->mbis.ar_mbi, out_mbref, out_mbr1k);
}
