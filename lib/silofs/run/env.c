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
#include <silofs/fuse.h>
#include "mbr.h"
#include "task.h"
#include "env.h"

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_pnptr *ubi_pnptr(const struct silofs_uber_info *ubi)
{
	return &ubi->ub_pni.pn_self;
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
		silofs_mbi_set_root(&env->mbis.fs_mbi, ubi_pnptr(ubi));
	}
}

void silofs_env_update_uber(struct silofs_env *env,
                            struct silofs_uber_info *ubi)
{
	env_bind_ubi(env, ubi);
	env_update_root_uber(env, ubi);
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

	if (flags & SILOFS_F_NOPASSWD) {
		return 0; /* password-less mode */
	}
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

static int env_update_fscap(struct silofs_env *env, size_t cap_want)
{
	const size_t align_size = SILOFS_LSEG_SIZE_MAX;
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

static int env_setup_mntflags(struct silofs_env *env, enum silofs_flags flags)
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

static void env_update_vfs_hooks(struct silofs_env *env)
{
	silofs_env_bind_hooks(env);
	if (env->fuseq != nullptr) {
		env->fuseq->fq_env       = env;
		env->fuseq->fq_vfs_hooks = env->vfs_hooks;
	}
}

int silofs_env_setup(struct silofs_env *env, const struct silofs_spec *spec)
{
	int err;

	err = env_update_repodir(env, spec->bref[0].repodir);
	if (err) {
		return err;
	}
	err = env_update_name(env, spec->bref[0].refname);
	if (err) {
		return err;
	}
	err = env_setup_owner(env, &spec->fsowner);
	if (err) {
		return err;
	}
	err = env_use_password(env, &spec->passwd, spec->flags);
	if (err) {
		return err;
	}
	err = env_update_fscap(env, spec->fscap);
	if (err) {
		return err;
	}
	err = env_setup_mntflags(env, spec->flags);
	if (err) {
		return err;
	}
	env_update_vfs_hooks(env);
	env_update_iopen_max(env);
	env->flags = spec->flags;
	return 0;
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
	env->init_time = silofs_time_mono_now();
	env->alloc     = alloc;
	env->ubi       = nullptr;
	env->sbi       = nullptr;
	env->flags     = 0;
	env->ms_flags  = 0;
	env->iconv_set = false;
	env->repodir   = nullptr;
	env->fuseq     = nullptr;
	env->vfs_hooks = nullptr;
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

int silofs_env_init(struct silofs_env *env, struct silofs_alloc *alloc)
{
	int err;

	env_init_commons(env, alloc);
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
	env_update_repodir(env, nullptr);
	env_update_sb(env, nullptr);
	silofs_env_update_uber(env, nullptr);
	env_fini_uconv(env);
	env_fini_crypto(env);
	env_fini_locks(env);
	env_fini_mbis(env);
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
make_super_lsid(struct silofs_env *env, struct silofs_lsid *out_lsid)
{
	struct silofs_blobid blobid;
	struct silofs_layerid layerid;
	struct silofs_uniqid uniqid;
	const struct silofs_stype stype = {
		.ptype = SILOFS_PTYPE_VNODE,
		.vtype = SILOFS_VTYPE_SUPER,
	};

	silofs_generate_layerid(env->base.prng, &layerid);
	silofs_generate_uniqid(env->base.prng, &uniqid);
	silofs_blobid_init(&blobid, &stype, &layerid, &uniqid);
	blobid.height = SILOFS_HEIGHT_SUPER;

	silofs_lsid_setup(out_lsid, &blobid, 0);
}

static void
make_super_uaddr(struct silofs_env *env, struct silofs_uaddr *out_uaddr)
{
	struct silofs_lsid lsid = { .lsize = 0 };

	make_super_lsid(env, &lsid);
	silofs_uaddr_setup(out_uaddr, &lsid, 0, 0);
}

static int
env_spawn_super_of(struct silofs_env *env, struct silofs_sb_info **out_sbi)
{
	struct silofs_uaddr uaddr = { .voff = -1 };
	int err;

	make_super_uaddr(env, &uaddr);
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
	silofs_env_update_uber(env, nullptr);
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
	silofs_memstat(env->alloc, out_alst);
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

static void
env_curr_fs_mbref(const struct silofs_env *env, struct silofs_mbref *out_mbref)
{
	silofs_mbref_assign(out_mbref, &env->mbis.fs_mbi.mb_ref);
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

int silofs_env_export_ar_mbr(struct silofs_env *env,
                             struct silofs_mbref *out_mbref,
                             struct silofs_mbr1k *out_mbr1k)
{
	return silofs_mbi_export(&env->mbis.ar_mbi, out_mbref, out_mbr1k);
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
	const struct silofs_mbr_info *fs_mbi = &env->mbis.fs_mbi;

	return env_reinit_ciphers(env, &fs_mbi->mb_meta.nmeta.ciargs);
}

int silofs_env_commit_fs_mbr(struct silofs_env *env,
                             struct silofs_mbref *out_mbref)
{
	return silofs_commit_mbr(&env->mbis.fs_mbi, env->base.dstor,
	                         out_mbref);
}

int silofs_env_sense_mbr(struct silofs_env *env,
                         const struct silofs_mbref *mbref)
{
	return silofs_sense_mbr(env->base.dstor, mbref);
}

int silofs_env_reload_fs_mbr(struct silofs_env *env,
                             const struct silofs_mbref *mbref)
{
	return silofs_reload_mbr(&env->mbis.fs_mbi, env->base.dstor, mbref);
}

int silofs_env_reload_ar_mbr(struct silofs_env *env,
                             const struct silofs_mbref *mbref)
{
	return silofs_reload_mbr(&env->mbis.ar_mbi, env->base.dstor, mbref);
}

int silofs_env_unref_fs_mbr(struct silofs_env *env,
                            const struct silofs_mbref *mbref)
{
	return silofs_unref_mbr(&env->mbis.fs_mbi, env->base.dstor, mbref);
}
