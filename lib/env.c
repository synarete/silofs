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

	if (sbi_cur != NULL) {
		silofs_sbi_decref(sbi_cur);
	}
	if (sbi_new != NULL) {
		silofs_sbi_incref(sbi_new);
	}
	env->sbi = sbi_new;
}

static void env_update_mbr_sb_addr(struct silofs_env *env)
{
	const struct silofs_uaddr *uaddr = NULL;
	struct silofs_mbr *mbr = &env->mbrctl.mbr;

	if (env->sbi != NULL) {
		uaddr = silofs_sbi_uaddr(env->sbi);
	} else {
		uaddr = silofs_uaddr_none();
	}
	silofs_mbr_set_sb_addr(mbr, uaddr);
	silofs_mbr_gen_uuid(mbr);
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

static int env_update_base_caddr(struct silofs_env *env)
{
	const struct silofs_xref *xref = &env->base.args->boot_args.fs_xref;
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };
	int err = 0;

	if (silofs_xref_isnull(xref)) {
		goto out;
	}
	err = silofs_xref_to_caddr(xref, &caddr);
	if (err) {
		goto out;
	}
	switch (caddr.ctype) {
	case SILOFS_CTYPE_MBR:
		silofs_env_set_mbr_addr(env, &caddr);
		break;
	case SILOFS_CTYPE_PACKIDX:
		silofs_env_set_arix_addr(env, &caddr);
		break;
	case SILOFS_CTYPE_NONE:
	case SILOFS_CTYPE_ENCSEG:
	default:
		log_err("invalid xref: '%s'", xref->s);
		err = -SILOFS_EINVAL;
		break;
	}
out:
	return err;
}

static int env_update_by_env_args(struct silofs_env *env)
{
	env_update_owner(env);
	env_update_mntflags(env);
	return env_update_base_caddr(env);
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
	silofs_caddr_reset(&env->arix_addr);
	env->init_time = silofs_time_mono_now();
	env->iconv_set = false;
	env->sbi = NULL;
	env->ms_flags = 0;
}

static void env_fini_commons(struct silofs_env *env)
{
	memset(&env->base, 0, sizeof(env->base));
	env->sbi = NULL;
	env->ms_flags = 0;
}

static int env_init_mbrc(struct silofs_env *env)
{
	return silofs_mbrctl_init(&env->mbrctl);
}

static void env_fini_mbrc(struct silofs_env *env)
{
	silofs_mbrctl_fini(&env->mbrctl);
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

	err = env_init_mbrc(env);
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
	env_bind_sbi(env, NULL);
	env_fini_iconv(env);
	env_fini_crypto(env);
	env_fini_locks(env);
	env_fini_mbrc(env);
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

int silofs_env_setup_passwd(struct silofs_env *env,
                            const struct silofs_password *pw)
{
	const struct silofs_mdigest *md = &env->mdigest;
	struct silofs_mbrctl *mbrc = &env->mbrctl;
	int ret = 0;

	if ((pw != NULL) && (pw->passlen > 0)) {
		ret = silofs_derive_default_ivkey(md, pw, &mbrc->ivkey);
	}
	return ret;
}

bool silofs_env_hasflag(const struct silofs_env *env, enum silofs_flags f)
{
	return (env->base.args->flags & f) == f;
}

static bool caddr_ismbr(const struct silofs_caddr *caddr)
{
	return (caddr->ctype == SILOFS_CTYPE_MBR);
}

int silofs_env_mbr_addr(const struct silofs_env *env,
                        struct silofs_caddr *out_caddr)
{
	silofs_caddr_assign(out_caddr, &env->mbrctl.mref);
	return caddr_ismbr(out_caddr) ? 0 : -SILOFS_ENOENT;
}

int silofs_env_set_mbr_addr(struct silofs_env *env,
                            const struct silofs_caddr *caddr)
{
	if (!caddr_ismbr(caddr)) {
		return -SILOFS_EINVAL;
	}
	silofs_caddr_assign(&env->mbrctl.mref, caddr);
	return 0;
}

int silofs_env_arix_addr(const struct silofs_env *env,
                         struct silofs_caddr *out_caddr)
{
	const struct silofs_caddr *caddr = &env->arix_addr;

	silofs_caddr_assign(out_caddr, caddr);
	return (caddr->ctype == SILOFS_CTYPE_PACKIDX) ? 0 : -SILOFS_ENOENT;
}

int silofs_env_set_arix_addr(struct silofs_env *env,
                             const struct silofs_caddr *caddr)
{
	if (caddr->ctype != SILOFS_CTYPE_PACKIDX) {
		return -SILOFS_EINVAL;
	}
	silofs_caddr_assign(&env->arix_addr, caddr);
	silofs_mbr_set_ar_addr(&env->mbrctl.mbr, caddr);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_env_format_bstore(struct silofs_env *env)
{
	// XXX FIXME
	silofs_unused(env);

	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_env_sense_mbr(struct silofs_env *env,
                         const struct silofs_caddr *caddr)
{
	struct silofs_repo *repo = env->base.repo;
	size_t sz = 0;
	int err;

	err = silofs_repo_lookup_ref(repo, caddr);
	if (err) {
		return err;
	}
	err = silofs_repo_stat_cobj(repo, caddr, &sz);
	if (err) {
		return err;
	}
	if (sz != SILOFS_MBR_SIZE) {
		log_warn("bad mbr: size=%zu", sz);
		return -SILOFS_EBADMBR;
	}
	return 0;
}

int silofs_env_reload_mbr(struct silofs_env *env)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };
	int err;

	err = silofs_env_mbr_addr(env, &caddr);
	if (err) {
		return err;
	}
	err = silofs_reload_mbr(env, &caddr, &env->mbrctl.mbr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_env_unlink_mbr(struct silofs_env *env)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };
	int err;

	err = silofs_env_mbr_addr(env, &caddr);
	if (err) {
		return err;
	}
	err = silofs_unlink_mbr(env, &caddr);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void make_super_lsid(struct silofs_lsid *out_lsid)
{
	struct silofs_blobid blobid;

	silofs_blobid_generate(&blobid);
	silofs_lsid_setup(out_lsid, &blobid, 0, SILOFS_MTYPE_SUPER,
	                  SILOFS_HEIGHT_SUPER, SILOFS_MTYPE_SUPER);
}

static void make_super_uaddr(const struct silofs_lsid *lsid,
                             struct silofs_uaddr *out_uaddr)
{
	silofs_assert_eq(lsid->height, SILOFS_HEIGHT_SUPER);
	silofs_assert_eq(lsid->mtype, SILOFS_MTYPE_SUPER);

	silofs_uaddr_setup(out_uaddr, lsid, 0, 0);
}

static const struct silofs_uaddr *env_sb_addr(const struct silofs_env *env)
{
	return &env->mbrctl.mbr.sb_addr;
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
	silofs_pcache_drop(env->base.pcache);
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
	struct silofs_sb_info *sbi = NULL;
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
	struct silofs_sb_info *sbi = NULL;
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
	struct silofs_sb_info *sbi = NULL;
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
	env_rebind_sbi(env, NULL);
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
	const struct silofs_mbr *mbr = &env->mbrctl.mbr;
	const int algo = mbr->cipher_algo;
	const int mode = mbr->cipher_mode;

	return env_reinit_ciphers(env, algo, mode);
}

static int env_update_mbr(struct silofs_env *env, const struct silofs_mbr *mbr)
{
	struct silofs_caddr caddr;
	int err;

	err = silofs_calc_mbr_caddr(env, mbr, &caddr);
	if (err) {
		return err;
	}
	silofs_env_set_mbr_addr(env, &caddr);
	silofs_mbr_assign(&env->mbrctl.mbr, mbr);
	return 0;
}

int silofs_env_update_by(struct silofs_env *env, const struct silofs_mbr *mbr)
{
	int err;

	err = env_reinit_ciphers_by_mbr(env);
	if (err) {
		return err;
	}
	err = env_update_mbr(env, mbr);
	if (err) {
		return err;
	}
	return 0;
}

static int env_regen_mbr(struct silofs_env *env)
{
	return silofs_mbrctl_regen(&env->mbrctl);
}

int silofs_env_setup_mbr(struct silofs_env *env)
{
	int err;

	err = env_regen_mbr(env);
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
	const struct silofs_uaddr *sb_uaddr = silofs_sbi_uaddr(env->sbi);

	return silofs_mbrctl_update_sb(&env->mbrctl, sb_uaddr);
}

static int env_save_mbr(struct silofs_env *env)
{
	struct silofs_mbr1k mbr1k_enc = { .mbr_magic = UINT64_MAX };
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };
	const struct silofs_rovec rovec = {
		.rov_base = &mbr1k_enc,
		.rov_len = sizeof(mbr1k_enc),
	};
	int err;

	err = silofs_mbrctl_encode(&env->mbrctl, &mbr1k_enc, &caddr);
	if (err) {
		return err;
	}
	err = silofs_repo_save_cobj(env->base.repo, &caddr, &rovec);
	if (err) {
		log_err("failed to save mbr: err=%d", err);
		return err;
	}
	err = silofs_repo_create_ref(env->base.repo, &caddr);
	if (err) {
		log_err("failed to create ref: err=%d", err);
		return err;
	}
	return 0;
}

int silofs_env_commit_mbr(struct silofs_env *env)
{
	int err;

	err = env_pre_commit_mbr(env);
	if (err) {
		return err;
	}
	err = env_save_mbr(env);
	if (err) {
		return err;
	}
	return 0;
}

static void env_drop_uamap(struct silofs_env *env)
{
	silofs_lcache_drop_uamap(env->base.lcache);
}

static int env_fork_rebind_super(struct silofs_env *env,
                                 const struct silofs_sb_info *sbi_cur,
                                 struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = NULL;
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

static void
env_main_ref(const struct silofs_env *env, struct silofs_caddr *out_caddr)
{
	silofs_caddr_assign(out_caddr, &env->mbrctl.mref);
}

static int
env_do_forkfs(struct silofs_env *env, struct silofs_mrefs *out_mrefs)
{
	struct silofs_sb_info *sbi_alt = NULL;
	struct silofs_sb_info *sbi_new = NULL;
	struct silofs_sb_info *sbi_cur = env->sbi;
	int err;

	env_main_ref(env, &out_mrefs->base);
	err = env_fork_rebind_super(env, sbi_cur, &sbi_alt);
	if (err) {
		return err;
	}
	err = silofs_env_commit_mbr(env);
	if (err) {
		return err;
	}
	env_main_ref(env, &out_mrefs->fork);
	err = env_fork_rebind_super(env, sbi_cur, &sbi_new);
	if (err) {
		return err;
	}
	err = silofs_env_commit_mbr(env);
	if (err) {
		return err;
	}
	env_main_ref(env, &out_mrefs->main);

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

static int check_par_index_size(ssize_t sz)
{
	if ((sz < SILOFS_AR_INDEX_SIZE_MIN) ||
	    (sz > SILOFS_AR_INDEX_SIZE_MAX)) {
		return -SILOFS_EBADPACK;
	}
	return 0;
}

int silofs_env_sense_ar(struct silofs_env *env)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };
	ssize_t sz = -1;
	int err;

	err = silofs_env_arix_addr(env, &caddr);
	if (err) {
		return err;
	}
	err = silofs_repo_stat_pack(env->base.repo, &caddr, &sz);
	if (err) {
		return err;
	}
	err = check_par_index_size(sz);
	if (err) {
		return err;
	}
	return 0;
}
