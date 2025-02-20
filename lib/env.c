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
#include <silofs/configs.h>
#include <silofs/fs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>

static const struct silofs_lsid *lsid_of(const struct silofs_ulink *ulink)
{
	return &ulink->uaddr.laddr.lsid;
}

static bool caddr_isuber(const struct silofs_caddr *caddr)
{
	return (caddr->ctype == SILOFS_CTYPE_UBER) &&
	       (caddr->size == SILOFS_UBER_SIZE);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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

static void env_update_uber_sb_ulink(struct silofs_env *env)
{
	struct silofs_uber *uber = &env->uber;
	struct silofs_sb_info *sbi = env->sbi;

	if (sbi != NULL) {
		silofs_uber_set_sb_ulink(uber, sbi_ulink(sbi));
	} else {
		silofs_uber_reset_sb_ulink(uber);
	}
	silofs_uber_gen_uuid(uber);
}

static void env_rebind_sbi(struct silofs_env *env, struct silofs_sb_info *sbi)
{
	env_bind_sbi(env, sbi);
	env_update_uber_sb_ulink(env);
}

static void env_update_owner(struct silofs_env *env)
{
	const struct silofs_args *args = env->base.args;

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
	const struct silofs_xref *xref = &env->base.args->boot.xref;
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
	case SILOFS_CTYPE_UBER:
		silofs_env_set_uber_caddr(env, &caddr);
		break;
	case SILOFS_CTYPE_PACKIDX:
		silofs_env_set_pack_caddr(env, &caddr);
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
	return div_round_up(lim, align) * align;
}

static void env_init_opstat(struct silofs_env *env)
{
	env->opstat.op_iopen_max = 0;
	env->opstat.op_iopen = 0;
	env->opstat.op_time = silofs_time_now();
	env->opstat.op_count = 0;
	env->opstat.op_iopen_max = env_calc_iopen_limit(env);
}

static void
env_init_commons(struct silofs_env *env, const struct silofs_env_base *base)
{
	memcpy(&env->base, base, sizeof(env->base));
	silofs_ivkey_init(&env->uber_ivkey);
	silofs_caddr_reset(&env->uber_caddr);
	silofs_caddr_reset(&env->uber_base_caddr);
	silofs_caddr_reset(&env->uber_fork_caddr);
	silofs_caddr_reset(&env->pack_caddr);
	silofs_uber_init(&env->uber);
	env->init_time = silofs_time_now_monotonic();
	env->iconv_set = false;
	env->sbi = NULL;
	env->ms_flags = 0;
}

static void env_fini_commons(struct silofs_env *env)
{
	memset(&env->base, 0, sizeof(env->base));
	silofs_ivkey_fini(&env->uber_ivkey);
	silofs_caddr_reset(&env->uber_caddr);
	silofs_caddr_reset(&env->uber_base_caddr);
	silofs_caddr_reset(&env->uber_fork_caddr);
	silofs_uber_fini(&env->uber);
	env->sbi = NULL;
	env->ms_flags = 0;
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
	silofs_cipher_fini(&env->uber_cipher);
	silofs_mdigest_fini(&env->mdigest);
}

static int env_init_crypto(struct silofs_env *env)
{
	int err;

	err = silofs_mdigest_init(&env->mdigest);
	if (err) {
		return err;
	}
	err = silofs_cipher_init(&env->uber_cipher);
	if (err) {
		goto out_err;
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

int silofs_env_setup(struct silofs_env *env, const struct silofs_password *pw)
{
	const struct silofs_mdigest *md = &env->mdigest;
	int ret = 0;

	if ((pw != NULL) && (pw->passlen > 0)) {
		ret = silofs_derive_default_ivkey(md, pw, &env->uber_ivkey);
	}
	return ret;
}

bool silofs_env_hasflag(const struct silofs_env *env, enum silofs_flags f)
{
	return (env->base.args->flags & f) == f;
}

int silofs_env_uber_caddr(const struct silofs_env *env,
                          struct silofs_caddr *out_caddr)
{
	caddr_assign(out_caddr, &env->uber_caddr);
	return caddr_isuber(&env->uber_caddr) ? 0 : -SILOFS_ENOENT;
}

int silofs_env_set_uber_caddr(struct silofs_env *env,
                              const struct silofs_caddr *caddr)
{
	if (!caddr_isuber(caddr)) {
		return -SILOFS_EINVAL;
	}
	caddr_assign(&env->uber_caddr, caddr);
	return 0;
}

int silofs_env_uber_caddrs(const struct silofs_env *env,
                           struct silofs_uber_caddrs *out_caddrs)
{
	silofs_caddr_assign(&out_caddrs->base, &env->uber_base_caddr);
	silofs_caddr_assign(&out_caddrs->curr, &env->uber_caddr);
	silofs_caddr_assign(&out_caddrs->fork, &env->uber_fork_caddr);
	return caddr_isuber(&env->uber_caddr) ? 0 : -SILOFS_ENOENT;
}

int silofs_env_pack_caddr(const struct silofs_env *env,
                          struct silofs_caddr *out_caddr)
{
	const struct silofs_caddr *caddr = &env->pack_caddr;

	caddr_assign(out_caddr, caddr);
	return (caddr->ctype == SILOFS_CTYPE_PACKIDX) ? 0 : -SILOFS_ENOENT;
}

int silofs_env_set_pack_caddr(struct silofs_env *env,
                              const struct silofs_caddr *caddr)
{
	if (caddr->ctype != SILOFS_CTYPE_PACKIDX) {
		return -SILOFS_EINVAL;
	}
	caddr_assign(&env->pack_caddr, caddr);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_env_format_bstore(struct silofs_env *env)
{
	return silofs_bstore_format(env->base.bstore);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_env_sense_uber(struct silofs_env *env)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };
	int err;

	err = silofs_env_uber_caddr(env, &caddr);
	if (err) {
		return err;
	}
	err = silofs_stat_uber(env, &caddr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_env_reload_uber(struct silofs_env *env)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };
	int err;

	err = silofs_env_uber_caddr(env, &caddr);
	if (err) {
		return err;
	}
	err = silofs_reload_uber(env, &caddr, &env->uber);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_env_unlink_uber(struct silofs_env *env)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };
	int err;

	err = silofs_env_uber_caddr(env, &caddr);
	if (err) {
		return err;
	}
	err = silofs_unlink_uber(env, &caddr);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void make_super_lsid(struct silofs_lsid *out_lsid)
{
	struct silofs_volid volid;

	silofs_volid_generate(&volid);
	silofs_lsid_setup(out_lsid, &volid, 0, SILOFS_LTYPE_SUPER,
	                  SILOFS_HEIGHT_SUPER, SILOFS_LTYPE_SUPER);
}

static void make_super_uaddr(const struct silofs_lsid *lsid,
                             struct silofs_uaddr *out_uaddr)
{
	silofs_assert_eq(lsid->height, SILOFS_HEIGHT_SUPER);
	silofs_assert_eq(lsid->ltype, SILOFS_LTYPE_SUPER);

	uaddr_setup(out_uaddr, lsid, 0, 0);
}

static void
ulink_init(struct silofs_ulink *ulink, const struct silofs_uaddr *uaddr,
           const struct silofs_iv *iv)
{
	silofs_uaddr_assign(&ulink->uaddr, uaddr);
	silofs_iv_assign(&ulink->riv, iv);
}

static void env_make_super_ulink(const struct silofs_env *env,
                                 struct silofs_ulink *out_ulink)
{
	struct silofs_lsid lsid = { .lsize = 0 };
	struct silofs_uaddr uaddr = { .voff = -1 };
	const struct silofs_iv *iv = &env->uber.main_ivkey.iv;

	make_super_lsid(&lsid);
	make_super_uaddr(&lsid, &uaddr);
	ulink_init(out_ulink, &uaddr, iv);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_env_drop_caches(struct silofs_env *env)
{
	silofs_lcache_drop(env->base.lcache);
	silofs_pcache_drop(env->base.pcache);
	silofs_repo_drop_some(env->base.repo);
}

static int
env_spawn_super_at(struct silofs_env *env, const struct silofs_ulink *ulink,
                   struct silofs_sb_info **out_sbi)
{
	int err;

	err = silofs_spawn_super(env, ulink, out_sbi);
	if (err) {
		return err;
	}
	silofs_sbi_setup_spawned(*out_sbi);
	return 0;
}

static int
env_spawn_super_of(struct silofs_env *env, struct silofs_sb_info **out_sbi)
{
	struct silofs_ulink ulink = { .uaddr.voff = -1 };

	env_make_super_ulink(env, &ulink);
	return env_spawn_super_at(env, &ulink, out_sbi);
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
	silofs_sbi_set_fs_birth(sbi);
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

static const struct silofs_ulink *env_sb_ulink(const struct silofs_env *env)
{
	return &env->uber.sb_ulink;
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
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = silofs_stage_super(env, env_sb_ulink(env), &sbi);
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

int silofs_env_reload_sb_lseg(struct silofs_env *env)
{
	const struct silofs_ulink *sb_ulink = env_sb_ulink(env);
	const struct silofs_lsid *lsid = lsid_of(sb_ulink);
	int err;

	err = silofs_stage_lseg(env, lsid);
	if (err) {
		log_warn("unable to stage sb-lseg: err=%d", err);
		return err;
	}
	return 0;
}

static void sbi_make_clone(struct silofs_sb_info *sbi_new,
                           const struct silofs_sb_info *sbi_cur)
{
	silofs_sbi_make_shadow_of(sbi_new, sbi_cur);
	silofs_sbi_set_lv_birth(sbi_new);
	silofs_sbst_rebuild_from(sbi_new, sbi_cur);
	silofs_sbst_account_super(sbi_new);
	silofs_sbst_force_into_sb(sbi_new);
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
	return silofs_bstore_close(env->base.bstore);
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
	const time_t now = silofs_time_now_monotonic();

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

static int
env_reinit_ciphers_by(struct silofs_env *env, const struct silofs_uber *uber)
{
	const int algo = uber->cipher_algo;
	const int mode = uber->cipher_mode;

	return env_reinit_ciphers(env, algo, mode);
}

static int
env_update_uber(struct silofs_env *env, const struct silofs_uber *uber)
{
	struct silofs_caddr caddr;
	int err;

	err = silofs_calc_uber_caddr(env, uber, &caddr);
	if (err) {
		return err;
	}
	silofs_env_set_uber_caddr(env, &caddr);
	silofs_uber_assign(&env->uber, uber);
	return 0;
}

static void env_update_pvsegr(struct silofs_env *env)
{
	struct silofs_pvsegr pvsegr;

	silofs_bstore_curr_pvsegr(env->base.bstore, &pvsegr);
	silofs_uber_set_pvsegr(&env->uber, &pvsegr);
}

int silofs_env_update_by(struct silofs_env *env,
                         const struct silofs_uber *uber)
{
	int err;

	err = env_reinit_ciphers_by(env, uber);
	if (err) {
		return err;
	}
	err = env_update_uber(env, uber);
	if (err) {
		return err;
	}
	env_update_pvsegr(env);
	return 0;
}

int silofs_env_format_uber(struct silofs_env *env)
{
	struct silofs_uber uber = { .flags = SILOFS_UBERF_NONE };
	int err;

	silofs_uber_init(&uber);
	silofs_uber_gen_uuid(&uber);
	err = silofs_uber_gen_ivkey(&uber, &env->mdigest);
	if (err) {
		return err;
	}
	err = silofs_env_update_by(env, &uber);
	if (err) {
		return err;
	}
	return 0;
}

static void
env_pre_commit_uber(const struct silofs_env *env, struct silofs_uber *uber)
{
	silofs_uber_assign(uber, &env->uber);
	silofs_uber_set_sb_ulink(uber, sbi_ulink(env->sbi));
}

int silofs_env_commit_uber(struct silofs_env *env)
{
	struct silofs_uber uber = { .flags = SILOFS_UBERF_NONE };
	struct silofs_caddr caddr;
	int err;

	env_pre_commit_uber(env, &uber);
	err = silofs_save_uber(env, &uber, &caddr);
	if (err) {
		return err;
	}
	err = silofs_env_update_by(env, &uber);
	if (err) {
		return err;
	}
	return 0;
}

static int
env_resave_uber(struct silofs_env *env, struct silofs_caddr *out_caddr)
{
	int err;

	err = silofs_save_uber(env, &env->uber, out_caddr);
	if (err) {
		return err;
	}
	silofs_env_set_uber_caddr(env, out_caddr);
	return 0;
}

static void env_drop_uamap(struct silofs_env *env)
{
	silofs_lcache_drop_uamap(env->base.lcache);
}

static int env_clone_rebind_super(struct silofs_env *env,
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
	sbi_make_clone(sbi, sbi_cur);
	env_rebind_sbi(env, sbi);

	*out_sbi = sbi;
	return 0;
}

static void sbi_mark_fossil(struct silofs_sb_info *sbi)
{
	silofs_sbi_add_flags(sbi, SILOFS_SUPERF_FOSSIL);
}

static int env_do_forkfs(struct silofs_env *env)
{
	struct silofs_sb_info *sbi_alt = NULL;
	struct silofs_sb_info *sbi_new = NULL;
	struct silofs_sb_info *sbi_cur = env->sbi;
	int err;

	err = silofs_env_uber_caddr(env, &env->uber_base_caddr);
	if (err) {
		return err;
	}

	err = env_clone_rebind_super(env, sbi_cur, &sbi_alt);
	if (err) {
		return err;
	}
	err = env_resave_uber(env, &env->uber_fork_caddr);
	if (err) {
		return err;
	}

	err = env_clone_rebind_super(env, sbi_cur, &sbi_new);
	if (err) {
		return err;
	}
	err = env_resave_uber(env, &env->uber_caddr);
	if (err) {
		return err;
	}

	sbi_mark_fossil(sbi_cur);
	return 0;
}

int silofs_env_forkfs(struct silofs_env *env)
{
	struct silofs_sb_info *sbi = env->sbi;
	int err;

	sbi_incref(sbi);
	err = env_do_forkfs(env);
	sbi_decref(sbi);
	return err;
}

static int check_par_index_size(ssize_t sz)
{
	if ((sz < SILOFS_PAR_INDEX_SIZE_MIN) ||
	    (sz > SILOFS_PAR_INDEX_SIZE_MAX)) {
		return -SILOFS_EBADPACK;
	}
	return 0;
}

int silofs_env_sense_pack(struct silofs_env *env)
{
	struct silofs_caddr caddr = { .ctype = SILOFS_CTYPE_NONE };
	ssize_t sz = -1;
	int err;

	err = silofs_env_pack_caddr(env, &caddr);
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
