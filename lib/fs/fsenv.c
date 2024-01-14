/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2024 Shachar Sharon
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
#include <silofs/fs-private.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_lsegid *lsegid_of(const struct silofs_ulink *ulink)
{
	return &ulink->uaddr.laddr.lsegid;
}

static const struct silofs_lsegid *
sbi_lsegid(const struct silofs_sb_info *sbi)
{
	return lsegid_of(&sbi->sb_ui.u_ulink);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fsenv_bind_sb_lsegid(struct silofs_fsenv *fsenv,
                                 const struct silofs_lsegid *lsegid_new)
{
	if (lsegid_new) {
		lsegid_assign(&fsenv->fse_sb_lsegid, lsegid_new);
	} else {
		lsegid_reset(&fsenv->fse_sb_lsegid);
	}
}

static void fsenv_bind_sbi(struct silofs_fsenv *fsenv,
                           struct silofs_sb_info *sbi_new)
{
	struct silofs_sb_info *sbi_cur = fsenv->fse_sbi;

	if (sbi_cur != NULL) {
		silofs_sbi_decref(sbi_cur);
	}
	if (sbi_new != NULL) {
		silofs_sbi_incref(sbi_new);
	}
	fsenv->fse_sbi = sbi_new;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fsenv_update_owner(struct silofs_fsenv *fsenv)
{
	const struct silofs_fs_args *fs_args = fsenv->fse.fs_args;

	fsenv->fse_owner.uid = fs_args->uid;
	fsenv->fse_owner.gid = fs_args->gid;
	fsenv->fse_owner.umask = fs_args->umask;
}

static void fsenv_update_mntflags(struct silofs_fsenv *fsenv)
{
	const struct silofs_fs_args *fs_args = fsenv->fse.fs_args;
	unsigned long ms_flag_with = 0;
	unsigned long ms_flag_dont = 0;

	if (fs_args->lazytime) {
		ms_flag_with |= MS_LAZYTIME;
	} else {
		ms_flag_dont |= MS_LAZYTIME;
	}
	if (fs_args->noexec) {
		ms_flag_with |= MS_NOEXEC;
	} else {
		ms_flag_dont |= MS_NOEXEC;
	}
	if (fs_args->nosuid) {
		ms_flag_with |= MS_NOSUID;
	} else {
		ms_flag_dont |= MS_NOSUID;
	}
	if (fs_args->nodev) {
		ms_flag_with |= MS_NODEV;
	} else {
		ms_flag_dont |= MS_NODEV;
	}
	if (fs_args->rdonly) {
		ms_flag_with |= MS_RDONLY;
	} else {
		ms_flag_dont |= MS_RDONLY;
	}
	fsenv->fse_ms_flags |= ms_flag_with;
	fsenv->fse_ms_flags &= ~ms_flag_dont;
}

static void fsenv_update_ctlflags(struct silofs_fsenv *fsenv)
{
	const struct silofs_fs_args *fs_args = fsenv->fse.fs_args;

	if (fs_args->allowother) {
		fsenv->fse_ctl_flags |= SILOFS_ENVF_ALLOWOTHER;
	}
	if (fs_args->allowadmin) {
		fsenv->fse_ctl_flags |= SILOFS_ENVF_ALLOWADMIN;
	}
	if (fs_args->withfuse) {
		fsenv->fse_ctl_flags |= SILOFS_ENVF_NLOOKUP;
	}
	if (fs_args->asyncwr) {
		fsenv->fse_ctl_flags |= SILOFS_ENVF_ASYNCWR;
	}
}

static void fsenv_update_by_fs_args(struct silofs_fsenv *fsenv)
{
	fsenv_update_owner(fsenv);
	fsenv_update_mntflags(fsenv);
	fsenv_update_ctlflags(fsenv);
}

static size_t fsenv_calc_iopen_limit(const struct silofs_fsenv *fsenv)
{
	struct silofs_alloc_stat st;
	const size_t align = 128;
	size_t lim;

	silofs_memstat(fsenv->fse.alloc, &st);
	lim = (st.nbytes_max / (2 * SILOFS_LBK_SIZE));
	return div_round_up(lim, align) * align;
}

static void fsenv_init_commons(struct silofs_fsenv *fsenv,
                               const struct silofs_fsenv_base *fse_base)
{
	memcpy(&fsenv->fse, fse_base, sizeof(fsenv->fse));
	lsegid_reset(&fsenv->fse_sb_lsegid);
	fsenv->fse_init_time = silofs_time_now_monotonic();
	fsenv->fse_commit_id = 0;
	fsenv->fse_iconv = (iconv_t)(-1);
	fsenv->fse_sbi = NULL;
	fsenv->fse_ctl_flags = 0;
	fsenv->fse_ms_flags = 0;

	fsenv->fse_op_stat.op_iopen_max = 0;
	fsenv->fse_op_stat.op_iopen = 0;
	fsenv->fse_op_stat.op_time = silofs_time_now();
	fsenv->fse_op_stat.op_count = 0;
	fsenv->fse_op_stat.op_iopen_max = fsenv_calc_iopen_limit(fsenv);
}

static void fsenv_fini_commons(struct silofs_fsenv *fsenv)
{
	memset(&fsenv->fse, 0, sizeof(fsenv->fse));
	lsegid_reset(&fsenv->fse_sb_lsegid);
	fsenv->fse_iconv = (iconv_t)(-1);
	fsenv->fse_sbi = NULL;
}

static int fsenv_init_locks(struct silofs_fsenv *fsenv)
{
	int err;

	err = silofs_rwlock_init(&fsenv->fse_rwlock);
	if (err) {
		return err;
	}
	err = silofs_mutex_init(&fsenv->fse_mutex);
	if (err) {
		silofs_rwlock_fini(&fsenv->fse_rwlock);
		return err;
	}
	return 0;
}

static void fsenv_fini_locks(struct silofs_fsenv *fsenv)
{
	silofs_mutex_fini(&fsenv->fse_mutex);
	silofs_rwlock_fini(&fsenv->fse_rwlock);
}

static int fsenv_init_crypto(struct silofs_fsenv *fsenv)
{
	int err;

	err = silofs_mdigest_init(&fsenv->fse_mdigest);
	if (err) {
		goto out_err;
	}
	err = silofs_cipher_init(&fsenv->fse_enc_cipher);
	if (err) {
		goto out_err1;
	}
	err = silofs_cipher_init(&fsenv->fse_dec_cipher);
	if (err) {
		goto out_err2;
	}
	return 0;

out_err2:
	silofs_cipher_init(&fsenv->fse_enc_cipher);
out_err1:
	silofs_mdigest_fini(&fsenv->fse_mdigest);
out_err:
	return err;
}

static void fsenv_fini_crypto(struct silofs_fsenv *fsenv)
{
	silofs_cipher_fini(&fsenv->fse_dec_cipher);
	silofs_cipher_fini(&fsenv->fse_enc_cipher);
	silofs_mdigest_fini(&fsenv->fse_mdigest);
}

static int fsenv_init_iconv(struct silofs_fsenv *fsenv)
{
	/* Using UTF32LE to avoid BOM (byte-order-mark) character */
	fsenv->fse_iconv = iconv_open("UTF32LE", "UTF8");
	if (fsenv->fse_iconv == (iconv_t)(-1)) {
		return errno ? -errno : -SILOFS_EOPNOTSUPP;
	}
	return 0;
}

static void fsenv_fini_iconv(struct silofs_fsenv *fsenv)
{
	if (fsenv->fse_iconv != (iconv_t)(-1)) {
		iconv_close(fsenv->fse_iconv);
		fsenv->fse_iconv = (iconv_t)(-1);
	}
}

int silofs_fsenv_init(struct silofs_fsenv *fsenv,
                      const struct silofs_fsenv_base *fse_base)
{
	int err;

	fsenv_init_commons(fsenv, fse_base);
	fsenv_update_by_fs_args(fsenv);

	err = fsenv_init_locks(fsenv);
	if (err) {
		return err;
	}
	err = fsenv_init_crypto(fsenv);
	if (err) {
		goto out_err;
	}
	err = fsenv_init_iconv(fsenv);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	silofs_fsenv_fini(fsenv);
	return err;
}

void silofs_fsenv_fini(struct silofs_fsenv *fsenv)
{
	fsenv_bind_sbi(fsenv, NULL);
	fsenv_fini_iconv(fsenv);
	fsenv_fini_crypto(fsenv);
	fsenv_fini_locks(fsenv);
	fsenv_fini_commons(fsenv);
}

void silofs_fsenv_lock(struct silofs_fsenv *fsenv)
{
	silofs_mutex_lock(&fsenv->fse_mutex);
}

void silofs_fsenv_unlock(struct silofs_fsenv *fsenv)
{
	silofs_mutex_unlock(&fsenv->fse_mutex);
}

void silofs_fsenv_rwlock(struct silofs_fsenv *fsenv, bool ex)
{
	if (ex) {
		silofs_rwlock_wrlock(&fsenv->fse_rwlock);
	} else {
		silofs_rwlock_rdlock(&fsenv->fse_rwlock);
	}
}

void silofs_fsenv_rwunlock(struct silofs_fsenv *fsenv)
{
	silofs_rwlock_unlock(&fsenv->fse_rwlock);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void make_super_lsegid(struct silofs_lsegid *out_lsegid)
{
	struct silofs_lvid lvid;

	silofs_lvid_generate(&lvid);
	silofs_lsegid_setup(out_lsegid, &lvid, 0,
	                    SILOFS_LTYPE_SUPER, SILOFS_HEIGHT_SUPER);
}

static void make_super_uaddr(const struct silofs_lsegid *lsegid,
                             struct silofs_uaddr *out_uaddr)
{
	silofs_assert_eq(lsegid->height, SILOFS_HEIGHT_SUPER);
	uaddr_setup(out_uaddr, lsegid, 0, SILOFS_LTYPE_SUPER, 0);
}

static void ulink_init(struct silofs_ulink *ulink,
                       const struct silofs_uaddr *uaddr,
                       const struct silofs_iv *iv)
{
	silofs_uaddr_assign(&ulink->uaddr, uaddr);
	silofs_iv_assign(&ulink->riv, iv);
}

static void fsenv_make_super_ulink(const struct silofs_fsenv *fsenv,
                                   struct silofs_ulink *out_ulink)
{
	struct silofs_lsegid lsegid;
	struct silofs_uaddr uaddr;

	make_super_lsegid(&lsegid);
	make_super_uaddr(&lsegid, &uaddr);
	ulink_init(out_ulink, &uaddr, &fsenv->fse.main_ivkey->iv);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_fsenv_bind_child(struct silofs_fsenv *fsenv,
                             const struct silofs_ulink *sb_ulink)
{
	ulink_assign(&fsenv->fse_sb_ulink, sb_ulink);
}

static int fsenv_spawn_super_at(struct silofs_fsenv *fsenv,
                                const struct silofs_ulink *ulink,
                                struct silofs_sb_info **out_sbi)
{
	int err;

	err = silofs_spawn_super(fsenv, ulink, out_sbi);
	if (err) {
		return err;
	}
	silofs_sbi_setup_spawned(*out_sbi);
	return 0;
}

static int fsenv_spawn_super_of(struct silofs_fsenv *fsenv,
                                struct silofs_sb_info **out_sbi)
{
	struct silofs_ulink ulink = { .uaddr.voff = -1 };

	fsenv_make_super_ulink(fsenv, &ulink);
	return fsenv_spawn_super_at(fsenv, &ulink, out_sbi);
}

static int fsenv_spawn_super(struct silofs_fsenv *fsenv, size_t capacity,
                             struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = fsenv_spawn_super_of(fsenv, &sbi);
	if (err) {
		return err;
	}
	silofs_sbi_setup_btime(sbi);
	silofs_sti_set_capacity(&sbi->sb_sti, capacity);
	*out_sbi = sbi;
	return 0;
}

static void sbi_account_super_of(struct silofs_sb_info *sbi)
{
	struct silofs_stats_info *sti = &sbi->sb_sti;

	silofs_sti_update_lsegs(sti, SILOFS_LTYPE_SUPER, 1);
	silofs_sti_update_bks(sti, SILOFS_LTYPE_SUPER, 1);
	silofs_sti_update_objs(sti, SILOFS_LTYPE_SUPER, 1);
}

int silofs_fsenv_format_super(struct silofs_fsenv *fsenv, size_t capacity)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = fsenv_spawn_super(fsenv, capacity, &sbi);
	if (err) {
		return err;
	}
	sbi_account_super_of(sbi);
	fsenv_bind_sbi(fsenv, sbi);
	return 0;
}

int silofs_fsenv_reload_super(struct silofs_fsenv *fsenv)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = silofs_stage_super(fsenv, &fsenv->fse_sb_ulink, &sbi);
	if (err) {
		return err;
	}
	fsenv_bind_sbi(fsenv, sbi);
	return 0;
}

int silofs_fsenv_reload_sb_lseg(struct silofs_fsenv *fsenv)
{
	const struct silofs_lsegid *lsegid = lsegid_of(&fsenv->fse_sb_ulink);
	int err;

	err = silofs_stage_lseg(fsenv, lsegid);
	if (err) {
		log_warn("unable to stage sb-lseg: err=%d", err);
		return err;
	}
	fsenv_bind_sb_lsegid(fsenv, lsegid);
	return 0;
}

static void sbi_make_clone(struct silofs_sb_info *sbi_new,
                           const struct silofs_sb_info *sbi_cur)
{
	struct silofs_stats_info *sti_new = &sbi_new->sb_sti;
	const struct silofs_stats_info *sti_cur = &sbi_cur->sb_sti;

	silofs_sbi_clone_from(sbi_new, sbi_cur);
	silofs_sti_make_clone(sti_new, sti_cur);
	silofs_sti_renew_stats(sti_new);
	silofs_sbi_setup_ctime(sbi_new);

	sbi_account_super_of(sbi_new);
}

void silofs_fsenv_shut(struct silofs_fsenv *fsenv)
{
	fsenv_bind_sbi(fsenv, NULL);
	fsenv_bind_sb_lsegid(fsenv, NULL);
}

static void fsenv_rebind_root_sb(struct silofs_fsenv *fsenv,
                                 struct silofs_sb_info *sbi)
{
	silofs_fsenv_bind_child(fsenv, sbi_ulink(sbi));
	fsenv_bind_sb_lsegid(fsenv, sbi_lsegid(sbi));
	fsenv_bind_sbi(fsenv, sbi);
}

static int fsenv_clone_rebind_super(struct silofs_fsenv *fsenv,
                                    const struct silofs_sb_info *sbi_cur,
                                    struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = fsenv_spawn_super(fsenv, 0, &sbi);
	if (err) {
		return err;
	}
	sbi_make_clone(sbi, sbi_cur);
	fsenv_rebind_root_sb(fsenv, sbi);

	*out_sbi = sbi;
	return 0;
}

static void sbi_mark_fossil(struct silofs_sb_info *sbi)
{
	silofs_sbi_add_flags(sbi, SILOFS_SUPERF_FOSSIL);
}

static void sbi_export_bootrec(const struct silofs_sb_info *sbi,
                               struct silofs_bootrec *brec)
{
	silofs_bootrec_init(brec);
	silofs_bootrec_set_sb_ulink(brec, sbi_ulink(sbi));
}

static void fsenv_pre_forkfs(struct silofs_fsenv *fsenv)
{
	silofs_cache_drop_uamap(fsenv->fse.cache);
}

int silofs_fsenv_forkfs(struct silofs_fsenv *fsenv,
                        struct silofs_bootrecs *out_brecs)
{
	struct silofs_sb_info *sbi_alt = NULL;
	struct silofs_sb_info *sbi_new = NULL;
	struct silofs_sb_info *sbi_cur = fsenv->fse_sbi;
	int err;

	fsenv_pre_forkfs(fsenv);
	err = fsenv_clone_rebind_super(fsenv, sbi_cur, &sbi_alt);
	if (err) {
		return err;
	}
	sbi_export_bootrec(sbi_alt, &out_brecs->brec[1]);

	fsenv_pre_forkfs(fsenv);
	err = fsenv_clone_rebind_super(fsenv, sbi_cur, &sbi_new);
	if (err) {
		return err;
	}
	sbi_export_bootrec(sbi_new, &out_brecs->brec[0]);

	sbi_mark_fossil(sbi_cur);
	return 0;
}

void silofs_fsenv_relax_caches(const struct silofs_fsenv *fsenv, int flags)
{
	silofs_cache_relax(fsenv->fse.cache, flags);
	if (flags & SILOFS_F_IDLE) {
		silofs_repo_relax(fsenv->fse.repo);
	}
}

void silofs_fsenv_uptime(const struct silofs_fsenv *fsenv, time_t *out_uptime)
{
	const time_t now = silofs_time_now_monotonic();

	*out_uptime = now - fsenv->fse_init_time;
}

void silofs_fsenv_allocstat(const struct silofs_fsenv *fsenv,
                            struct silofs_alloc_stat *out_alst)
{
	silofs_memstat(fsenv->fse.alloc, out_alst);
}
