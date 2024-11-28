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

static const struct silofs_lsid *lsid_of(const struct silofs_ulink *ulink)
{
	return &ulink->uaddr.laddr.lsid;
}

static const struct silofs_lsid *sbi_lsid(const struct silofs_sb_info *sbi)
{
	return lsid_of(&sbi->sb_uni.un_ulink);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fsenv_bind_sb_lsid(struct silofs_fsenv *fsenv,
                               const struct silofs_lsid *lsid_new)
{
	if (lsid_new) {
		lsid_assign(&fsenv->fse_sb_lsid, lsid_new);
	} else {
		lsid_reset(&fsenv->fse_sb_lsid);
	}
}

static void
fsenv_bind_sbi(struct silofs_fsenv *fsenv, struct silofs_sb_info *sbi_new)
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
	const struct silofs_fs_args *fs_args = &fsenv->fse_args;

	fsenv->fse_owner.uid = fs_args->uid;
	fsenv->fse_owner.gid = fs_args->gid;
	fsenv->fse_owner.umask = fs_args->umask;
}

static void fsenv_update_mntflags(struct silofs_fsenv *fsenv)
{
	const struct silofs_fs_args *fs_args = &fsenv->fse_args;
	unsigned long ms_flag_with = 0;
	unsigned long ms_flag_dont = 0;

	if (fs_args->cflags.lazytime) {
		ms_flag_with |= MS_LAZYTIME;
	} else {
		ms_flag_dont |= MS_LAZYTIME;
	}
	if (fs_args->cflags.noexec) {
		ms_flag_with |= MS_NOEXEC;
	} else {
		ms_flag_dont |= MS_NOEXEC;
	}
	if (fs_args->cflags.nosuid) {
		ms_flag_with |= MS_NOSUID;
	} else {
		ms_flag_dont |= MS_NOSUID;
	}
	if (fs_args->cflags.nodev) {
		ms_flag_with |= MS_NODEV;
	} else {
		ms_flag_dont |= MS_NODEV;
	}
	if (fs_args->cflags.rdonly) {
		ms_flag_with |= MS_RDONLY;
	} else {
		ms_flag_dont |= MS_RDONLY;
	}
	fsenv->fse_ms_flags |= ms_flag_with;
	fsenv->fse_ms_flags &= ~ms_flag_dont;
}

static void fsenv_update_ctlflags(struct silofs_fsenv *fsenv)
{
	const struct silofs_fs_args *fs_args = &fsenv->fse_args;

	if (fs_args->cflags.with_fuse) {
		fsenv->fse_ctl_flags |= SILOFS_ENVF_WITHFUSE;
		fsenv->fse_ctl_flags |= SILOFS_ENVF_NLOOKUP;
	}
	if (fs_args->cflags.writeback_cache) {
		fsenv->fse_ctl_flags |= SILOFS_ENVF_WRITEBACK;
	}
	if (fs_args->cflags.may_splice) {
		fsenv->fse_ctl_flags |= SILOFS_ENVF_MAYSPLICE;
	}
	if (fs_args->cflags.allow_other) {
		fsenv->fse_ctl_flags |= SILOFS_ENVF_ALLOWOTHER;
	}
	if (fs_args->cflags.allow_xattr_acl) {
		fsenv->fse_ctl_flags |= SILOFS_ENVF_ALLOWXACL;
	}
	if (fs_args->cflags.allow_admin) {
		fsenv->fse_ctl_flags |= SILOFS_ENVF_ALLOWADMIN;
	}
	if (fs_args->cflags.asyncwr) {
		fsenv->fse_ctl_flags |= SILOFS_ENVF_ASYNCWR;
	}
}

static int fsenv_update_base_caddr(struct silofs_fsenv *fsenv)
{
	const struct silofs_fs_args *fs_args = &fsenv->fse_args;
	const struct silofs_caddr *caddr = &fs_args->bref.caddr;
	int ret = 0;

	switch (caddr->ctype) {
	case SILOFS_CTYPE_BOOTREC:
		silofs_fsenv_set_boot_caddr(fsenv, caddr);
		break;
	case SILOFS_CTYPE_PACKIDX:
		silofs_fsenv_set_pack_caddr(fsenv, caddr);
		break;
	case SILOFS_CTYPE_NONE:
		break;
	case SILOFS_CTYPE_ENCSEG:
	default:
		log_err("bad fs-args boot-ref: ctype=%d", caddr->ctype);
		ret = -SILOFS_EINVAL;
		break;
	}
	return ret;
}

static int fsenv_update_by_fs_args(struct silofs_fsenv *fsenv)
{

	fsenv_update_owner(fsenv);
	fsenv_update_mntflags(fsenv);
	fsenv_update_ctlflags(fsenv);
	return fsenv_update_base_caddr(fsenv);
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
                               const struct silofs_fs_args *args,
                               const struct silofs_fsenv_base *base)
{
	memcpy(&fsenv->fse_args, args, sizeof(fsenv->fse_args));
	memcpy(&fsenv->fse, base, sizeof(fsenv->fse));
	silofs_caddr_reset(&fsenv->fse_pack_caddr);
	silofs_lsid_reset(&fsenv->fse_sb_lsid);
	fsenv->fse_init_time = silofs_time_now_monotonic();
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
	lsid_reset(&fsenv->fse_sb_lsid);
	fsenv->fse_iconv = (iconv_t)(-1);
	fsenv->fse_sbi = NULL;
}

static int fsenv_init_locks(struct silofs_fsenv *fsenv)
{
	int err;

	err = silofs_rwlock_init(&fsenv->fse_locks.rwlock);
	if (err) {
		return err;
	}
	err = silofs_mutex_init(&fsenv->fse_locks.mutex);
	if (err) {
		silofs_rwlock_fini(&fsenv->fse_locks.rwlock);
		return err;
	}
	return 0;
}

static void fsenv_fini_locks(struct silofs_fsenv *fsenv)
{
	silofs_mutex_fini(&fsenv->fse_locks.mutex);
	silofs_rwlock_fini(&fsenv->fse_locks.rwlock);
}

static int fsenv_init_boot(struct silofs_fsenv *fsenv)
{
	silofs_bootrec_init(&fsenv->fse_boot.brec);
	silofs_caddr_reset(&fsenv->fse_boot.caddr);
	silofs_ivkey_init(&fsenv->fse_boot.ivkey);
	return silofs_cipher_init(&fsenv->fse_boot.cipher);
}

static void fsenv_fini_boot(struct silofs_fsenv *fsenv)
{
	silofs_cipher_fini(&fsenv->fse_boot.cipher);
	silofs_bootrec_fini(&fsenv->fse_boot.brec);
	silofs_caddr_reset(&fsenv->fse_boot.caddr);
	silofs_ivkey_fini(&fsenv->fse_boot.ivkey);
}

static int fsenv_init_crypto(struct silofs_fsenv *fsenv)
{
	int err;

	err = silofs_mdigest_init(&fsenv->fse_mdigest);
	if (err) {
		return err;
	}
	err = silofs_cipher_init(&fsenv->fse_enc_cipher);
	if (err) {
		goto out_err;
	}
	err = silofs_cipher_init(&fsenv->fse_dec_cipher);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	silofs_cipher_fini(&fsenv->fse_dec_cipher);
	silofs_cipher_fini(&fsenv->fse_enc_cipher);
	silofs_mdigest_fini(&fsenv->fse_mdigest);
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
                      const struct silofs_fs_args *args,
                      const struct silofs_fsenv_base *base)
{
	int err;

	fsenv_init_commons(fsenv, args, base);

	err = fsenv_update_by_fs_args(fsenv);
	if (err) {
		return err;
	}
	err = fsenv_init_locks(fsenv);
	if (err) {
		return err;
	}
	err = fsenv_init_boot(fsenv);
	if (err) {
		goto out_err;
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
	fsenv_fini_boot(fsenv);
	fsenv_fini_locks(fsenv);
	fsenv_fini_commons(fsenv);
}

void silofs_fsenv_lock(struct silofs_fsenv *fsenv)
{
	silofs_mutex_lock(&fsenv->fse_locks.mutex);
}

void silofs_fsenv_unlock(struct silofs_fsenv *fsenv)
{
	silofs_mutex_unlock(&fsenv->fse_locks.mutex);
}

void silofs_fsenv_rwlock(struct silofs_fsenv *fsenv, bool ex)
{
	if (ex) {
		silofs_rwlock_wrlock(&fsenv->fse_locks.rwlock);
	} else {
		silofs_rwlock_rdlock(&fsenv->fse_locks.rwlock);
	}
}

void silofs_fsenv_rwunlock(struct silofs_fsenv *fsenv)
{
	silofs_rwlock_unlock(&fsenv->fse_locks.rwlock);
}

int silofs_fsenv_setup(struct silofs_fsenv *fsenv,
                       const struct silofs_password *pw)
{
	const struct silofs_mdigest *md = &fsenv->fse_mdigest;
	struct silofs_ivkey *ivkey = &fsenv->fse_boot.ivkey;
	int ret = 0;

	if ((pw != NULL) && (pw->passlen > 0)) {
		ret = silofs_derive_boot_ivkey(md, pw, ivkey);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void make_super_lsid(struct silofs_lsid *out_lsid)
{
	struct silofs_lvid lvid;

	silofs_lvid_generate(&lvid);
	silofs_lsid_setup(out_lsid, &lvid, 0, SILOFS_LTYPE_SUPER,
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

static void fsenv_make_super_ulink(const struct silofs_fsenv *fsenv,
                                   struct silofs_ulink *out_ulink)
{
	struct silofs_lsid lsid = { .lsize = 0 };
	struct silofs_uaddr uaddr = { .voff = -1 };
	const struct silofs_iv *iv = &fsenv->fse_boot.brec.main_ivkey.iv;

	make_super_lsid(&lsid);
	make_super_uaddr(&lsid, &uaddr);
	ulink_init(out_ulink, &uaddr, iv);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_fsenv_set_boot_caddr(struct silofs_fsenv *fsenv,
                                 const struct silofs_caddr *caddr)
{
	silofs_assert_eq(caddr->ctype, SILOFS_CTYPE_BOOTREC);

	caddr_assign(&fsenv->fse_boot.caddr, caddr);
}

void silofs_fsenv_set_pack_caddr(struct silofs_fsenv *fsenv,
                                 const struct silofs_caddr *caddr)
{
	silofs_assert_eq(caddr->ctype, SILOFS_CTYPE_PACKIDX);

	caddr_assign(&fsenv->fse_pack_caddr, caddr);
}

void silofs_fsenv_set_sb_ulink(struct silofs_fsenv *fsenv,
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
	silofs_sbi_set_fs_birth(sbi);
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
	const struct silofs_lsid *lsid = lsid_of(&fsenv->fse_sb_ulink);
	int err;

	err = silofs_stage_lseg(fsenv, lsid);
	if (err) {
		log_warn("unable to stage sb-lseg: err=%d", err);
		return err;
	}
	fsenv_bind_sb_lsid(fsenv, lsid);
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
	silofs_sbi_set_lv_birth(sbi_new);

	sbi_account_super_of(sbi_new);
}

static int fsenv_shut_sb(struct silofs_fsenv *fsenv)
{
	int err;

	err = silofs_sbi_shut(fsenv->fse_sbi);
	if (err) {
		return err;
	}
	fsenv_bind_sbi(fsenv, NULL);
	fsenv_bind_sb_lsid(fsenv, NULL);
	return 0;
}

static int fsenv_shut_pstore(struct silofs_fsenv *fsenv)
{
	return silofs_pstore_close(fsenv->fse.pstore);
}

int silofs_fsenv_shut(struct silofs_fsenv *fsenv)
{
	int err;

	err = fsenv_shut_sb(fsenv);
	if (err) {
		return err;
	}
	err = fsenv_shut_pstore(fsenv);
	if (err) {
		return err;
	}
	return 0;
}

static void
fsenv_rebind_root_sb(struct silofs_fsenv *fsenv, struct silofs_sb_info *sbi)
{
	silofs_fsenv_set_sb_ulink(fsenv, sbi_ulink(sbi));
	fsenv_bind_sb_lsid(fsenv, sbi_lsid(sbi));
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

static void fsenv_make_bootrec_of(const struct silofs_fsenv *fsenv,
                                  const struct silofs_sb_info *sbi,
                                  struct silofs_bootrec *out_brec)
{
	silofs_bootrec_assign(out_brec, &fsenv->fse_boot.brec);
	silofs_bootrec_gen_uuid(out_brec);
	silofs_bootrec_set_sb_ulink(out_brec, sbi_ulink(sbi));
}

static void fsenv_pre_forkfs(struct silofs_fsenv *fsenv)
{
	silofs_lcache_drop_uamap(fsenv->fse.lcache);
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
	fsenv_make_bootrec_of(fsenv, sbi_alt, &out_brecs->brec_alt);

	fsenv_pre_forkfs(fsenv);
	err = fsenv_clone_rebind_super(fsenv, sbi_cur, &sbi_new);
	if (err) {
		return err;
	}
	fsenv_make_bootrec_of(fsenv, sbi_new, &out_brecs->brec_new);

	sbi_mark_fossil(sbi_cur);
	return 0;
}

void silofs_fsenv_relax_caches(const struct silofs_fsenv *fsenv, int flags)
{
	silofs_bcache_relax(&fsenv->fse.pstore->bcache, flags);
	silofs_lcache_relax(fsenv->fse.lcache, flags);
	silofs_repo_relax(fsenv->fse.repo, flags);
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

void silofs_fsenv_bootpath(const struct silofs_fsenv *fsenv,
                           struct silofs_bootpath *out_bootpath)
{
	const struct silofs_fs_bref *bref = &fsenv->fse_args.bref;

	silofs_bootpath_setup(out_bootpath, bref->repodir, bref->name);
}

static int fsenv_reinit_ciphers(struct silofs_fsenv *fsenv, int algo, int mode)
{
	int err;

	err = silofs_cipher_reinit(&fsenv->fse_enc_cipher, algo, mode);
	if (err) {
		return err;
	}
	err = silofs_cipher_reinit(&fsenv->fse_dec_cipher, algo, mode);
	if (err) {
		return err;
	}
	return 0;
}

static int fsenv_reinit_ciphers_by(struct silofs_fsenv *fsenv,
                                   const struct silofs_bootrec *brec)
{
	const int algo = brec->cipher_algo;
	const int mode = brec->cipher_mode;

	return fsenv_reinit_ciphers(fsenv, algo, mode);
}

static int fsenv_update_bootrec(struct silofs_fsenv *fsenv,
                                const struct silofs_bootrec *brec)
{
	struct silofs_caddr caddr;
	int err;

	err = silofs_calc_bootrec_caddr(fsenv, brec, &caddr);
	if (err) {
		return err;
	}
	silofs_fsenv_set_boot_caddr(fsenv, &caddr);
	silofs_bootrec_assign(&fsenv->fse_boot.brec, brec);
	return 0;
}

int silofs_fsenv_update_by(struct silofs_fsenv *fsenv,
                           const struct silofs_bootrec *brec)
{
	int err;

	err = fsenv_reinit_ciphers_by(fsenv, brec);
	if (err) {
		return err;
	}
	err = fsenv_update_bootrec(fsenv, brec);
	if (err) {
		return err;
	}
	return 0;
}
