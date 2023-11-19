/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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

struct silofs_fsenv_ctx {
	struct silofs_fsenv    *fsenv;
	struct silofs_repo     *repo;
	struct silofs_cache    *cache;
	struct silofs_mdigest  *mdigest;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_lsegid *lsegid_of(const struct silofs_ulink *ulink)
{
	return &ulink->uaddr.laddr.lsegid;
}

static const struct silofs_lsegid *
sbi_lsegid(const struct silofs_sb_info *sbi)
{
	return &sbi->sb_ui.u_ulink.uaddr.laddr.lsegid;
}

static void sbi_set_fsenv(struct silofs_sb_info *sbi,
                          struct silofs_fsenv *fsenv)
{
	silofs_ui_set_fsenv(&sbi->sb_ui, fsenv);
}

static void sni_set_fsenv(struct silofs_spnode_info *sni,
                          struct silofs_fsenv *fsenv)
{
	silofs_ui_set_fsenv(&sni->sn_ui, fsenv);
}

static void sli_set_fsenv(struct silofs_spleaf_info *sli,
                          struct silofs_fsenv *fsenv)
{
	silofs_ui_set_fsenv(&sli->sl_ui, fsenv);
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
		fsenv->fse_ctl_flags |= SILOFS_UBF_ALLOWOTHER;
	}
	if (fs_args->allowadmin) {
		fsenv->fse_ctl_flags |= SILOFS_UBF_ALLOWADMIN;
	}
	if (fs_args->withfuse) {
		fsenv->fse_ctl_flags |= SILOFS_UBF_NLOOKUP;
	}
	if (fs_args->asyncwr) {
		fsenv->fse_ctl_flags |= SILOFS_UBF_ASYNCWR;
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

	silofs_allocstat(fsenv->fse.alloc, &st);
	lim = (st.nbytes_max / (2 * SILOFS_LBK_SIZE));
	return div_round_up(lim, align) * align;
}

static void fsenv_init_commons(struct silofs_fsenv *fsenv,
                               const struct silofs_fsenv_base *ub_base)
{
	memcpy(&fsenv->fse, ub_base, sizeof(fsenv->fse));
	lsegid_reset(&fsenv->fse_sb_lsegid);
	fsenv->fse_init_time = silofs_time_now_monotonic();
	fsenv->fse_commit_id = 0;
	fsenv->fse_iconv = (iconv_t)(-1);
	fsenv->fse_sbi = NULL;
	fsenv->fse_ctl_flags = 0;
	fsenv->fse_ms_flags = 0;
	fsenv->fse_pruneq = NULL;

	fsenv->fse_op_stat.op_iopen_max = 0;
	fsenv->fse_op_stat.op_iopen = 0;
	fsenv->fse_op_stat.op_time = silofs_time_now();
	fsenv->fse_op_stat.op_count = 0;
	fsenv->fse_op_stat.op_iopen_max = fsenv_calc_iopen_limit(fsenv);
}

static void fsenv_fini_commons(struct silofs_fsenv *fsenv)
{
	silofs_assert_null(fsenv->fse_pruneq);

	memset(&fsenv->fse, 0, sizeof(fsenv->fse));
	lsegid_reset(&fsenv->fse_sb_lsegid);
	fsenv->fse_iconv = (iconv_t)(-1);
	fsenv->fse_sbi = NULL;
}

static int fsenv_init_fs_lock(struct silofs_fsenv *fsenv)
{
	return silofs_mutex_init(&fsenv->fse_lock);
}

static void fsenv_fini_fs_lock(struct silofs_fsenv *fsenv)
{
	silofs_mutex_fini(&fsenv->fse_lock);
}

static int fsenv_init_crypto(struct silofs_fsenv *fsenv)
{
	return silofs_crypto_init(&fsenv->fse_crypto);
}

static void fsenv_fini_crypto(struct silofs_fsenv *fsenv)
{
	silofs_crypto_fini(&fsenv->fse_crypto);
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
                      const struct silofs_fsenv_base *ub_base)
{
	int err;

	fsenv_init_commons(fsenv, ub_base);
	fsenv_update_by_fs_args(fsenv);

	err = fsenv_init_fs_lock(fsenv);
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
	fsenv_fini_fs_lock(fsenv);
	fsenv_fini_commons(fsenv);
}

time_t silofs_fsenv_uptime(const struct silofs_fsenv *fsenv)
{
	const time_t now = silofs_time_now_monotonic();

	return now - fsenv->fse_init_time;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void make_super_lsegid(struct silofs_lsegid *out_lsegid)
{
	struct silofs_lvid lvid;

	silofs_lvid_generate(&lvid);
	silofs_lsegid_setup(out_lsegid, &lvid, 0,
	                    SILOFS_STYPE_SUPER, SILOFS_HEIGHT_SUPER);
}

static void make_super_uaddr(const struct silofs_lsegid *lsegid,
                             struct silofs_uaddr *out_uaddr)
{
	silofs_assert_eq(lsegid->height, SILOFS_HEIGHT_SUPER);
	uaddr_setup(out_uaddr, lsegid, 0, SILOFS_STYPE_SUPER, 0);
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

	err = silofs_spawn_super_at(fsenv, ulink, out_sbi);
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

	silofs_sti_update_lsegs(sti, SILOFS_STYPE_SUPER, 1);
	silofs_sti_update_bks(sti, SILOFS_STYPE_SUPER, 1);
	silofs_sti_update_objs(sti, SILOFS_STYPE_SUPER, 1);
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

	err = silofs_stage_super_at(fsenv, &fsenv->fse_sb_ulink, &sbi);
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

	err = silofs_stage_lseg_at(fsenv, lsegid);
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

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void sbi_bind_spstats(struct silofs_sb_info *sbi)
{
	sbi->sb_sti.spst_curr = &sbi->sb->sb_space_stats_curr;
	sbi->sb_sti.spst_base = &sbi->sb->sb_space_stats_base;
	sbi->sb_sti.sbi = sbi;
}

static bool sbi_is_active(const struct silofs_sb_info *sbi)
{
	return silofs_ui_is_active(&sbi->sb_ui);
}

static void sbi_set_active(struct silofs_sb_info *sbi)
{
	silofs_ui_set_active(&sbi->sb_ui);
}

static int sbi_verify_view(struct silofs_sb_info *sbi)
{
	return silofs_ui_verify_view(&sbi->sb_ui);
}

static void sbi_set_staged(struct silofs_sb_info *sbi)
{
	sbi_set_active(sbi);
	sbi_bind_spstats(sbi);
}

static void sbi_set_spawned(struct silofs_sb_info *sbi)
{
	sbi_set_active(sbi);
	sbi_bind_spstats(sbi);
	silofs_ui_mark_verified(&sbi->sb_ui);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool sni_is_active(const struct silofs_spnode_info *sni)
{
	return silofs_ui_is_active(&sni->sn_ui);
}

static void sni_set_active(struct silofs_spnode_info *sni)
{
	silofs_ui_set_active(&sni->sn_ui);
}

static int sni_verify_view(struct silofs_spnode_info *sni)
{
	return silofs_ui_verify_view(&sni->sn_ui);
}

static void sni_set_staged(struct silofs_spnode_info *sni)
{
	sni_set_active(sni);
	silofs_sni_update_nactive(sni);
}

static void sni_set_spawned(struct silofs_spnode_info *sni)
{
	sni_set_active(sni);
	silofs_ui_mark_verified(&sni->sn_ui);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool sli_is_active(const struct silofs_spleaf_info *sli)
{
	return silofs_ui_is_active(&sli->sl_ui);
}

static void sli_set_active(struct silofs_spleaf_info *sli)
{
	silofs_ui_set_active(&sli->sl_ui);
}

static int sli_verify_view(struct silofs_spleaf_info *sli)
{
	return silofs_ui_verify_view(&sli->sl_ui);
}

static void sli_set_staged(struct silofs_spleaf_info *sli)
{
	sli_set_active(sli);
	silofs_sli_update_nused(sli);
}

static void sli_set_spawned(struct silofs_spleaf_info *sli)
{
	sli_set_active(sli);
	silofs_ui_mark_verified(&sli->sl_ui);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void fsec_setup(struct silofs_fsenv_ctx *fse_ctx)
{
	struct silofs_fsenv *fsenv = fse_ctx->fsenv;
	struct silofs_repo *repo = fsenv->fse.repo;

	fse_ctx->fsenv = fsenv;
	fse_ctx->repo = fsenv->fse.repo;
	fse_ctx->cache = fsenv->fse.cache;
	fse_ctx->mdigest = &repo->re_mdigest;
}

static int fsec_fetch_cached_ui(const struct silofs_fsenv_ctx *fse_ctx,
                                const struct silofs_uaddr *uaddr,
                                struct silofs_unode_info **out_ui)
{
	*out_ui = silofs_cache_lookup_ui(fse_ctx->cache, uaddr);
	return (*out_ui == NULL) ? -SILOFS_ENOENT : 0;
}

static void fsec_bind_spawned_ui(const struct silofs_fsenv_ctx *fse_ctx,
                                 struct silofs_unode_info *ui)
{
	ui->u_lni.fsenv = fse_ctx->fsenv;
}

static int fsec_create_cached_ui(const struct silofs_fsenv_ctx *fse_ctx,
                                 const struct silofs_ulink *ulink,
                                 struct silofs_unode_info **out_ui)
{
	*out_ui = silofs_cache_create_ui(fse_ctx->cache, ulink);
	if (*out_ui == NULL) {
		return -SILOFS_ENOMEM;
	}
	fsec_bind_spawned_ui(fse_ctx, *out_ui);
	return 0;
}

static int fsec_require_cached_ui(const struct silofs_fsenv_ctx *fse_ctx,
                                  const struct silofs_ulink *ulink,
                                  struct silofs_unode_info **out_ui)
{
	int ret;

	ret = fsec_fetch_cached_ui(fse_ctx, &ulink->uaddr, out_ui);
	if (ret == -SILOFS_ENOENT) {
		ret = fsec_create_cached_ui(fse_ctx, ulink, out_ui);
	}
	return ret;
}

static void fsec_forget_cached_ui(const struct silofs_fsenv_ctx *fse_ctx,
                                  struct silofs_unode_info *ui)
{
	silofs_cache_forget_ui(fse_ctx->cache, ui);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool fsec_lsegid_rw_mode(const struct silofs_fsenv_ctx *fse_ctx,
                                const struct silofs_lsegid *lsegid)
{
	const struct silofs_sb_info *sbi = fse_ctx->fsenv->fse_sbi;
	bool rw_mode;

	if (unlikely(sbi == NULL)) {
		rw_mode = true;
	} else if (silofs_sbi_ismutable_lsegid(sbi, lsegid)) {
		rw_mode = true;
	} else {
		/*
		 * TODO-0054: Allow read-only mode to lseg.
		 *
		 * When staging logical-segment which is not part of active
		 * main file-system, stage it as read-only. Currently, this
		 * logic has an issue with (offline) snapshots, thus forcing
		 * read-write mode.
		 */
		rw_mode = true;
	}
	return rw_mode;
}

static int fsec_lookup_lseg(const struct silofs_fsenv_ctx *fse_ctx,
                            const struct silofs_lsegid *lsegid)
{
	struct stat st;

	return silofs_repo_stat_lseg(fse_ctx->repo, lsegid, true, &st);
}

static int fsec_stage_lseg(const struct silofs_fsenv_ctx *fse_ctx,
                           const struct silofs_lsegid *lsegid)
{
	int err;
	const bool rw = fsec_lsegid_rw_mode(fse_ctx, lsegid);

	err = silofs_repo_stage_lseg(fse_ctx->repo, rw, lsegid);
	if (err && (err != -SILOFS_ENOENT)) {
		log_dbg("stage lseg failed: err=%d", err);
	}
	return err;
}

static int fsec_spawn_lseg(const struct silofs_fsenv_ctx *fse_ctx,
                           const struct silofs_lsegid *lsegid)
{
	int err;

	err = silofs_repo_spawn_lseg(fse_ctx->repo, lsegid);
	if (err && (err != -SILOFS_ENOENT)) {
		log_dbg("spawn lseg failed: err=%d", err);
	}
	return err;
}

static int fsec_require_lseg(const struct silofs_fsenv_ctx *fse_ctx,
                             const struct silofs_lsegid *lsegid)
{
	int err;

	err = fsec_lookup_lseg(fse_ctx, lsegid);
	if (!err) {
		err = fsec_stage_lseg(fse_ctx, lsegid);
	} else if (err == -SILOFS_ENOENT) {
		err = fsec_spawn_lseg(fse_ctx, lsegid);
	}
	return err;
}

static int fsec_require_lseg_by(const struct silofs_fsenv_ctx *fse_ctx,
                                const struct silofs_ulink *ulink)
{
	return fsec_require_lseg(fse_ctx, &ulink->uaddr.laddr.lsegid);
}

static int fsec_load_view_at(const struct silofs_fsenv_ctx *fse_ctx,
                             const struct silofs_laddr *laddr,
                             struct silofs_view *view)
{
	return silofs_repo_read_at(fse_ctx->repo, laddr, view);
}

static int fsec_stage_load_view(const struct silofs_fsenv_ctx *fse_ctx,
                                const struct silofs_laddr *laddr,
                                struct silofs_view *view)
{
	int err;

	silofs_assert_not_null(view);

	err = fsec_stage_lseg(fse_ctx, &laddr->lsegid);
	if (err) {
		return err;
	}
	err = fsec_load_view_at(fse_ctx, laddr, view);
	if (err) {
		return err;
	}
	return 0;
}

static int fsec_decrypt_ui_view(const struct silofs_fsenv_ctx *fse_ctx,
                                struct silofs_unode_info *ui)
{
	return silofs_decrypt_ui_view(fse_ctx->fsenv, ui);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fsec_forget_cached_sbi(const struct silofs_fsenv_ctx *fse_ctx,
                                   struct silofs_sb_info *sbi)
{
	if (sbi != NULL) {
		fsec_forget_cached_ui(fse_ctx, &sbi->sb_ui);
	}
}

static int fsec_require_cached_sbi(const struct silofs_fsenv_ctx *fse_ctx,
                                   const struct silofs_ulink *ulink,
                                   struct silofs_sb_info **out_sbi)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = fsec_require_cached_ui(fse_ctx, ulink, &ui);
	if (err) {
		return err;
	}
	*out_sbi = silofs_sbi_from_ui(ui);
	sbi_set_fsenv(*out_sbi, fse_ctx->fsenv);
	return 0;
}

static int fsec_spawn_super_at(const struct silofs_fsenv_ctx *fse_ctx,
                               const struct silofs_ulink *ulink,
                               struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = fsec_require_cached_sbi(fse_ctx, ulink, &sbi);
	if (err) {
		goto out_err;
	}
	err = fsec_require_lseg_by(fse_ctx, ulink);
	if (err) {
		goto out_err;
	}
	sbi_set_spawned(sbi);

	*out_sbi = sbi;
	return 0;
out_err:
	fsec_forget_cached_sbi(fse_ctx, sbi);
	*out_sbi = NULL;
	return err;
}

int silofs_spawn_super_at(struct silofs_fsenv *fsenv,
                          const struct silofs_ulink *ulink,
                          struct silofs_sb_info **out_sbi)
{
	struct silofs_fsenv_ctx fse_ctx = { .fsenv = fsenv };

	fsec_setup(&fse_ctx);
	return fsec_spawn_super_at(&fse_ctx, ulink, out_sbi);
}

static int fsec_decrypt_view_of_sbi(const struct silofs_fsenv_ctx *fse_ctx,
                                    struct silofs_sb_info *sbi)
{
	return fsec_decrypt_ui_view(fse_ctx, &sbi->sb_ui);
}

static int fsec_load_view_of_sbi(const struct silofs_fsenv_ctx *fse_ctx,
                                 struct silofs_sb_info *sbi)
{
	return fsec_stage_load_view(fse_ctx, sbi_laddr(sbi),
	                            sbi->sb_ui.u_lni.view);
}

static int fsec_stage_super_at(const struct silofs_fsenv_ctx *fse_ctx,
                               const struct silofs_ulink *ulink,
                               struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = fsec_require_cached_sbi(fse_ctx, ulink, &sbi);
	if (err) {
		return err;
	}
	if (sbi_is_active(sbi)) {
		goto out_ok;
	}
	err = fsec_require_lseg_by(fse_ctx, ulink);
	if (err) {
		goto out_err;
	}
	err = fsec_load_view_of_sbi(fse_ctx, sbi);
	if (err) {
		goto out_err;
	}
	err = fsec_decrypt_view_of_sbi(fse_ctx, sbi);
	if (err) {
		goto out_err;
	}
	err = sbi_verify_view(sbi);
	if (err) {
		goto out_err;
	}
	sbi_set_staged(sbi);
out_ok:
	*out_sbi = sbi;
	return 0;
out_err:
	fsec_forget_cached_sbi(fse_ctx, sbi);
	*out_sbi = NULL;
	return err;
}

int silofs_stage_super_at(struct silofs_fsenv *fsenv,
                          const struct silofs_ulink *ulink,
                          struct silofs_sb_info **out_sbi)
{
	struct silofs_fsenv_ctx fse_ctx = { .fsenv = fsenv };

	fsec_setup(&fse_ctx);
	return fsec_stage_super_at(&fse_ctx, ulink, out_sbi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fsec_forget_cached_sni(const struct silofs_fsenv_ctx *fse_ctx,
                                   struct silofs_spnode_info *sni)
{
	if (sni != NULL) {
		fsec_forget_cached_ui(fse_ctx, &sni->sn_ui);
	}
}

static int fsec_require_cached_sni(const struct silofs_fsenv_ctx *fse_ctx,
                                   const struct silofs_ulink *ulink,
                                   struct silofs_spnode_info **out_sni)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = fsec_require_cached_ui(fse_ctx, ulink, &ui);
	if (err) {
		return err;
	}
	*out_sni = silofs_sni_from_ui(ui);
	sni_set_fsenv(*out_sni, fse_ctx->fsenv);
	return 0;
}

static int fsec_spawn_spnode_at(const struct silofs_fsenv_ctx *fse_ctx,
                                const struct silofs_ulink *ulink,
                                struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni = NULL;
	int err;

	err = fsec_require_cached_sni(fse_ctx, ulink, &sni);
	if (err) {
		return err;
	}
	if (sni_is_active(sni)) {
		goto out_ok;
	}
	err = fsec_require_lseg_by(fse_ctx, ulink);
	if (err) {
		goto out_err;
	}
	sni_set_spawned(sni);
out_ok:
	*out_sni = sni;
	return 0;
out_err:
	fsec_forget_cached_sni(fse_ctx, sni);
	*out_sni = NULL;
	return err;
}

int silofs_spawn_spnode_at(struct silofs_fsenv *fsenv,
                           const struct silofs_ulink *ulink,
                           struct silofs_spnode_info **out_sni)
{
	struct silofs_fsenv_ctx fse_ctx = { .fsenv = fsenv };

	fsec_setup(&fse_ctx);
	return fsec_spawn_spnode_at(&fse_ctx, ulink, out_sni);
}

static int fsec_decrypt_view_of_sni(const struct silofs_fsenv_ctx *fse_ctx,
                                    struct silofs_spnode_info *sni)
{
	return fsec_decrypt_ui_view(fse_ctx, &sni->sn_ui);
}

static int fsec_load_view_of_sni(const struct silofs_fsenv_ctx *fse_ctx,
                                 struct silofs_spnode_info *sni)
{
	return fsec_stage_load_view(fse_ctx, sni_laddr(sni),
	                            sni->sn_ui.u_lni.view);
}

static int fsec_stage_spnode_at(const struct silofs_fsenv_ctx *fse_ctx,
                                const struct silofs_ulink *ulink,
                                struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni = NULL;
	int err;

	err = fsec_require_cached_sni(fse_ctx, ulink, &sni);
	if (err) {
		return err;
	}
	if (sni_is_active(sni)) {
		goto out_ok;
	}
	err = fsec_require_lseg_by(fse_ctx, ulink);
	if (err) {
		goto out_err;
	}
	err = fsec_load_view_of_sni(fse_ctx, sni);
	if (err) {
		goto out_err;
	}
	err = fsec_decrypt_view_of_sni(fse_ctx, sni);
	if (err) {
		goto out_err;
	}
	err = sni_verify_view(sni);
	if (err) {
		goto out_err;
	}
	sni_set_staged(sni);
out_ok:
	*out_sni = sni;
	return 0;
out_err:
	fsec_forget_cached_sni(fse_ctx, sni);
	*out_sni = NULL;
	return err;
}

int silofs_stage_spnode_at(struct silofs_fsenv *fsenv,
                           const struct silofs_ulink *ulink,
                           struct silofs_spnode_info **out_sni)
{
	struct silofs_fsenv_ctx fse_ctx = { .fsenv = fsenv };

	fsec_setup(&fse_ctx);
	return fsec_stage_spnode_at(&fse_ctx, ulink, out_sni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void fsec_forget_cached_sli(const struct silofs_fsenv_ctx *fse_ctx,
                                   struct silofs_spleaf_info *sli)
{
	if (sli != NULL) {
		fsec_forget_cached_ui(fse_ctx, &sli->sl_ui);
	}
}

static int fsec_require_cached_sli(const struct silofs_fsenv_ctx *fse_ctx,
                                   const struct silofs_ulink *ulink,
                                   struct silofs_spleaf_info **out_sli)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = fsec_require_cached_ui(fse_ctx, ulink, &ui);
	if (err) {
		return err;
	}
	*out_sli = silofs_sli_from_ui(ui);
	sli_set_fsenv(*out_sli, fse_ctx->fsenv);
	return 0;
}

static int fsec_spawn_spleaf_at(const struct silofs_fsenv_ctx *fse_ctx,
                                const struct silofs_ulink *ulink,
                                struct silofs_spleaf_info **out_sli)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = fsec_require_cached_sli(fse_ctx, ulink, &sli);
	if (err) {
		goto out_err;
	}
	if (sli_is_active(sli)) {
		goto out_ok;
	}
	err = fsec_require_lseg_by(fse_ctx, ulink);
	if (err) {
		goto out_err;
	}
	sli_set_spawned(sli);
out_ok:
	*out_sli = sli;
	return 0;
out_err:
	fsec_forget_cached_sli(fse_ctx, sli);
	*out_sli = NULL;
	return err;
}

int silofs_spawn_spleaf_at(struct silofs_fsenv *fsenv,
                           const struct silofs_ulink *ulink,
                           struct silofs_spleaf_info **out_sli)
{
	struct silofs_fsenv_ctx fse_ctx = { .fsenv = fsenv };

	fsec_setup(&fse_ctx);
	return fsec_spawn_spleaf_at(&fse_ctx, ulink, out_sli);
}

static int fsec_decrypt_view_of_sli(const struct silofs_fsenv_ctx *fse_ctx,
                                    struct silofs_spleaf_info *sli)
{
	return fsec_decrypt_ui_view(fse_ctx, &sli->sl_ui);
}

static int fsec_load_view_of_sli(const struct silofs_fsenv_ctx *fse_ctx,
                                 struct silofs_spleaf_info *sli)
{
	return fsec_stage_load_view(fse_ctx, sli_laddr(sli),
	                            sli->sl_ui.u_lni.view);
}

static int fsec_stage_spleaf_at(const struct silofs_fsenv_ctx *fse_ctx,
                                const struct silofs_ulink *ulink,
                                struct silofs_spleaf_info **out_sli)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = fsec_require_cached_sli(fse_ctx, ulink, &sli);
	if (err) {
		goto out_err;
	}
	if (sli_is_active(sli)) {
		goto out_ok;
	}
	err = fsec_require_lseg_by(fse_ctx, ulink);
	if (err) {
		goto out_err;
	}
	err = fsec_load_view_of_sli(fse_ctx, sli);
	if (err) {
		goto out_err;
	}
	err = fsec_decrypt_view_of_sli(fse_ctx, sli);
	if (err) {
		goto out_err;
	}
	err = sli_verify_view(sli);
	if (err) {
		goto out_err;
	}
	sli_set_staged(sli);
out_ok:
	*out_sli = sli;
	return 0;
out_err:
	fsec_forget_cached_sli(fse_ctx, sli);
	*out_sli = NULL;
	return err;
}

int silofs_stage_spleaf_at(struct silofs_fsenv *fsenv,
                           const struct silofs_ulink *ulink,
                           struct silofs_spleaf_info **out_sli)
{
	struct silofs_fsenv_ctx fse_ctx = { .fsenv = fsenv };

	fsec_setup(&fse_ctx);
	return fsec_stage_spleaf_at(&fse_ctx, ulink, out_sli);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int fsec_require_no_lseg(const struct silofs_fsenv_ctx *fse_ctx,
                                const struct silofs_lsegid *lsegid)
{
	int err;

	err = fsec_lookup_lseg(fse_ctx, lsegid);
	if (!err) {
		return -SILOFS_EEXIST;
	}
	if (err != -SILOFS_ENOENT) {
		return err;
	}
	return 0;
}

int silofs_spawn_lseg_at(struct silofs_fsenv *fsenv,
                         const struct silofs_lsegid *lsegid)
{
	struct silofs_fsenv_ctx fse_ctx = { .fsenv = fsenv };
	int err;

	fsec_setup(&fse_ctx);
	err = fsec_require_no_lseg(&fse_ctx, lsegid);
	if (err) {
		return err;
	}
	err = fsec_spawn_lseg(&fse_ctx, lsegid);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_stage_lseg_at(struct silofs_fsenv *fsenv,
                         const struct silofs_lsegid *lsegid)
{
	struct silofs_fsenv_ctx fse_ctx = { .fsenv = fsenv };
	int err;

	fsec_setup(&fse_ctx);
	err = fsec_lookup_lseg(&fse_ctx, lsegid);
	if (err) {
		return err;
	}
	err = fsec_stage_lseg(&fse_ctx, lsegid);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_relax_caches(const struct silofs_task *task, int flags)
{
	silofs_cache_relax(task_cache(task), flags);
	if (flags & SILOFS_F_IDLE) {
		silofs_repo_relax(task_repo(task));
	}
}
