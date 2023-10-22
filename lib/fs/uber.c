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

struct silofs_uber_ctx {
	struct silofs_uber     *uber;
	struct silofs_repo     *repo;
	struct silofs_cache    *cache;
	struct silofs_mdigest  *mdigest;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_lextid *lextid_of(const struct silofs_ulink *ulink)
{
	return &ulink->uaddr.laddr.lextid;
}

static void ui_bkaddr(const struct silofs_unode_info *ui,
                      struct silofs_bkaddr *out_bkaddr)
{
	bkaddr_by_laddr(out_bkaddr, ui_laddr(ui));
}

static const struct silofs_lextid *
sbi_lextid(const struct silofs_sb_info *sbi)
{
	return &sbi->sb_ui.u_ubki->ubk_addr.laddr.lextid;
}

static void sbi_set_uber(struct silofs_sb_info *sbi, struct silofs_uber *uber)
{
	silofs_ui_set_uber(&sbi->sb_ui, uber);
}

static void sbi_bkaddr(const struct silofs_sb_info *sbi,
                       struct silofs_bkaddr *out_bkaddr)
{
	ui_bkaddr(&sbi->sb_ui, out_bkaddr);
}

static void sni_set_uber(struct silofs_spnode_info *sni,
                         struct silofs_uber *uber)
{
	silofs_ui_set_uber(&sni->sn_ui, uber);
}

static void sni_bkaddr(const struct silofs_spnode_info *sni,
                       struct silofs_bkaddr *out_bkaddr)
{
	ui_bkaddr(&sni->sn_ui, out_bkaddr);
}

static void sli_set_uber(struct silofs_spleaf_info *sli,
                         struct silofs_uber *uber)
{
	silofs_ui_set_uber(&sli->sl_ui, uber);
}

static void sli_bkaddr(const struct silofs_spleaf_info *sli,
                       struct silofs_bkaddr *out_bkaddr)
{
	ui_bkaddr(&sli->sl_ui, out_bkaddr);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void uber_bind_sb_lextid(struct silofs_uber *uber,
                                const struct silofs_lextid *lextid_new)
{
	struct silofs_repo *repo = uber->ub.repo;
	struct silofs_lextid *lextid_cur = &uber->ub_sb_lextid;

	if (!lextid_isnull(lextid_cur)) {
		silofs_repo_funlock_lext(repo, lextid_cur);
	}
	if (lextid_new && !lextid_isnull(lextid_new)) {
		silofs_repo_flock_lext(repo, lextid_new);
	}
	if (lextid_new) {
		lextid_assign(lextid_cur, lextid_new);
	} else {
		lextid_reset(lextid_cur);
	}
}

static void uber_bind_sbi(struct silofs_uber *uber,
                          struct silofs_sb_info *sbi_new)
{
	struct silofs_sb_info *sbi_cur = uber->ub_sbi;

	if (sbi_cur != NULL) {
		silofs_sbi_decref(sbi_cur);
	}
	if (sbi_new != NULL) {
		silofs_sbi_incref(sbi_new);
	}
	uber->ub_sbi = sbi_new;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void uber_update_owner(struct silofs_uber *uber)
{
	const struct silofs_fs_args *fs_args = uber->ub.fs_args;

	uber->ub_owner.uid = fs_args->uid;
	uber->ub_owner.gid = fs_args->gid;
	uber->ub_owner.umask = fs_args->umask;
}

static void uber_update_mntflags(struct silofs_uber *uber)
{
	const struct silofs_fs_args *fs_args = uber->ub.fs_args;
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
	uber->ub_ms_flags |= ms_flag_with;
	uber->ub_ms_flags &= ~ms_flag_dont;
}

static void uber_update_ctlflags(struct silofs_uber *uber)
{
	const struct silofs_fs_args *fs_args = uber->ub.fs_args;

	if (fs_args->allowother) {
		uber->ub_ctl_flags |= SILOFS_UBF_ALLOWOTHER;
	}
	if (fs_args->allowadmin) {
		uber->ub_ctl_flags |= SILOFS_UBF_ALLOWADMIN;
	}
	if (fs_args->withfuse) {
		uber->ub_ctl_flags |= SILOFS_UBF_NLOOKUP;
	}
	if (fs_args->asyncwr) {
		uber->ub_ctl_flags |= SILOFS_UBF_ASYNCWR;
	}
}

static void uber_update_by_fs_args(struct silofs_uber *uber)
{
	uber_update_owner(uber);
	uber_update_mntflags(uber);
	uber_update_ctlflags(uber);
}

static size_t uber_calc_iopen_limit(const struct silofs_uber *uber)
{
	struct silofs_alloc_stat st;
	const size_t align = 128;
	size_t lim;

	silofs_allocstat(uber->ub.alloc, &st);
	lim = (st.nbytes_max / (2 * SILOFS_LBK_SIZE));
	return div_round_up(lim, align) * align;
}

static void uber_init_commons(struct silofs_uber *uber,
                              const struct silofs_uber_base *ub_base)
{
	memcpy(&uber->ub, ub_base, sizeof(uber->ub));
	lextid_reset(&uber->ub_sb_lextid);
	uber->ub_initime = silofs_time_now_monotonic();
	uber->ub_commit_id = 0;
	uber->ub_iconv = (iconv_t)(-1);
	uber->ub_sbi = NULL;
	uber->ub_ctl_flags = 0;
	uber->ub_ms_flags = 0;

	uber->ub_ops.op_iopen_max = 0;
	uber->ub_ops.op_iopen = 0;
	uber->ub_ops.op_time = silofs_time_now();
	uber->ub_ops.op_count = 0;
	uber->ub_ops.op_iopen_max = uber_calc_iopen_limit(uber);
}

static void uber_fini_commons(struct silofs_uber *uber)
{
	memset(&uber->ub, 0, sizeof(uber->ub));
	lextid_reset(&uber->ub_sb_lextid);
	uber->ub_iconv = (iconv_t)(-1);
	uber->ub_sbi = NULL;
}

static int uber_init_fs_lock(struct silofs_uber *uber)
{
	return silofs_mutex_init(&uber->ub_fs_lock);
}

static void uber_fini_fs_lock(struct silofs_uber *uber)
{
	silofs_mutex_fini(&uber->ub_fs_lock);
}

static int uber_init_crypto(struct silofs_uber *uber)
{
	return silofs_crypto_init(&uber->ub_crypto);
}

static void uber_fini_crypto(struct silofs_uber *uber)
{
	silofs_crypto_fini(&uber->ub_crypto);
}

static int uber_init_iconv(struct silofs_uber *uber)
{
	/* Using UTF32LE to avoid BOM (byte-order-mark) character */
	uber->ub_iconv = iconv_open("UTF32LE", "UTF8");
	if (uber->ub_iconv == (iconv_t)(-1)) {
		return errno ? -errno : -SILOFS_EOPNOTSUPP;
	}
	return 0;
}

static void uber_fini_iconv(struct silofs_uber *uber)
{
	if (uber->ub_iconv != (iconv_t)(-1)) {
		iconv_close(uber->ub_iconv);
		uber->ub_iconv = (iconv_t)(-1);
	}
}

int silofs_uber_init(struct silofs_uber *uber,
                     const struct silofs_uber_base *ub_base)
{
	int err;

	uber_init_commons(uber, ub_base);
	uber_update_by_fs_args(uber);

	err = uber_init_fs_lock(uber);
	if (err) {
		return err;
	}
	err = uber_init_crypto(uber);
	if (err) {
		goto out_err;
	}
	err = uber_init_iconv(uber);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	silofs_uber_fini(uber);
	return err;
}

void silofs_uber_fini(struct silofs_uber *uber)
{
	uber_bind_sbi(uber, NULL);
	uber_fini_iconv(uber);
	uber_fini_crypto(uber);
	uber_fini_fs_lock(uber);
	uber_fini_commons(uber);
}

time_t silofs_uber_uptime(const struct silofs_uber *uber)
{
	const time_t now = silofs_time_now_monotonic();

	return now - uber->ub_initime;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void make_super_lextid(struct silofs_lextid *out_lextid)
{
	struct silofs_treeid treeid;

	silofs_treeid_generate(&treeid);
	silofs_lextid_setup(out_lextid, &treeid, 0,
	                    SILOFS_STYPE_SUPER, SILOFS_HEIGHT_SUPER);
}

static void make_super_uaddr(const struct silofs_lextid *lextid,
                             struct silofs_uaddr *out_uaddr)
{
	silofs_assert_eq(lextid->height, SILOFS_HEIGHT_SUPER);
	uaddr_setup(out_uaddr, lextid, 0, SILOFS_STYPE_SUPER, 0);
}

static void ulink_init(struct silofs_ulink *ulink,
                       const struct silofs_uaddr *uaddr,
                       const struct silofs_iv *iv)
{
	silofs_uaddr_assign(&ulink->uaddr, uaddr);
	silofs_iv_assign(&ulink->riv, iv);
}

static void uber_make_super_ulink(const struct silofs_uber *uber,
                                  struct silofs_ulink *out_ulink)
{
	struct silofs_lextid lextid;
	struct silofs_uaddr uaddr;

	make_super_lextid(&lextid);
	make_super_uaddr(&lextid, &uaddr);
	ulink_init(out_ulink, &uaddr, &uber->ub.main_ivkey->iv);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_uber_bind_child(struct silofs_uber *uber,
                            const struct silofs_ulink *sb_ulink)
{
	ulink_assign(&uber->ub_sb_ulink, sb_ulink);
}

static int uber_spawn_super_at(struct silofs_uber *uber,
                               const struct silofs_ulink *ulink,
                               struct silofs_sb_info **out_sbi)
{
	int err;

	err = silofs_spawn_super_at(uber, ulink, out_sbi);
	if (err) {
		return err;
	}
	silofs_sbi_setup_spawned(*out_sbi);
	return 0;
}

static int uber_spawn_super_of(struct silofs_uber *uber,
                               struct silofs_sb_info **out_sbi)
{
	struct silofs_ulink ulink = { .uaddr.voff = -1 };

	uber_make_super_ulink(uber, &ulink);
	return uber_spawn_super_at(uber, &ulink, out_sbi);
}

static int uber_spawn_super(struct silofs_uber *uber, size_t capacity,
                            struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = uber_spawn_super_of(uber, &sbi);
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

	silofs_sti_update_lexts(sti, SILOFS_STYPE_SUPER, 1);
	silofs_sti_update_bks(sti, SILOFS_STYPE_SUPER, 1);
	silofs_sti_update_objs(sti, SILOFS_STYPE_SUPER, 1);
}

int silofs_uber_format_super(struct silofs_uber *uber, size_t capacity)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = uber_spawn_super(uber, capacity, &sbi);
	if (err) {
		return err;
	}
	sbi_account_super_of(sbi);
	uber_bind_sbi(uber, sbi);
	return 0;
}

int silofs_uber_reload_super(struct silofs_uber *uber)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = silofs_stage_super_at(uber, &uber->ub_sb_ulink, &sbi);
	if (err) {
		return err;
	}
	uber_bind_sbi(uber, sbi);
	return 0;
}

int silofs_uber_reload_sb_lext(struct silofs_uber *uber)
{
	const struct silofs_lextid *lextid = lextid_of(&uber->ub_sb_ulink);
	int err;

	err = silofs_stage_lext_at(uber, lextid);
	if (err) {
		log_warn("unable to stage sb-lext: err=%d", err);
		return err;
	}
	err = silofs_repo_flock_lext(uber->ub.repo, lextid);
	if (err) {
		log_err("unable to lock sb-lext: err=%d", err);
		return err;
	}
	uber_bind_sb_lextid(uber, lextid);
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

void silofs_uber_shut(struct silofs_uber *uber)
{
	uber_bind_sbi(uber, NULL);
	uber_bind_sb_lextid(uber, NULL);
}

static void uber_rebind_root_sb(struct silofs_uber *uber,
                                struct silofs_sb_info *sbi)
{
	silofs_uber_bind_child(uber, sbi_ulink(sbi));
	uber_bind_sb_lextid(uber, sbi_lextid(sbi));
	uber_bind_sbi(uber, sbi);
}

static int uber_clone_rebind_super(struct silofs_uber *uber,
                                   const struct silofs_sb_info *sbi_cur,
                                   struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = uber_spawn_super(uber, 0, &sbi);
	if (err) {
		return err;
	}
	sbi_make_clone(sbi, sbi_cur);
	uber_rebind_root_sb(uber, sbi);

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

static void uber_pre_forkfs(struct silofs_uber *uber)
{
	silofs_cache_drop_uamap(uber->ub.cache);
}

int silofs_uber_forkfs(struct silofs_uber *uber,
                       struct silofs_bootrecs *out_brecs)
{
	struct silofs_sb_info *sbi_alt = NULL;
	struct silofs_sb_info *sbi_new = NULL;
	struct silofs_sb_info *sbi_cur = uber->ub_sbi;
	int err;

	uber_pre_forkfs(uber);
	err = uber_clone_rebind_super(uber, sbi_cur, &sbi_alt);
	if (err) {
		return err;
	}
	sbi_export_bootrec(sbi_alt, &out_brecs->brec[1]);

	uber_pre_forkfs(uber);
	err = uber_clone_rebind_super(uber, sbi_cur, &sbi_new);
	if (err) {
		return err;
	}
	sbi_export_bootrec(sbi_new, &out_brecs->brec[0]);

	sbi_mark_fossil(sbi_cur);
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void ui_stamp_mark_visible(struct silofs_unode_info *ui)
{
	silofs_zero_stamp_meta(ui->u.view, ui_stype(ui));
	ui->u.flags |= SILOFS_LNF_VERIFIED;
}

static bool sbi_is_stable(const struct silofs_sb_info *sbi)
{
	return (sbi->sb_ui.u_ubki != NULL) && (sbi->sb != NULL);
}

static void sbi_attach_to(struct silofs_sb_info *sbi,
                          struct silofs_ubk_info *ubki)
{
	silofs_ui_attach_to(&sbi->sb_ui, ubki);
	sbi->sb = &sbi->sb_ui.u.view->sb;
	sbi->sb_sti.spst_curr = &sbi->sb->sb_space_stats_curr;
	sbi->sb_sti.spst_base = &sbi->sb->sb_space_stats_base;
	sbi->sb_sti.sbi = sbi;
}

static int sbi_verify_view(struct silofs_sb_info *sbi)
{
	return silofs_ui_verify_view(&sbi->sb_ui);
}

static void sbi_set_spawned(struct silofs_sb_info *sbi)
{
	ui_stamp_mark_visible(&sbi->sb_ui);
	silofs_ui_set_bkview(&sbi->sb_ui);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool sni_is_stable(const struct silofs_spnode_info *sni)
{
	return (sni->sn_ui.u_ubki != NULL) && (sni->sn != NULL);
}

static void sni_attach_to(struct silofs_spnode_info *sni,
                          struct silofs_ubk_info *ubki)
{
	silofs_ui_attach_to(&sni->sn_ui, ubki);
	sni->sn = &sni->sn_ui.u.view->sn;
}

static int sni_verify_view(struct silofs_spnode_info *sni)
{
	return silofs_ui_verify_view(&sni->sn_ui);
}

static void sni_set_spawned(struct silofs_spnode_info *sni)
{
	ui_stamp_mark_visible(&sni->sn_ui);
	silofs_ui_set_bkview(&sni->sn_ui);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool sli_is_stable(const struct silofs_spleaf_info *sli)
{
	return (sli->sl_ui.u_ubki != NULL) && (sli->sl != NULL);
}

static void sli_attach_to(struct silofs_spleaf_info *sli,
                          struct silofs_ubk_info *ubki)
{
	silofs_ui_attach_to(&sli->sl_ui, ubki);
	sli->sl = &sli->sl_ui.u.view->sl;
}

static int sli_verify_view(struct silofs_spleaf_info *sli)
{
	return silofs_ui_verify_view(&sli->sl_ui);
}

static void sli_set_spawned(struct silofs_spleaf_info *sli)
{
	ui_stamp_mark_visible(&sli->sl_ui);
	silofs_ui_set_bkview(&sli->sl_ui);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void ubc_setup(struct silofs_uber_ctx *ub_ctx)
{
	struct silofs_uber *uber = ub_ctx->uber;
	struct silofs_repo *repo = uber->ub.repo;

	ub_ctx->uber = uber;
	ub_ctx->repo = uber->ub.repo;
	ub_ctx->cache = uber->ub.cache;
	ub_ctx->mdigest = &repo->re_mdigest;
}

static int ubc_fetch_cached_ui(const struct silofs_uber_ctx *ub_ctx,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_unode_info **out_ui)
{
	*out_ui = silofs_cache_lookup_ui(ub_ctx->cache, uaddr);
	return (*out_ui == NULL) ? -SILOFS_ENOENT : 0;
}

static void ubc_bind_spawned_ui(const struct silofs_uber_ctx *ub_ctx,
                                struct silofs_unode_info *ui)
{
	ui->u.uber = ub_ctx->uber;
}

static int ubc_create_cached_ui(const struct silofs_uber_ctx *ub_ctx,
                                const struct silofs_ulink *ulink,
                                struct silofs_unode_info **out_ui)
{
	*out_ui = silofs_cache_create_ui(ub_ctx->cache, ulink);
	if (*out_ui == NULL) {
		return -SILOFS_ENOMEM;
	}
	ubc_bind_spawned_ui(ub_ctx, *out_ui);
	return 0;
}

static int ubc_require_cached_ui(const struct silofs_uber_ctx *ub_ctx,
                                 const struct silofs_ulink *ulink,
                                 struct silofs_unode_info **out_ui)
{
	int ret;

	ret = ubc_fetch_cached_ui(ub_ctx, &ulink->uaddr, out_ui);
	if (ret == -SILOFS_ENOENT) {
		ret = ubc_create_cached_ui(ub_ctx, ulink, out_ui);
	}
	return ret;
}

static void ubc_forget_cached_ui(const struct silofs_uber_ctx *ub_ctx,
                                 struct silofs_unode_info *ui)
{
	silofs_cache_forget_ui(ub_ctx->cache, ui);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool ubc_lextid_rw_mode(const struct silofs_uber_ctx *ub_ctx,
                               const struct silofs_lextid *lextid)
{
	const struct silofs_sb_info *sbi = ub_ctx->uber->ub_sbi;

	return likely(sbi) ? silofs_sbi_ismutable_lextid(sbi, lextid) : true;
}

static int ubc_lookup_lext(const struct silofs_uber_ctx *ub_ctx,
                           const struct silofs_lextid *lextid)
{
	struct stat st;

	return silofs_repo_stat_lext(ub_ctx->repo, lextid, true, &st);
}

static int ubc_stage_lext(const struct silofs_uber_ctx *ub_ctx,
                          const struct silofs_lextid *lextid)
{
	int err;
	const bool rw_mode = ubc_lextid_rw_mode(ub_ctx, lextid);

	err = silofs_repo_stage_lext(ub_ctx->repo, rw_mode, lextid);
	if (err && (err != -SILOFS_ENOENT)) {
		log_dbg("stage lext failed: err=%d", err);
	}
	return err;
}

static int ubc_spawn_lext(const struct silofs_uber_ctx *ub_ctx,
                          const struct silofs_lextid *lextid)
{
	int err;

	err = silofs_repo_spawn_lext(ub_ctx->repo, lextid);
	if (err && (err != -SILOFS_ENOENT)) {
		log_dbg("spawn lext failed: err=%d", err);
	}
	return err;
}

static int ubc_require_lext(const struct silofs_uber_ctx *ub_ctx,
                            const struct silofs_lextid *lextid)
{
	int err;

	err = ubc_lookup_lext(ub_ctx, lextid);
	if (!err) {
		err = ubc_stage_lext(ub_ctx, lextid);
	} else if (err == -SILOFS_ENOENT) {
		err = ubc_spawn_lext(ub_ctx, lextid);
	}
	return err;
}

static int ubc_require_lext_of(const struct silofs_uber_ctx *ub_ctx,
                               const struct silofs_bkaddr *bkaddr)
{
	return ubc_require_lext(ub_ctx, &bkaddr->laddr.lextid);
}

static int ubc_lookup_cached_ubki(const struct silofs_uber_ctx *ub_ctx,
                                  const struct silofs_bkaddr *bkaddr,
                                  struct silofs_ubk_info **out_ubki)
{
	*out_ubki = silofs_cache_lookup_ubk(ub_ctx->cache, bkaddr);
	return (*out_ubki == NULL) ? -SILOFS_ENOENT : 0;
}

static int ubc_create_cached_ubki(const struct silofs_uber_ctx *ub_ctx,
                                  const struct silofs_bkaddr *bkaddr,
                                  struct silofs_ubk_info **out_ubki)
{
	*out_ubki = silofs_cache_create_ubk(ub_ctx->cache, bkaddr);
	return (*out_ubki == NULL) ? -SILOFS_ENOMEM : 0;
}

static int ubc_require_bkaddr(const struct silofs_uber_ctx *ub_ctx,
                              const struct silofs_bkaddr *bkaddr)
{
	return silofs_repo_require_laddr(ub_ctx->repo, &bkaddr->laddr);
}

static int ubc_spawn_ubk_at(const struct silofs_uber_ctx *ub_ctx,
                            const struct silofs_bkaddr *bkaddr,
                            struct silofs_ubk_info **out_ubki)
{
	int err;

	err = ubc_lookup_cached_ubki(ub_ctx, bkaddr, out_ubki);
	if (!err) {
		return -SILOFS_EEXIST;
	}
	err = ubc_require_bkaddr(ub_ctx, bkaddr);
	if (err) {
		return err;
	}
	err = ubc_create_cached_ubki(ub_ctx, bkaddr, out_ubki);
	if (err) {
		return err;
	}
	return 0;
}

static int ubc_spawn_ubk(const struct silofs_uber_ctx *ub_ctx,
                         const struct silofs_bkaddr *bkaddr,
                         struct silofs_ubk_info **out_ubki)
{
	int err;

	err = ubc_require_lext_of(ub_ctx, bkaddr);
	if (err) {
		return err;
	}
	err = ubc_spawn_ubk_at(ub_ctx, bkaddr, out_ubki);
	if (err) {
		return err;
	}
	return 0;
}

static void ubc_forget_cached_ubki(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_ubk_info *ubki)
{
	silofs_cache_forget_ubk(ub_ctx->cache, ubki);
}

static int ubc_load_bk_of(const struct silofs_uber_ctx *ub_ctx,
                          const struct silofs_bkaddr *bkaddr,
                          struct silofs_ubk_info *ubki)
{
	return silofs_repo_read_at(ub_ctx->repo, &bkaddr->laddr,
	                           ubki->ubk.lbk);
}

static int ubc_do_stage_ubk_at(const struct silofs_uber_ctx *ub_ctx, bool sb,
                               const struct silofs_bkaddr *bkaddr,
                               struct silofs_ubk_info **out_ubki)
{
	struct silofs_ubk_info *ubki = NULL;
	int err;

	err = ubc_lookup_cached_ubki(ub_ctx, bkaddr, out_ubki);
	if (!err) {
		return 0;
	}
	err = ubc_stage_lext(ub_ctx, &bkaddr->laddr.lextid);
	if (err) {
		return err;
	}
	err = ubc_create_cached_ubki(ub_ctx, bkaddr, &ubki);
	if (err) {
		return err;
	}
	err = ubc_load_bk_of(ub_ctx, bkaddr, ubki);
	if (err) {
		ubc_forget_cached_ubki(ub_ctx, ubki);
		return err;
	}
	silofs_unused(sb);
	*out_ubki = ubki;
	return 0;
}

int silofs_stage_ubk_at(struct silofs_uber *uber,
                        const struct silofs_laddr *laddr,
                        struct silofs_ubk_info **out_ubki)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };
	struct silofs_bkaddr bkaddr;
	int err;

	ubc_setup(&ub_ctx);
	bkaddr_by_laddr(&bkaddr, laddr);
	err = ubc_do_stage_ubk_at(&ub_ctx, false, &bkaddr, out_ubki);
	if (err) {
		return err;
	}
	return 0;
}

static int ubc_stage_ubk_of(const struct silofs_uber_ctx *ub_ctx,
                            const struct silofs_bkaddr *bkaddr,
                            struct silofs_ubk_info **out_ubki)
{
	return ubc_do_stage_ubk_at(ub_ctx, false, bkaddr, out_ubki);
}

static int ubc_require_ubk(const struct silofs_uber_ctx *ub_ctx,
                           const struct silofs_bkaddr *bkaddr,
                           struct silofs_ubk_info **out_ubki)
{
	int err;

	err = ubc_require_bkaddr(ub_ctx, bkaddr);
	if (err) {
		return err;
	}
	err = ubc_require_lext_of(ub_ctx, bkaddr);
	if (err) {
		return err;
	}
	err = ubc_stage_ubk_of(ub_ctx, bkaddr, out_ubki);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int ubc_restore_view_of(const struct silofs_uber_ctx *ub_ctx,
                               struct silofs_unode_info *ui)
{
	return silofs_restore_uview(ub_ctx->uber, ui);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ubc_forget_cached_sbi(const struct silofs_uber_ctx *ub_ctx,
                                  struct silofs_sb_info *sbi)
{
	if (sbi != NULL) {
		ubc_forget_cached_ui(ub_ctx, &sbi->sb_ui);
	}
}

static int ubc_require_cached_sbi(const struct silofs_uber_ctx *ub_ctx,
                                  const struct silofs_ulink *ulink,
                                  struct silofs_sb_info **out_sbi)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = ubc_require_cached_ui(ub_ctx, ulink, &ui);
	if (err) {
		return err;
	}
	*out_sbi = silofs_sbi_from_ui(ui);
	sbi_set_uber(*out_sbi, ub_ctx->uber);
	return 0;
}

static int ubc_stage_attach_sbi_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_sb_info *sbi)
{
	struct silofs_bkaddr bkaddr = { .lba = SILOFS_LBA_NULL };
	struct silofs_ubk_info *ubki = NULL;
	int err;

	sbi_bkaddr(sbi, &bkaddr);
	sbi_incref(sbi);
	err = ubc_do_stage_ubk_at(ub_ctx, true, &bkaddr, &ubki);
	if (!err) {
		sbi_attach_to(sbi, ubki);
	}
	sbi_decref(sbi);
	return err;
}

static int ubc_spawn_attach_sbi_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_sb_info *sbi)
{
	struct silofs_bkaddr bkaddr;
	struct silofs_ubk_info *ubki = NULL;
	int err;

	sbi_bkaddr(sbi, &bkaddr);
	sbi_incref(sbi);
	err = ubc_spawn_ubk(ub_ctx, &bkaddr, &ubki);
	if (!err) {
		sbi_attach_to(sbi, ubki);
	}
	sbi_decref(sbi);
	return err;
}

static int ubc_spawn_super_at(const struct silofs_uber_ctx *ub_ctx,
                              const struct silofs_ulink *ulink,
                              struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = ubc_require_cached_sbi(ub_ctx, ulink, &sbi);
	if (err) {
		goto out_err;
	}
	if (sbi_is_stable(sbi)) {
		return -SILOFS_EEXIST;
	}
	err = ubc_spawn_attach_sbi_bk(ub_ctx, sbi);
	if (err) {
		goto out_err;
	}
	sbi_set_spawned(sbi);

	*out_sbi = sbi;
	return 0;
out_err:
	ubc_forget_cached_sbi(ub_ctx, sbi);
	*out_sbi = NULL;
	return err;
}

int silofs_spawn_super_at(struct silofs_uber *uber,
                          const struct silofs_ulink *ulink,
                          struct silofs_sb_info **out_sbi)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };

	ubc_setup(&ub_ctx);
	return ubc_spawn_super_at(&ub_ctx, ulink, out_sbi);
}

static int ubc_decrypt_view_of_sbi(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_sb_info *sbi)
{
	return ubc_restore_view_of(ub_ctx, &sbi->sb_ui);
}

static int ubc_stage_super_at(const struct silofs_uber_ctx *ub_ctx,
                              const struct silofs_ulink *ulink,
                              struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = ubc_require_cached_sbi(ub_ctx, ulink, &sbi);
	if (err) {
		goto out_err;
	}
	if (sbi_is_stable(sbi)) {
		goto out_ok;
	}
	err = ubc_stage_attach_sbi_bk(ub_ctx, sbi);
	if (err) {
		goto out_err;
	}

	err = ubc_decrypt_view_of_sbi(ub_ctx, sbi);
	if (err) {
		goto out_err;
	}
	err = sbi_verify_view(sbi);
	if (err) {
		goto out_err;
	}
out_ok:
	*out_sbi = sbi;
	return 0;
out_err:
	ubc_forget_cached_sbi(ub_ctx, sbi);
	*out_sbi = NULL;
	return err;
}

int silofs_stage_super_at(struct silofs_uber *uber,
                          const struct silofs_ulink *ulink,
                          struct silofs_sb_info **out_sbi)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };

	ubc_setup(&ub_ctx);
	return ubc_stage_super_at(&ub_ctx, ulink, out_sbi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ubc_forget_cached_sni(const struct silofs_uber_ctx *ub_ctx,
                                  struct silofs_spnode_info *sni)
{
	if (sni != NULL) {
		ubc_forget_cached_ui(ub_ctx, &sni->sn_ui);
	}
}

static int ubc_require_cached_sni(const struct silofs_uber_ctx *ub_ctx,
                                  const struct silofs_ulink *ulink,
                                  struct silofs_spnode_info **out_sni)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = ubc_require_cached_ui(ub_ctx, ulink, &ui);
	if (err) {
		return err;
	}
	*out_sni = silofs_sni_from_ui(ui);
	sni_set_uber(*out_sni, ub_ctx->uber);
	return 0;
}

static int ubc_stage_attach_sni_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_spnode_info *sni)
{
	struct silofs_bkaddr bkaddr = { .lba = SILOFS_LBA_NULL };
	struct silofs_ubk_info *ubki = NULL;
	int err;

	sni_bkaddr(sni, &bkaddr);
	sni_incref(sni);
	err = ubc_do_stage_ubk_at(ub_ctx, false, &bkaddr, &ubki);
	if (!err) {
		sni_attach_to(sni, ubki);
	}
	sni_decref(sni);
	return err;
}

static int ubc_require_attach_sni_bk(const struct silofs_uber_ctx *ub_ctx,
                                     struct silofs_spnode_info *sni)
{
	struct silofs_bkaddr bkaddr;
	struct silofs_ubk_info *ubki = NULL;
	int err;

	sni_bkaddr(sni, &bkaddr);
	sni_incref(sni);
	err = ubc_require_ubk(ub_ctx, &bkaddr, &ubki);
	if (!err) {
		sni_attach_to(sni, ubki);
	}
	sni_decref(sni);
	return err;
}

static int ubc_spawn_spnode_at(const struct silofs_uber_ctx *ub_ctx,
                               const struct silofs_ulink *ulink,
                               struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni = NULL;
	int err;

	err = ubc_require_cached_sni(ub_ctx, ulink, &sni);
	if (err) {
		goto out_err;
	}
	if (sni_is_stable(sni)) {
		return -SILOFS_EEXIST;
	}
	err = ubc_require_attach_sni_bk(ub_ctx, sni);
	if (err) {
		goto out_err;
	}
	sni_set_spawned(sni);

	*out_sni = sni;
	return 0;
out_err:
	ubc_forget_cached_sni(ub_ctx, sni);
	*out_sni = NULL;
	return err;
}

int silofs_spawn_spnode_at(struct silofs_uber *uber,
                           const struct silofs_ulink *ulink,
                           struct silofs_spnode_info **out_sni)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };

	ubc_setup(&ub_ctx);
	return ubc_spawn_spnode_at(&ub_ctx, ulink, out_sni);
}

static int ubc_decrypt_view_of_sni(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_spnode_info *sni)
{
	return ubc_restore_view_of(ub_ctx, &sni->sn_ui);
}

static int ubc_stage_spnode_at(const struct silofs_uber_ctx *ub_ctx,
                               const struct silofs_ulink *ulink,
                               struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni = NULL;
	int err;

	err = ubc_require_cached_sni(ub_ctx, ulink, &sni);
	if (err) {
		goto out_err;
	}
	if (sni_is_stable(sni)) {
		goto out_ok;
	}
	err = ubc_stage_attach_sni_bk(ub_ctx, sni);
	if (err) {
		goto out_err;
	}
	err = ubc_decrypt_view_of_sni(ub_ctx, sni);
	if (err) {
		goto out_err;
	}
	err = sni_verify_view(sni);
	if (err) {
		goto out_err;
	}
	silofs_sni_update_staged(sni);
out_ok:
	*out_sni = sni;
	return 0;
out_err:
	ubc_forget_cached_sni(ub_ctx, sni);
	*out_sni = NULL;
	return err;
}

int silofs_stage_spnode_at(struct silofs_uber *uber,
                           const struct silofs_ulink *ulink,
                           struct silofs_spnode_info **out_sni)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };

	ubc_setup(&ub_ctx);
	return ubc_stage_spnode_at(&ub_ctx, ulink, out_sni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ubc_forget_cached_sli(const struct silofs_uber_ctx *ub_ctx,
                                  struct silofs_spleaf_info *sli)
{
	if (sli != NULL) {
		ubc_forget_cached_ui(ub_ctx, &sli->sl_ui);
	}
}

static int ubc_require_cached_sli(const struct silofs_uber_ctx *ub_ctx,
                                  const struct silofs_ulink *ulink,
                                  struct silofs_spleaf_info **out_sli)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = ubc_require_cached_ui(ub_ctx, ulink, &ui);
	if (err) {
		return err;
	}
	*out_sli = silofs_sli_from_ui(ui);
	sli_set_uber(*out_sli, ub_ctx->uber);
	return 0;
}

static int ubc_stage_attach_sli_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_spleaf_info *sli)
{
	struct silofs_bkaddr bkaddr = { .lba = SILOFS_LBA_NULL };
	struct silofs_ubk_info *ubki = NULL;
	int err;

	sli_bkaddr(sli, &bkaddr);
	sli_incref(sli);
	err = ubc_do_stage_ubk_at(ub_ctx, false, &bkaddr, &ubki);
	if (!err) {
		sli_attach_to(sli, ubki);
	}
	sli_decref(sli);
	return err;
}

static int ubc_require_attach_sli_bk(const struct silofs_uber_ctx *ub_ctx,
                                     struct silofs_spleaf_info *sli)
{
	struct silofs_bkaddr bkaddr;
	struct silofs_ubk_info *ubki = NULL;
	int err;

	sli_bkaddr(sli, &bkaddr);
	sli_incref(sli);
	err = ubc_require_ubk(ub_ctx, &bkaddr, &ubki);
	if (!err) {
		sli_attach_to(sli, ubki);
	}
	sli_decref(sli);
	return err;
}

static int ubc_spawn_spleaf_at(const struct silofs_uber_ctx *ub_ctx,
                               const struct silofs_ulink *ulink,
                               struct silofs_spleaf_info **out_sli)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = ubc_require_cached_sli(ub_ctx, ulink, &sli);
	if (err) {
		goto out_err;
	}
	if (sli_is_stable(sli)) {
		return -SILOFS_EEXIST;
	}
	err = ubc_require_attach_sli_bk(ub_ctx, sli);
	if (err) {
		goto out_err;
	}
	sli_set_spawned(sli);

	*out_sli = sli;
	return 0;
out_err:
	ubc_forget_cached_sli(ub_ctx, sli);
	*out_sli = NULL;
	return err;
}

int silofs_spawn_spleaf_at(struct silofs_uber *uber,
                           const struct silofs_ulink *ulink,
                           struct silofs_spleaf_info **out_sli)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };

	ubc_setup(&ub_ctx);
	return ubc_spawn_spleaf_at(&ub_ctx, ulink, out_sli);
}

static int ubc_decrypt_view_of_sli(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_spleaf_info *sli)
{
	return ubc_restore_view_of(ub_ctx, &sli->sl_ui);
}

static int ubc_stage_spleaf_at(const struct silofs_uber_ctx *ub_ctx,
                               const struct silofs_ulink *ulink,
                               struct silofs_spleaf_info **out_sli)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = ubc_require_cached_sli(ub_ctx, ulink, &sli);
	if (err) {
		goto out_err;
	}
	if (sli_is_stable(sli)) {
		goto out_ok;
	}
	err = ubc_stage_attach_sli_bk(ub_ctx, sli);
	if (err) {
		goto out_err;
	}
	err = ubc_decrypt_view_of_sli(ub_ctx, sli);
	if (err) {
		goto out_err;
	}
	err = sli_verify_view(sli);
	if (err) {
		goto out_err;
	}
	silofs_sli_update_staged(sli);
out_ok:
	*out_sli = sli;
	return 0;
out_err:
	ubc_forget_cached_sli(ub_ctx, sli);
	*out_sli = NULL;
	return err;
}

int silofs_stage_spleaf_at(struct silofs_uber *uber,
                           const struct silofs_ulink *ulink,
                           struct silofs_spleaf_info **out_sli)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };

	ubc_setup(&ub_ctx);
	return ubc_stage_spleaf_at(&ub_ctx, ulink, out_sli);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int ubc_require_no_lext(const struct silofs_uber_ctx *ub_ctx,
                               const struct silofs_lextid *lextid)
{
	int err;

	err = ubc_lookup_lext(ub_ctx, lextid);
	if (!err) {
		return -SILOFS_EEXIST;
	}
	if (err != -SILOFS_ENOENT) {
		return err;
	}
	return 0;
}

int silofs_spawn_lext_at(struct silofs_uber *uber,
                         const struct silofs_lextid *lextid)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };
	int err;

	ubc_setup(&ub_ctx);
	err = ubc_require_no_lext(&ub_ctx, lextid);
	if (err) {
		return err;
	}
	err = ubc_spawn_lext(&ub_ctx, lextid);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_stage_lext_at(struct silofs_uber *uber,
                         const struct silofs_lextid *lextid)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };
	int err;

	ubc_setup(&ub_ctx);
	err = ubc_lookup_lext(&ub_ctx, lextid);
	if (err) {
		return err;
	}
	err = ubc_stage_lext(&ub_ctx, lextid);
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
