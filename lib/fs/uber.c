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

static const struct silofs_blobid *blobid_of(const struct silofs_uaddr *uaddr)
{
	return &uaddr->oaddr.bka.blobid;
}

static struct silofs_blobf *
sbi_blobref(const struct silofs_sb_info *sbi)
{
	return sbi->sb_ui.u_ubki->ubk_blobf;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void uber_bind_blobf(struct silofs_uber *uber,
                            struct silofs_blobf *blobf_new)
{
	struct silofs_blobf *blobf_cur = uber->ub_sb_blobf;

	if (blobf_cur != NULL) {
		silofs_blobf_funlock(blobf_cur);
		silofs_blobf_decref(blobf_cur);
	}
	if (blobf_new != NULL) {
		silofs_blobf_incref(blobf_new);
		silofs_blobf_flock(blobf_new);
	}
	uber->ub_sb_blobf = blobf_new;
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
	uber->ub_owner.pid = fs_args->pid;
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
	lim = (st.nbytes_max / (2 * SILOFS_BK_SIZE));
	return div_round_up(lim, align) * align;
}

static void uber_init_commons(struct silofs_uber *uber,
                              const struct silofs_uber_base *ub_base)
{
	memcpy(&uber->ub, ub_base, sizeof(uber->ub));
	uber->ub_initime = silofs_time_now_monotonic();
	uber->ub_commit_id = 0;
	uber->ub_iconv = (iconv_t)(-1);
	uber->ub_sb_blobf = NULL;
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
	uber->ub_iconv = (iconv_t)(-1);
	uber->ub_sb_blobf = NULL;
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
		return errno ? -errno : -EOPNOTSUPP;
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
	uber_bind_blobf(uber, NULL);
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

static void make_super_blobid(struct silofs_blobid *out_blobid)
{
	struct silofs_treeid treeid;

	silofs_treeid_generate(&treeid);
	silofs_blobid_setup(out_blobid, &treeid, 0,
	                    SILOFS_STYPE_SUPER, SILOFS_HEIGHT_SUPER);
}

static void make_super_uaddr(const struct silofs_blobid *blobid,
                             struct silofs_uaddr *out_uaddr)
{
	silofs_assert_eq(blobid->height, SILOFS_HEIGHT_SUPER);
	uaddr_setup(out_uaddr, blobid, 0, SILOFS_STYPE_SUPER, 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_uber_set_sbaddr(struct silofs_uber *uber,
                            const struct silofs_uaddr *sb_addr)
{
	uaddr_assign(&uber->ub_sb_addr, sb_addr);
}

static int uber_spawn_super_at(struct silofs_uber *uber,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = silofs_spawn_super_at(uber, uaddr, &sbi);
	if (err) {
		return err;
	}
	silofs_sbi_setup_spawned(sbi);
	silofs_sbi_bind_uber(sbi, uber);

	*out_sbi = sbi;
	return 0;
}

static int uber_spawn_super_of(struct silofs_uber *uber,
                               struct silofs_sb_info **out_sbi)
{
	struct silofs_blobid blobid = { .size = 0 };
	struct silofs_uaddr uaddr = { .voff = -1 };

	make_super_blobid(&blobid);
	make_super_uaddr(&blobid, &uaddr);

	return uber_spawn_super_at(uber, &uaddr, out_sbi);
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

static int uber_stage_super_at(struct silofs_uber *uber,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_sb_info **out_sbi)
{
	int err;

	err = silofs_stage_super_at(uber, uaddr, out_sbi);
	if (err) {
		return err;
	}
	silofs_sbi_bind_uber(*out_sbi, uber);
	return 0;
}

static int uber_stage_super(struct silofs_uber *uber,
                            const struct silofs_uaddr *uaddr,
                            struct silofs_sb_info **out_sbi)
{
	return uber_stage_super_at(uber, uaddr, out_sbi);
}

static void sbi_account_super_of(struct silofs_sb_info *sbi)
{
	struct silofs_stats_info *sti = &sbi->sb_sti;

	silofs_sti_update_blobs(sti, SILOFS_STYPE_SUPER, 1);
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
	const struct silofs_uaddr *sb_uaddr = &uber->ub_sb_addr;
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = uber_stage_super(uber, sb_uaddr, &sbi);
	if (err) {
		return err;
	}
	uber_bind_sbi(uber, sbi);
	return 0;
}

int silofs_uber_reload_sblob(struct silofs_uber *uber)
{
	const struct silofs_uaddr *sb_uaddr = &uber->ub_sb_addr;
	struct silofs_blobf *blobf = NULL;
	int err;

	err = silofs_stage_blob_at(uber, blobid_of(sb_uaddr), &blobf);
	if (err) {
		return err;
	}
	err = silofs_blobf_flock(blobf);
	if (err) {
		return err;
	}
	uber_bind_blobf(uber, blobf);
	return 0;
}

static void sbi_make_clone(struct silofs_sb_info *sbi_new,
                           const struct silofs_sb_info *sbi_cur)
{
	struct silofs_stats_info *sti_new = &sbi_new->sb_sti;
	const struct silofs_stats_info *sti_cur = &sbi_cur->sb_sti;

	silofs_sbi_make_clone(sbi_new, sbi_cur);
	silofs_sti_make_clone(sti_new, sti_cur);
	silofs_sti_renew_stats(sti_new);
	silofs_sbi_setup_ctime(sbi_new);

	sbi_account_super_of(sbi_new);
}

void silofs_uber_shut(struct silofs_uber *uber)
{
	uber_bind_sbi(uber, NULL);
	uber_bind_blobf(uber, NULL);
}

static void uber_rebind_root_sb(struct silofs_uber *uber,
                                struct silofs_sb_info *sbi)
{
	silofs_uber_set_sbaddr(uber, sbi_uaddr(sbi));
	uber_bind_blobf(uber, sbi_blobref(sbi));
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

static void sbi_export_bootsec(const struct silofs_sb_info *sbi,
                               struct silofs_bootsec *bsec)
{
	silofs_bootsec_init(bsec);
	silofs_bootsec_set_sb_uaddr(bsec, sbi_uaddr(sbi));
}

static void uber_pre_forkfs(struct silofs_uber *uber)
{
	silofs_cache_forget_uaddrs(uber->ub.cache);
}

int silofs_uber_forkfs(struct silofs_uber *uber,
                       struct silofs_bootsecs *out_bsecs)
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
	sbi_export_bootsec(sbi_alt, &out_bsecs->bsec[1]);

	uber_pre_forkfs(uber);
	err = uber_clone_rebind_super(uber, sbi_cur, &sbi_new);
	if (err) {
		return err;
	}
	sbi_export_bootsec(sbi_new, &out_bsecs->bsec[0]);

	sbi_mark_fossil(sbi_cur);
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void ui_stamp_mark_visible(struct silofs_unode_info *ui)
{
	silofs_zero_stamp_meta(ui->u_si.s_view, ui_stype(ui));
	ui->u_verified = true;
}

static const struct silofs_bkaddr *
sbi_bkaddr(const struct silofs_sb_info *sbi)
{
	return ui_bkaddr(&sbi->sb_ui);
}

static bool sbi_is_stable(const struct silofs_sb_info *sbi)
{
	return (sbi->sb_ui.u_ubki != NULL) && (sbi->sb != NULL);
}

static void sbi_attach_to(struct silofs_sb_info *sbi,
                          struct silofs_ubk_info *ubki)
{
	silofs_ui_attach_to(&sbi->sb_ui, ubki);
	sbi->sb = &sbi->sb_ui.u_si.s_view->sb;
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

static const struct silofs_bkaddr *
sni_bkaddr(const struct silofs_spnode_info *sni)
{
	return ui_bkaddr(&sni->sn_ui);
}

static bool sni_is_stable(const struct silofs_spnode_info *sni)
{
	return (sni->sn_ui.u_ubki != NULL) && (sni->sn != NULL);
}

static void sni_attach_to(struct silofs_spnode_info *sni,
                          struct silofs_ubk_info *ubki)
{
	silofs_ui_attach_to(&sni->sn_ui, ubki);
	sni->sn = &sni->sn_ui.u_si.s_view->sn;
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

static const struct silofs_bkaddr *
sli_bkaddr(const struct silofs_spleaf_info *sli)
{
	return ui_bkaddr(&sli->sl_ui);
}

static bool sli_is_stable(const struct silofs_spleaf_info *sli)
{
	return (sli->sl_ui.u_ubki != NULL) && (sli->sl != NULL);
}

static void sli_attach_to(struct silofs_spleaf_info *sli,
                          struct silofs_ubk_info *ubki)
{
	silofs_ui_attach_to(&sli->sl_ui, ubki);
	sli->sl = &sli->sl_ui.u_si.s_view->sl;
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

static int ubc_stage_cached_ui(const struct silofs_uber_ctx *ub_ctx,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_unode_info **out_ui)
{
	*out_ui = silofs_cache_lookup_ui(ub_ctx->cache, uaddr);
	return (*out_ui == NULL) ? -ENOENT : 0;
}

static void ubc_bind_spawned_ui(const struct silofs_uber_ctx *ub_ctx,
                                struct silofs_unode_info *ui)
{
	ui->u_si.s_md = ub_ctx->mdigest;
	ui->u_repo = ub_ctx->repo;
}

static int ubc_spawn_cached_ui(const struct silofs_uber_ctx *ub_ctx,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_unode_info **out_ui)
{
	*out_ui = silofs_cache_spawn_ui(ub_ctx->cache, uaddr);
	if (*out_ui == NULL) {
		return -ENOMEM;
	}
	ubc_bind_spawned_ui(ub_ctx, *out_ui);
	return 0;
}

static int ubc_require_cached_ui(const struct silofs_uber_ctx *ub_ctx,
                                 const struct silofs_uaddr *uaddr,
                                 struct silofs_unode_info **out_ui)
{
	int ret;

	ret = ubc_stage_cached_ui(ub_ctx, uaddr, out_ui);
	if (ret == -ENOENT) {
		ret = ubc_spawn_cached_ui(ub_ctx, uaddr, out_ui);
	}
	return ret;
}

static void ubc_forget_cached_ui(const struct silofs_uber_ctx *ub_ctx,
                                 struct silofs_unode_info *ui)
{
	silofs_cache_forget_ui(ub_ctx->cache, ui);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool ubc_blobid_rw_mode(const struct silofs_uber_ctx *ub_ctx,
                               const struct silofs_blobid *blobid)
{
	const struct silofs_sb_info *sbi = ub_ctx->uber->ub_sbi;

	return likely(sbi) ? silofs_sbi_ismutable_blobid(sbi, blobid) : true;
}

static bool ubc_bkaddr_rw_mode(const struct silofs_uber_ctx *ub_ctx,
                               const struct silofs_bkaddr *bkaddr)
{
	return ubc_blobid_rw_mode(ub_ctx, &bkaddr->blobid);
}

static int ubc_lookup_blob(const struct silofs_uber_ctx *ub_ctx,
                           const struct silofs_blobid *blobid)
{
	return silofs_repo_lookup_blob(ub_ctx->repo, blobid);
}

static int ubc_stage_blob(const struct silofs_uber_ctx *ub_ctx,
                          const struct silofs_blobid *blobid,
                          struct silofs_blobf **out_blobf)
{
	int err;
	const bool rw_mode = ubc_blobid_rw_mode(ub_ctx, blobid);

	err = silofs_repo_stage_blob(ub_ctx->repo, rw_mode, blobid, out_blobf);
	if (err && (err != -ENOENT)) {
		log_dbg("stage blob failed: err=%d", err);
	}
	return err;
}

static int ubc_spawn_blob(const struct silofs_uber_ctx *ub_ctx,
                          const struct silofs_blobid *blobid,
                          struct silofs_blobf **out_blobf)
{
	int err;

	err = silofs_repo_spawn_blob(ub_ctx->repo, blobid, out_blobf);
	if (err && (err != -ENOENT)) {
		log_dbg("spawn blob failed: err=%d", err);
	}
	return err;
}

static int ubc_require_blob(const struct silofs_uber_ctx *ub_ctx,
                            const struct silofs_blobid *blobid,
                            struct silofs_blobf **out_blobf)
{
	int err;

	err = ubc_lookup_blob(ub_ctx, blobid);
	if (!err) {
		err = ubc_stage_blob(ub_ctx, blobid, out_blobf);
	} else if (err == -ENOENT) {
		err = ubc_spawn_blob(ub_ctx, blobid, out_blobf);
	}
	return err;
}

static int ubc_spawn_ubk_at(const struct silofs_uber_ctx *ub_ctx,
                            const struct silofs_bkaddr *bkaddr,
                            struct silofs_blobf *blobf,
                            struct silofs_ubk_info **out_ubki)
{
	int err;
	const bool rw_mode = ubc_bkaddr_rw_mode(ub_ctx, bkaddr);

	blobf_incref(blobf);
	err = silofs_repo_spawn_ubk(ub_ctx->repo, rw_mode, bkaddr, out_ubki);
	blobf_decref(blobf);
	return err;
}

static int ubc_spawn_ubk(const struct silofs_uber_ctx *ub_ctx,
                         const struct silofs_bkaddr *bkaddr,
                         struct silofs_ubk_info **out_ubki)
{
	struct silofs_blobf *blobf = NULL;
	int err;

	err = ubc_require_blob(ub_ctx, &bkaddr->blobid, &blobf);
	if (err) {
		return err;
	}
	err = ubc_spawn_ubk_at(ub_ctx, bkaddr, blobf, out_ubki);
	if (err) {
		return err;
	}
	return 0;
}

static int ubc_do_require_ubk_at(const struct silofs_uber_ctx *ub_ctx,
                                 const struct silofs_bkaddr *bkaddr,
                                 struct silofs_ubk_info **out_ubki)
{
	return silofs_repo_require_ubk(ub_ctx->repo, bkaddr, out_ubki);
}

static int ubc_require_ubk_at(const struct silofs_uber_ctx *ub_ctx,
                              const struct silofs_bkaddr *bkaddr,
                              struct silofs_blobf *blobf,
                              struct silofs_ubk_info **out_ubki)
{
	int err;

	blobf_incref(blobf);
	err = ubc_do_require_ubk_at(ub_ctx, bkaddr, out_ubki);
	blobf_decref(blobf);
	return err;
}

static int ubc_require_ubk(const struct silofs_uber_ctx *ub_ctx,
                           const struct silofs_bkaddr *bkaddr,
                           struct silofs_ubk_info **out_ubki)
{
	struct silofs_blobf *blobf = NULL;
	int err;

	err = ubc_require_blob(ub_ctx, &bkaddr->blobid, &blobf);
	if (err) {
		return err;
	}
	err = silofs_blobf_require_bk(blobf, bkaddr);
	if (err) {
		return err;
	}
	err = ubc_require_ubk_at(ub_ctx, bkaddr, blobf, out_ubki);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int ubc_do_stage_ubk_at(const struct silofs_uber_ctx *ub_ctx, bool sb,
                               const struct silofs_bkaddr *bkaddr,
                               struct silofs_ubk_info **out_ubki)
{
	const bool rw = sb ? true : ubc_bkaddr_rw_mode(ub_ctx, bkaddr);

	return silofs_repo_stage_ubk(ub_ctx->repo, rw, bkaddr, out_ubki);
}

int silofs_stage_ubk_at(struct silofs_uber *uber,
                        const struct silofs_bkaddr *bkaddr,
                        struct silofs_ubk_info **out_ubki)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };
	int err;

	ubc_setup(&ub_ctx);
	err = ubc_do_stage_ubk_at(&ub_ctx, false, bkaddr, out_ubki);
	if (err) {
		return err;
	}
	return 0;
}

static int ubc_restore_view_of(const struct silofs_uber_ctx *ub_ctx,
                               struct silofs_unode_info *ui)
{
	return silofs_restore_ui_view(ub_ctx->uber, ui);
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
                                  const struct silofs_uaddr *uaddr,
                                  struct silofs_sb_info **out_sbi)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = ubc_require_cached_ui(ub_ctx, uaddr, &ui);
	if (!err) {
		*out_sbi = silofs_sbi_from_ui(ui);
	}
	return err;
}

static int ubc_stage_attach_sbi_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_sb_info *sbi)
{
	struct silofs_ubk_info *ubki = NULL;
	int err;

	sbi_incref(sbi);
	err = ubc_do_stage_ubk_at(ub_ctx, true, sbi_bkaddr(sbi), &ubki);
	if (!err) {
		sbi_attach_to(sbi, ubki);
	}
	sbi_decref(sbi);
	return err;
}

static int ubc_spawn_attach_sbi_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_sb_info *sbi)
{
	struct silofs_ubk_info *ubki = NULL;
	int err;

	sbi_incref(sbi);
	err = ubc_spawn_ubk(ub_ctx, sbi_bkaddr(sbi), &ubki);
	if (!err) {
		sbi_attach_to(sbi, ubki);
	}
	sbi_decref(sbi);
	return err;
}

static int ubc_spawn_super_at(const struct silofs_uber_ctx *ub_ctx,
                              const struct silofs_uaddr *uaddr,
                              struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = ubc_require_cached_sbi(ub_ctx, uaddr, &sbi);
	if (err) {
		goto out_err;
	}
	if (sbi_is_stable(sbi)) {
		return -EEXIST;
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
                          const struct silofs_uaddr *uaddr,
                          struct silofs_sb_info **out_sbi)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };

	ubc_setup(&ub_ctx);
	return ubc_spawn_super_at(&ub_ctx, uaddr, out_sbi);
}

static int ubc_decrypt_view_of_sbi(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_sb_info *sbi)
{
	return ubc_restore_view_of(ub_ctx, &sbi->sb_ui);
}

static int ubc_stage_super_at(const struct silofs_uber_ctx *ub_ctx,
                              const struct silofs_uaddr *uaddr,
                              struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = ubc_require_cached_sbi(ub_ctx, uaddr, &sbi);
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
                          const struct silofs_uaddr *uaddr,
                          struct silofs_sb_info **out_sbi)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };

	ubc_setup(&ub_ctx);
	return ubc_stage_super_at(&ub_ctx, uaddr, out_sbi);
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
                                  const struct silofs_uaddr *uaddr,
                                  struct silofs_spnode_info **out_sni)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = ubc_require_cached_ui(ub_ctx, uaddr, &ui);
	if (!err) {
		*out_sni = silofs_sni_from_ui(ui);
	}
	return err;
}

static int ubc_stage_attach_sni_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_spnode_info *sni)
{
	struct silofs_ubk_info *ubki = NULL;
	const struct silofs_bkaddr *bkaddr = sni_bkaddr(sni);
	int err;

	sni_incref(sni);
	err = ubc_do_stage_ubk_at(ub_ctx, false, bkaddr, &ubki);
	if (!err) {
		sni_attach_to(sni, ubki);
	}
	sni_decref(sni);
	return err;
}

static int ubc_require_attach_sni_bk(const struct silofs_uber_ctx *ub_ctx,
                                     struct silofs_spnode_info *sni)
{
	struct silofs_ubk_info *ubki = NULL;
	int err;

	sni_incref(sni);
	err = ubc_require_ubk(ub_ctx, sni_bkaddr(sni), &ubki);
	if (!err) {
		sni_attach_to(sni, ubki);
	}
	sni_decref(sni);
	return err;
}

static int ubc_spawn_spnode_at(const struct silofs_uber_ctx *ub_ctx,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni = NULL;
	int err;

	err = ubc_require_cached_sni(ub_ctx, uaddr, &sni);
	if (err) {
		goto out_err;
	}
	if (sni_is_stable(sni)) {
		return -EEXIST;
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
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spnode_info **out_sni)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };

	ubc_setup(&ub_ctx);
	return ubc_spawn_spnode_at(&ub_ctx, uaddr, out_sni);
}

static int ubc_decrypt_view_of_sni(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_spnode_info *sni)
{
	return ubc_restore_view_of(ub_ctx, &sni->sn_ui);
}

static int ubc_stage_spnode_at(const struct silofs_uber_ctx *ub_ctx,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni = NULL;
	int err;

	err = ubc_require_cached_sni(ub_ctx, uaddr, &sni);
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
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spnode_info **out_sni)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };


	ubc_setup(&ub_ctx);
	return ubc_stage_spnode_at(&ub_ctx, uaddr, out_sni);
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
                                  const struct silofs_uaddr *uaddr,
                                  struct silofs_spleaf_info **out_sli)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = ubc_require_cached_ui(ub_ctx, uaddr, &ui);
	if (!err) {
		*out_sli = silofs_sli_from_ui(ui);
	}
	return err;
}

static int ubc_stage_attach_sli_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_spleaf_info *sli)
{
	struct silofs_ubk_info *ubki = NULL;
	const struct silofs_bkaddr *bkaddr = sli_bkaddr(sli);
	int err;

	sli_incref(sli);
	err = ubc_do_stage_ubk_at(ub_ctx, false, bkaddr, &ubki);
	if (!err) {
		sli_attach_to(sli, ubki);
	}
	sli_decref(sli);
	return err;
}

static int ubc_require_attach_sli_bk(const struct silofs_uber_ctx *ub_ctx,
                                     struct silofs_spleaf_info *sli)
{
	struct silofs_ubk_info *ubki = NULL;
	int err;

	sli_incref(sli);
	err = ubc_require_ubk(ub_ctx, sli_bkaddr(sli), &ubki);
	if (!err) {
		sli_attach_to(sli, ubki);
	}
	sli_decref(sli);
	return err;
}

static int ubc_spawn_spleaf_at(const struct silofs_uber_ctx *ub_ctx,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_spleaf_info **out_sli)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = ubc_require_cached_sli(ub_ctx, uaddr, &sli);
	if (err) {
		goto out_err;
	}
	if (sli_is_stable(sli)) {
		return -EEXIST;
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
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spleaf_info **out_sli)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };

	ubc_setup(&ub_ctx);
	return ubc_spawn_spleaf_at(&ub_ctx, uaddr, out_sli);
}

static int ubc_decrypt_view_of_sli(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_spleaf_info *sli)
{
	return ubc_restore_view_of(ub_ctx, &sli->sl_ui);
}

static int ubc_stage_spleaf_at(const struct silofs_uber_ctx *ub_ctx,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_spleaf_info **out_sli)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = ubc_require_cached_sli(ub_ctx, uaddr, &sli);
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
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spleaf_info **out_sli)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };

	ubc_setup(&ub_ctx);
	return ubc_stage_spleaf_at(&ub_ctx, uaddr, out_sli);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int ubc_require_no_blob(const struct silofs_uber_ctx *ub_ctx,
                               const struct silofs_blobid *blobid)
{
	int err;

	err = ubc_lookup_blob(ub_ctx, blobid);
	if (!err) {
		return -EEXIST;
	}
	if (err != -ENOENT) {
		return err;
	}
	return 0;
}

int silofs_spawn_blob_at(struct silofs_uber *uber,
                         const struct silofs_blobid *blobid,
                         struct silofs_blobf **out_blobf)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };
	int err;

	ubc_setup(&ub_ctx);
	err = ubc_require_no_blob(&ub_ctx, blobid);
	if (err) {
		return err;
	}
	err = ubc_spawn_blob(&ub_ctx, blobid, out_blobf);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_stage_blob_at(struct silofs_uber *uber,
                         const struct silofs_blobid *blobid,
                         struct silofs_blobf **out_blobf)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };
	int err;

	ubc_setup(&ub_ctx);
	err = ubc_lookup_blob(&ub_ctx, blobid);
	if (err) {
		return err;
	}
	err = ubc_stage_blob(&ub_ctx, blobid, out_blobf);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_relax_cache_by(struct silofs_task *task, int flags)
{
	silofs_cache_relax(task->t_uber->ub.cache, flags);
}

