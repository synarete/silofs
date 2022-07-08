/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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
#include <silofs/fs/private.h>

struct silofs_uber_ctx {
	struct silofs_fs_uber     *uber;
	struct silofs_repo        *repo;
	struct silofs_cache       *cache;
	struct silofs_mdigest     *mdigest;
};


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_uaddr *
spi_uaddr(const struct silofs_spstats_info *spi)
{
	return &spi->sp_ui.u_uaddr;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t uber_calc_iopen_limit(const struct silofs_fs_uber *uber)
{
	struct silofs_alloc_stat st;
	const size_t align = 128;
	size_t lim;

	silofs_allocstat(uber->ub_alloc, &st);
	lim = (st.memsz_data / (2 * SILOFS_BK_SIZE));
	return div_round_up(lim, align) * align;
}

static void uber_init_commons(struct silofs_fs_uber *uber,
                              struct silofs_repos *repos)
{
	uber->ub_initime = silofs_time_now_monotonic();
	uber->ub_repos = repos;
	uber->ub_alloc = repos->repo_warm.re_alloc;
	uber->ub_iconv = (iconv_t)(-1);
	uber->ub_sbi = NULL;
	uber->ub_slock_fd = -1;

	uber->ub_ops.op_iopen_max = 0;
	uber->ub_ops.op_iopen = 0;
	uber->ub_ops.op_time = silofs_time_now();
	uber->ub_ops.op_count = 0;
	uber->ub_ops.op_iopen_max = uber_calc_iopen_limit(uber);
}

static void uber_fini_commons(struct silofs_fs_uber *uber)
{
	silofs_sys_closefd(&uber->ub_slock_fd);
	uber->ub_repos = NULL;
	uber->ub_alloc = NULL;
	uber->ub_iconv = (iconv_t)(-1);
	uber->ub_sbi = NULL;
}

static int uber_init_piper(struct silofs_fs_uber *uber)
{
	return silofs_piper_init(&uber->ub_piper, SILOFS_BK_SIZE);
}

static void uber_fini_piper(struct silofs_fs_uber *uber)
{
	silofs_piper_fini(&uber->ub_piper);
}

static int uber_init_iconv(struct silofs_fs_uber *uber)
{
	/* Using UTF32LE to avoid BOM (byte-order-mark) character */
	uber->ub_iconv = iconv_open("UTF32LE", "UTF8");
	if (uber->ub_iconv == (iconv_t)(-1)) {
		return errno ? -errno : -EOPNOTSUPP;
	}
	return 0;
}

static void uber_fini_iconv(struct silofs_fs_uber *uber)
{
	if (uber->ub_iconv != (iconv_t)(-1)) {
		iconv_close(uber->ub_iconv);
		uber->ub_iconv = (iconv_t)(-1);
	}
}

int silofs_uber_init(struct silofs_fs_uber *uber, struct silofs_repos *repos)
{
	int err;

	uber_init_commons(uber, repos);
	err = uber_init_piper(uber);
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

void silofs_uber_fini(struct silofs_fs_uber *uber)
{
	uber_fini_iconv(uber);
	uber_fini_piper(uber);
	uber_fini_commons(uber);
}

time_t silofs_uber_uptime(const struct silofs_fs_uber *uber)
{
	const time_t now = silofs_time_now_monotonic();

	return now - uber->ub_initime;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_uber_relax_caches(const struct silofs_fs_uber *uber, int flags)
{
	if (uber->ub_sbi) {
		silofs_relax_inomap_of(uber->ub_sbi, flags);
	}
	if (uber->ub_repos->repo_warm.re_inited) {
		silofs_repo_relax_cache(&uber->ub_repos->repo_warm, flags);
	}
	if (uber->ub_repos->repo_cold.re_inited) {
		silofs_repo_relax_cache(&uber->ub_repos->repo_cold, flags);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void make_supers_blobid(struct silofs_blobid *out_blobid)
{
	struct silofs_treeid treeid;

	silofs_treeid_generate(&treeid);
	silofs_blobid_make_ta(out_blobid, &treeid, 0,
	                      SILOFS_HEIGHT_SUPER, SILOFS_STYPE_SUPER);
}

static void make_super_uaddr(const struct silofs_blobid *blobid,
                             struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr_setup(out_uaddr, blobid, 0,
	                   SILOFS_STYPE_SUPER, SILOFS_HEIGHT_SUPER, 0);
}

static void make_stats_uaddr(const struct silofs_blobid *blobid,
                             struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr_setup(out_uaddr, blobid, SILOFS_BK_SIZE,
	                   SILOFS_STYPE_SPSTATS, SILOFS_HEIGHT_SUPER, 0);
}

/*. . . . . . . . . . . . . . . b. . . . . . . . . . . . . . . . . . . . . .*/

static void uber_bind_sbi(struct silofs_fs_uber *uber,
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

static int uber_spawn_super_at(struct silofs_fs_uber *uber,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = silofs_spawn_super_at(uber, true, uaddr, &sbi);
	if (err) {
		return err;
	}
	silofs_sbi_setup_spawned(sbi);
	silofs_sbi_bind_uber(sbi, uber);

	*out_sbi = sbi;
	return 0;
}

static int uber_spawn_super_of(struct silofs_fs_uber *uber,
                               struct silofs_sb_info **out_sbi)
{
	struct silofs_blobid blobid = { .size = 0 };
	struct silofs_uaddr uaddr = { .voff = -1 };

	make_supers_blobid(&blobid);
	make_super_uaddr(&blobid, &uaddr);

	return uber_spawn_super_at(uber, &uaddr, out_sbi);
}

static int uber_spawn_stats_at(struct silofs_fs_uber *uber,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_spstats_info **out_spi)
{
	int err;

	err = silofs_spawn_stats_at(uber, true, uaddr, out_spi);
	if (err) {
		return err;
	}
	silofs_spi_setup_spawned(*out_spi);
	silofs_spi_bind_uber(*out_spi, uber);
	return 0;
}

static int uber_spawn_stats_of(struct silofs_fs_uber *uber,
                               struct silofs_sb_info *sbi,
                               struct silofs_spstats_info **out_spi)
{
	struct silofs_uaddr uaddr;
	int ret;

	make_stats_uaddr(sbi_blobid(sbi), &uaddr);
	sbi_incref(sbi);
	ret = uber_spawn_stats_at(uber, &uaddr, out_spi);
	sbi_decref(sbi);
	return ret;
}

int silofs_uber_spawn_supers(struct silofs_fs_uber *uber, size_t capacity,
                             struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = NULL;
	struct silofs_spstats_info *spi = NULL;
	int err;

	err = uber_spawn_super_of(uber, &sbi);
	if (err) {
		return err;
	}
	silofs_sbi_setup_btime(sbi);

	err = uber_spawn_stats_of(uber, sbi, &spi);
	if (err) {
		return err;
	}

	silofs_spi_set_capacity(spi, capacity);
	silofs_sbi_set_stats_uaddr(sbi, spi_uaddr(spi));
	silofs_sbi_bind_stats(sbi, spi);

	*out_sbi = sbi;
	return 0;
}

static int uber_stage_super_at(struct silofs_fs_uber *uber,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_sb_info **out_sbi)
{
	int err;

	err = silofs_stage_super_at(uber, true, uaddr, out_sbi);
	if (err) {
		return err;
	}
	silofs_sbi_bind_uber(*out_sbi, uber);
	return 0;
}

static int uber_stage_stats_at(struct silofs_fs_uber *uber,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_spstats_info **out_spi)
{
	int err;

	err = silofs_stage_stats_at(uber, true, uaddr, out_spi);
	if (err) {
		return err;
	}
	silofs_spi_bind_uber(*out_spi, uber);
	return 0;
}

static int uber_stage_stats_of(struct silofs_fs_uber *uber,
                               struct silofs_sb_info *sbi,
                               struct silofs_spstats_info **out_spi)
{
	struct silofs_uaddr uaddr;
	int err;

	err = silofs_sbi_stats_uaddr(sbi, &uaddr);
	if (!err) {
		sbi_incref(sbi);
		err = uber_stage_stats_at(uber, &uaddr, out_spi);
		sbi_decref(sbi);
	}
	return err;
}

int silofs_uber_stage_supers(struct silofs_fs_uber *uber,
                             const struct silofs_uaddr *uaddr,
                             struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = NULL;
	struct silofs_spstats_info *sti = NULL;
	int err;

	err = uber_stage_super_at(uber, uaddr, &sbi);
	if (err) {
		return err;
	}
	err = uber_stage_stats_of(uber, sbi, &sti);
	if (err) {
		return err;
	}
	silofs_sbi_bind_stats(sbi, sti);
	*out_sbi = sbi;
	return 0;
}

static void sbi_account_supers_of(struct silofs_sb_info *sbi)
{
	struct silofs_spstats_info *sti = sbi->sb_spi;

	silofs_spi_update_blobs(sti, SILOFS_STYPE_SUPER, 1);
	silofs_spi_update_bks(sti, SILOFS_STYPE_SUPER, 1);
	silofs_spi_update_bks(sti, SILOFS_STYPE_SPSTATS, 1);
	silofs_spi_update_objs(sti, SILOFS_STYPE_SUPER, 1);
	silofs_spi_update_objs(sti, SILOFS_STYPE_SPSTATS, 1);
}

int silofs_uber_format_supers(struct silofs_fs_uber *uber, size_t capacity)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = silofs_uber_spawn_supers(uber, capacity, &sbi);
	if (err) {
		return err;
	}
	sbi_account_supers_of(sbi);
	uber_bind_sbi(uber, sbi);
	return 0;
}

int silofs_uber_reload_supers(struct silofs_fs_uber *uber,
                              const struct silofs_uaddr *sb_uaddr)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = silofs_uber_stage_supers(uber, sb_uaddr, &sbi);
	if (err) {
		return err;
	}
	uber_bind_sbi(uber, sbi);
	return 0;
}

static void sbi_make_clone(struct silofs_sb_info *sbi_new,
                           const struct silofs_sb_info *sbi_cur)
{
	struct silofs_spstats_info *spi_new = sbi_new->sb_spi;
	struct silofs_spstats_info *spi_cur = sbi_cur->sb_spi;

	silofs_spi_make_clone(spi_new, spi_cur);
	silofs_sbi_make_clone(sbi_new, sbi_cur);
	silofs_sbi_set_stats_uaddr(sbi_new, spi_uaddr(spi_new));
	silofs_sbi_setup_ctime(sbi_new);

	sbi_account_supers_of(sbi_new);
}

void silofs_uber_shut(struct silofs_fs_uber *uber)
{
	uber_bind_sbi(uber, NULL);
}

static int uber_clone_rebind_supers(struct silofs_fs_uber *uber,
                                    const struct silofs_sb_info *sbi_cur,
                                    struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = silofs_uber_spawn_supers(uber, 0, &sbi);
	if (err) {
		return err;
	}
	sbi_make_clone(sbi, sbi_cur);
	uber_bind_sbi(uber, sbi);

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
	silofs_bootsec_set_uaddr(bsec, sbi_uaddr(sbi));
}

static void uber_pre_forkfs(struct silofs_fs_uber *uber)
{
	struct silofs_repos *repos = uber->ub_repos;
	struct silofs_cache *cache;

	if (uber->ub_repos->repo_warm.re_inited) {
		cache = &repos->repo_warm.re_cache;
		silofs_cache_forget_uaddrs(cache);
	}
	if (uber->ub_repos->repo_cold.re_inited) {
		cache = &repos->repo_cold.re_cache;
		silofs_cache_forget_uaddrs(cache);
	}
}

int silofs_uber_forkfs(struct silofs_fs_uber *uber,
                       struct silofs_bootsecs *out_bsecs)
{
	struct silofs_sb_info *sbi_alt = NULL;
	struct silofs_sb_info *sbi_new = NULL;
	struct silofs_sb_info *sbi_cur = uber->ub_sbi;
	int err;

	uber_pre_forkfs(uber);

	err = uber_clone_rebind_supers(uber, sbi_cur, &sbi_alt);
	if (err) {
		return err;
	}
	sbi_export_bootsec(sbi_alt, &out_bsecs->bsec[1]);

	err = uber_clone_rebind_supers(uber, sbi_cur, &sbi_new);
	if (err) {
		return err;
	}
	sbi_export_bootsec(sbi_new, &out_bsecs->bsec[0]);

	sbi_mark_fossil(sbi_cur);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_exec_kcopy_by(struct silofs_fs_uber *uber,
                         const struct silofs_xiovec *xiov_src,
                         const struct silofs_xiovec *xiov_dst, size_t len)
{
	struct silofs_piper *piper = &uber->ub_piper;
	loff_t off_src = xiov_src->xiov_off;
	loff_t off_dst = xiov_dst->xiov_off;
	int err;

	err = silofs_piper_kcopy(piper, xiov_src->xiov_fd, &off_src,
	                         xiov_dst->xiov_fd, &off_dst, len, 0);
	if (err) {
		silofs_piper_dispose(piper);
	}
	return err;
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
}

static int sbi_verify_view(struct silofs_sb_info *sbi)
{
	return silofs_ui_verify_view(&sbi->sb_ui);
}

static void sbi_set_spawned(struct silofs_sb_info *sbi)
{
	ui_stamp_mark_visible(&sbi->sb_ui);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_bkaddr *
spi_bkaddr(const struct silofs_spstats_info *spi)
{
	return ui_bkaddr(&spi->sp_ui);
}

static bool spi_is_stable(const struct silofs_spstats_info *spi)
{
	return (spi->sp_ui.u_ubki != NULL) && (spi->sp != NULL);
}

static void spi_attach_to(struct silofs_spstats_info *spi,
                          struct silofs_ubk_info *ubki)
{
	silofs_ui_attach_to(&spi->sp_ui, ubki);
	spi->sp = &spi->sp_ui.u_si.s_view->sp;
}

static int spi_verify_view(struct silofs_spstats_info *spi)
{
	return silofs_ui_verify_view(&spi->sp_ui);
}

static void spi_set_spawned(struct silofs_spstats_info *spi)
{
	ui_stamp_mark_visible(&spi->sp_ui);
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
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_repo *repo_of(struct silofs_fs_uber *uber, bool warm)
{
	return warm ? &uber->ub_repos->repo_warm : &uber->ub_repos->repo_cold;
}

static void ubc_setup(struct silofs_uber_ctx *ub_ctx, bool warm)
{
	struct silofs_fs_uber *uber = ub_ctx->uber;
	struct silofs_repo *repo = repo_of(uber, warm);

	ub_ctx->uber = uber;
	ub_ctx->repo = repo;
	ub_ctx->cache = &repo->re_cache;
	ub_ctx->mdigest = &repo->re_bootldr.btl_md;
}

static int ubc_spawn_cached_ubki(const struct silofs_uber_ctx *ub_ctx,
                                 const struct silofs_bkaddr *bkaddr,
                                 struct silofs_ubk_info **out_ubki)
{
	*out_ubki = silofs_cache_spawn_ubk(ub_ctx->cache, bkaddr);
	return (*out_ubki != NULL) ? 0 : -ENOMEM;
}

static int ubc_stage_cached_ui(const struct silofs_uber_ctx *ub_ctx,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_unode_info **out_ui)
{
	*out_ui = silofs_cache_lookup_unode(ub_ctx->cache, uaddr);
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
	*out_ui = silofs_cache_spawn_unode(ub_ctx->cache, uaddr);
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
	silofs_cache_forget_unode(ub_ctx->cache, ui);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int ubc_lookup_blob(const struct silofs_uber_ctx *ub_ctx,
                           const struct silofs_blobid *blobid)
{
	return silofs_repo_lookup_blob(ub_ctx->repo, blobid);
}

static int ubc_stage_blob(const struct silofs_uber_ctx *ub_ctx,
                          const struct silofs_blobid *blobid,
                          struct silofs_blob_info **out_bli)
{
	int err;

	err = silofs_repo_stage_blob(ub_ctx->repo, blobid, out_bli);
	if (err && (err != -ENOENT)) {
		log_dbg("stage blob failed: err=%d", err);
	}
	return err;
}

static int ubc_spawn_blob(const struct silofs_uber_ctx *ub_ctx,
                          const struct silofs_blobid *blobid,
                          struct silofs_blob_info **out_bli)
{
	int err;

	err = silofs_repo_spawn_blob(ub_ctx->repo, blobid, out_bli);
	if (err && (err != -ENOENT)) {
		log_dbg("spawn blob failed: err=%d", err);
	}
	return err;
}

static int ubc_require_blob(const struct silofs_uber_ctx *ub_ctx,
                            const struct silofs_blobid *blobid,
                            struct silofs_blob_info **out_bli)
{
	int err;

	err = ubc_lookup_blob(ub_ctx, blobid);
	if (!err) {
		err = ubc_stage_blob(ub_ctx, blobid, out_bli);
	} else if (err == -ENOENT) {
		err = ubc_spawn_blob(ub_ctx, blobid, out_bli);
	}
	return err;
}

static int ubc_spawn_ubk_at(const struct silofs_uber_ctx *ub_ctx,
                            const struct silofs_bkaddr *bkaddr,
                            struct silofs_blob_info *bli,
                            struct silofs_ubk_info **out_ubki)
{
	int err;

	bli_incref(bli);
	err = silofs_repo_spawn_ubk(ub_ctx->repo, bkaddr, out_ubki);
	bli_decref(bli);
	return err;
}

static int ubc_spawn_ubk(const struct silofs_uber_ctx *ub_ctx,
                         const struct silofs_bkaddr *bkaddr,
                         struct silofs_ubk_info **out_ubki)
{
	struct silofs_blob_info *bli = NULL;
	int err;

	err = ubc_require_blob(ub_ctx, &bkaddr->blobid, &bli);
	if (err) {
		return err;
	}
	err = ubc_spawn_ubk_at(ub_ctx, bkaddr, bli, out_ubki);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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
	err = silofs_repo_stage_ubk(ub_ctx->repo, sbi_bkaddr(sbi), &ubki);
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

static int ubc_attach_ghost_sbi_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_sb_info *sbi)
{
	struct silofs_ubk_info *ubki = NULL;
	int err;

	sbi_incref(sbi);
	err = ubc_spawn_cached_ubki(ub_ctx, sbi_bkaddr(sbi), &ubki);
	if (!err) {
		sbi_attach_to(sbi, ubki);
	}
	sbi_decref(sbi);
	return err;
}

int silofs_spawn_super_at(struct silofs_fs_uber *uber, bool warm,
                          const struct silofs_uaddr *uaddr,
                          struct silofs_sb_info **out_sbi)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };
	struct silofs_sb_info *sbi = NULL;
	int err;

	ubc_setup(&ub_ctx, warm);
	err = ubc_require_cached_sbi(&ub_ctx, uaddr, &sbi);
	if (err) {
		return err;
	}
	if (sbi_is_stable(sbi)) {
		return -EEXIST;
	}
	err = ubc_spawn_attach_sbi_bk(&ub_ctx, sbi);
	if (err) {
		return err;
	}
	sbi_set_spawned(sbi);
	*out_sbi = sbi;
	return 0;
}

int silofs_stage_super_at(struct silofs_fs_uber *uber, bool warm,
                          const struct silofs_uaddr *uaddr,
                          struct silofs_sb_info **out_sbi)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };
	int err;

	ubc_setup(&ub_ctx, warm);
	err = ubc_require_cached_sbi(&ub_ctx, uaddr, out_sbi);
	if (err) {
		return err;
	}
	if (sbi_is_stable(*out_sbi)) {
		return 0;
	}
	err = ubc_stage_attach_sbi_bk(&ub_ctx, *out_sbi);
	if (err) {
		return err;
	}
	err = sbi_verify_view(*out_sbi);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_shadow_super_at(struct silofs_fs_uber *uber, bool warm,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_sb_info **out_sbi)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };
	int err;

	ubc_setup(&ub_ctx, warm);
	err = ubc_require_cached_sbi(&ub_ctx, uaddr, out_sbi);
	if (err) {
		return err;
	}
	if (sbi_is_stable(*out_sbi)) {
		return 0;
	}
	err = ubc_attach_ghost_sbi_bk(&ub_ctx, *out_sbi);
	if (err) {
		return err;
	}
	sbi_set_spawned(*out_sbi);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ubc_forget_cached_spi(const struct silofs_uber_ctx *ub_ctx,
                                  struct silofs_spstats_info *spi)
{
	if (spi != NULL) {
		ubc_forget_cached_ui(ub_ctx, &spi->sp_ui);
	}
}

static int ubc_require_cached_spi(const struct silofs_uber_ctx *ub_ctx,
                                  const struct silofs_uaddr *uaddr,
                                  struct silofs_spstats_info **out_spi)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = ubc_require_cached_ui(ub_ctx, uaddr, &ui);
	if (!err) {
		*out_spi = silofs_spi_from_ui(ui);
	}
	return err;
}

static int ubc_stage_attach_spi_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_spstats_info *sti)
{
	struct silofs_ubk_info *ubki = NULL;
	int err;

	spi_incref(sti);
	err = silofs_repo_stage_ubk(ub_ctx->repo, spi_bkaddr(sti), &ubki);
	if (!err) {
		spi_attach_to(sti, ubki);
	}
	spi_decref(sti);
	return err;
}

static int ubc_spawn_attach_spi_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_spstats_info *sti)
{
	struct silofs_ubk_info *ubki = NULL;
	int err;

	spi_incref(sti);
	err = ubc_spawn_ubk(ub_ctx, spi_bkaddr(sti), &ubki);
	if (!err) {
		spi_attach_to(sti, ubki);
	}
	spi_decref(sti);
	return err;
}

static int ubc_ghost_attach_spi_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_spstats_info *sti)
{
	struct silofs_ubk_info *ubki = NULL;
	int err;

	spi_incref(sti);
	err = ubc_spawn_cached_ubki(ub_ctx, spi_bkaddr(sti), &ubki);
	if (!err) {
		spi_attach_to(sti, ubki);
	}
	spi_decref(sti);
	return err;
}

int silofs_spawn_stats_at(struct silofs_fs_uber *uber, bool warm,
                          const struct silofs_uaddr *uaddr,
                          struct silofs_spstats_info **out_spi)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };
	struct silofs_spstats_info *spi = NULL;
	int err;

	ubc_setup(&ub_ctx, warm);
	err = ubc_require_cached_spi(&ub_ctx, uaddr, &spi);
	if (err) {
		return err;
	}
	if (spi_is_stable(spi)) {
		return -EEXIST;
	}
	err = ubc_spawn_attach_spi_bk(&ub_ctx, spi);
	if (err) {
		goto out_err;
	}
	spi_set_spawned(spi);
	*out_spi = spi;
	return 0;
out_err:
	ubc_forget_cached_spi(&ub_ctx, spi);
	return err;
}

int silofs_stage_stats_at(struct silofs_fs_uber *uber, bool warm,
                          const struct silofs_uaddr *uaddr,
                          struct silofs_spstats_info **out_spi)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };
	struct silofs_spstats_info *spi = NULL;
	int err;

	ubc_setup(&ub_ctx, warm);
	err = ubc_require_cached_spi(&ub_ctx, uaddr, &spi);
	if (err) {
		return err;
	}
	if (spi_is_stable(spi)) {
		goto out_ok;
	}
	err = ubc_stage_attach_spi_bk(&ub_ctx, spi);
	if (err) {
		goto out_err;
	}
	err = spi_verify_view(spi);
	if (err) {
		return err;
	}
out_ok:
	*out_spi = spi;
	return 0;
out_err:
	ubc_forget_cached_spi(&ub_ctx, spi);
	return err;
}

int silofs_shadow_stats_at(struct silofs_fs_uber *uber, bool warm,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spstats_info **out_spi)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };
	struct silofs_spstats_info *spi = NULL;
	int err;

	ubc_setup(&ub_ctx, warm);
	err = ubc_require_cached_spi(&ub_ctx, uaddr, &spi);
	if (err) {
		return err;
	}
	if (spi_is_stable(spi)) {
		goto out_ok;
	}
	err = ubc_ghost_attach_spi_bk(&ub_ctx, spi);
	if (err) {
		goto out_err;
	}
	spi_set_spawned(spi);
out_ok:
	*out_spi = spi;
	return 0;
out_err:
	ubc_forget_cached_spi(&ub_ctx, spi);
	return err;
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
	int err;

	sni_incref(sni);
	err = silofs_repo_stage_ubk(ub_ctx->repo, sni_bkaddr(sni), &ubki);
	if (!err) {
		sni_attach_to(sni, ubki);
	}
	sni_decref(sni);
	return err;
}

static int ubc_spawn_attach_sni_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_spnode_info *sni)
{
	struct silofs_ubk_info *ubki = NULL;
	int err;

	sni_incref(sni);
	err = ubc_spawn_ubk(ub_ctx, sni_bkaddr(sni), &ubki);
	if (!err) {
		sni_attach_to(sni, ubki);
	}
	sni_decref(sni);
	return err;
}

static int ubc_ghost_attach_sni_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_spnode_info *sni)
{
	struct silofs_ubk_info *ubki = NULL;
	int err;

	sni_incref(sni);
	err = ubc_spawn_cached_ubki(ub_ctx, sni_bkaddr(sni), &ubki);
	if (!err) {
		sni_attach_to(sni, ubki);
	}
	sni_decref(sni);
	return err;
}

int silofs_spawn_spnode_at(struct silofs_fs_uber *uber, bool warm,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spnode_info **out_sni)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };
	struct silofs_spnode_info *sni = NULL;
	int err;

	ubc_setup(&ub_ctx, warm);
	err = ubc_require_cached_sni(&ub_ctx, uaddr, &sni);
	if (err) {
		return err;
	}
	if (sni_is_stable(sni)) {
		return -EEXIST;
	}
	err = ubc_spawn_attach_sni_bk(&ub_ctx, sni);
	if (err) {
		goto out_err;
	}
	sni_set_spawned(sni);
	*out_sni = sni;
	return 0;
out_err:
	ubc_forget_cached_sni(&ub_ctx, sni);
	return err;
}

int silofs_stage_spnode_at(struct silofs_fs_uber *uber, bool warm,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spnode_info **out_sni)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };
	struct silofs_spnode_info *sni = NULL;
	int err;

	ubc_setup(&ub_ctx, warm);
	err = ubc_require_cached_sni(&ub_ctx, uaddr, &sni);
	if (err) {
		return err;
	}
	if (sni_is_stable(sni)) {
		goto out_ok;
	}
	err = ubc_stage_attach_sni_bk(&ub_ctx, sni);
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
	ubc_forget_cached_sni(&ub_ctx, sni);
	return err;
}

int silofs_shadow_spnode_at(struct silofs_fs_uber *uber, bool warm,
                            const struct silofs_uaddr *uaddr,
                            struct silofs_spnode_info **out_sni)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };
	struct silofs_spnode_info *sni = NULL;
	int err;

	ubc_setup(&ub_ctx, warm);
	err = ubc_require_cached_sni(&ub_ctx, uaddr, &sni);
	if (err) {
		return err;
	}
	if (sni_is_stable(sni)) {
		goto out_ok;
	}
	err = ubc_ghost_attach_sni_bk(&ub_ctx, sni);
	if (err) {
		goto out_err;
	}
	sni_set_spawned(sni);
out_ok:
	*out_sni = sni;
	return 0;
out_err:
	ubc_forget_cached_sni(&ub_ctx, sni);
	return err;
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
	int err;

	sli_incref(sli);
	err = silofs_repo_stage_ubk(ub_ctx->repo, sli_bkaddr(sli), &ubki);
	if (!err) {
		sli_attach_to(sli, ubki);
	}
	sli_decref(sli);
	return err;
}

static int ubc_spawn_attach_sli_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_spleaf_info *sli)
{
	struct silofs_ubk_info *ubki = NULL;
	int err;

	sli_incref(sli);
	err = ubc_spawn_ubk(ub_ctx, sli_bkaddr(sli), &ubki);
	if (!err) {
		sli_attach_to(sli, ubki);
	}
	sli_decref(sli);
	return err;
}

static int ubc_ghost_attach_sli_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_spleaf_info *sli)
{
	struct silofs_ubk_info *ubki = NULL;
	int err;

	sli_incref(sli);
	err = ubc_spawn_cached_ubki(ub_ctx, sli_bkaddr(sli), &ubki);
	if (!err) {
		sli_attach_to(sli, ubki);
	}
	sli_decref(sli);
	return err;
}

int silofs_spawn_spleaf_at(struct silofs_fs_uber *uber, bool warm,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spleaf_info **out_sli)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };
	struct silofs_spleaf_info *sli = NULL;
	int err;

	ubc_setup(&ub_ctx, warm);
	err = ubc_require_cached_sli(&ub_ctx, uaddr, &sli);
	if (err) {
		return err;
	}
	if (sli_is_stable(sli)) {
		return -EEXIST;
	}
	err = ubc_spawn_attach_sli_bk(&ub_ctx, sli);
	if (err) {
		goto out_err;
	}
	sli_set_spawned(sli);
	*out_sli = sli;
	return 0;
out_err:
	ubc_forget_cached_sli(&ub_ctx, sli);
	return err;
}

int silofs_stage_spleaf_at(struct silofs_fs_uber *uber, bool warm,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spleaf_info **out_sli)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };
	struct silofs_spleaf_info *sli = NULL;
	int err;

	ubc_setup(&ub_ctx, warm);
	err = ubc_require_cached_sli(&ub_ctx, uaddr, &sli);
	if (err) {
		return err;
	}
	if (sli_is_stable(sli)) {
		goto out_ok;
	}
	err = ubc_stage_attach_sli_bk(&ub_ctx, sli);
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
	ubc_forget_cached_sli(&ub_ctx, sli);
	return err;
}

int silofs_shadow_spleaf_at(struct silofs_fs_uber *uber, bool warm,
                            const struct silofs_uaddr *uaddr,
                            struct silofs_spleaf_info **out_sli)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };
	struct silofs_spleaf_info *sli = NULL;
	int err;

	ubc_setup(&ub_ctx, warm);
	err = ubc_require_cached_sli(&ub_ctx, uaddr, &sli);
	if (err) {
		return err;
	}
	if (sli_is_stable(sli)) {
		goto out_ok;
	}
	err = ubc_ghost_attach_sli_bk(&ub_ctx, sli);
	if (err) {
		goto out_err;
	}
	sli_set_spawned(sli);
out_ok:
	*out_sli = sli;
	return 0;
out_err:
	ubc_forget_cached_sli(&ub_ctx, sli);
	return err;
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int ubc_stage_ubk_of(const struct silofs_uber_ctx *ub_ctx,
                            const struct silofs_bkaddr *bkaddr,
                            struct silofs_ubk_info **out_ubki)
{
	return silofs_repo_stage_ubk(ub_ctx->repo, bkaddr, out_ubki);
}

int silofs_stage_ubk_at(struct silofs_fs_uber *uber, bool warm,
                        const struct silofs_bkaddr *bkaddr,
                        struct silofs_ubk_info **out_ubki)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };
	int err;

	ubc_setup(&ub_ctx, warm);
	err = ubc_stage_ubk_of(&ub_ctx, bkaddr, out_ubki);
	if (err) {
		return err;
	}
	return 0;
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

int silofs_spawn_blob_at(struct silofs_fs_uber *uber, bool warm,
                         const struct silofs_blobid *blobid,
                         struct silofs_blob_info **out_bli)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };
	int err;

	ubc_setup(&ub_ctx, warm);
	err = ubc_require_no_blob(&ub_ctx, blobid);
	if (err) {
		return err;
	}
	err = ubc_spawn_blob(&ub_ctx, blobid, out_bli);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_stage_blob_at(struct silofs_fs_uber *uber, bool warm,
                         const struct silofs_blobid *blobid,
                         struct silofs_blob_info **out_bli)
{
	struct silofs_uber_ctx ub_ctx = { .uber = uber };
	int err;

	ubc_setup(&ub_ctx, warm);
	err = ubc_lookup_blob(&ub_ctx, blobid);
	if (err) {
		return err;
	}
	err = ubc_stage_blob(&ub_ctx, blobid, out_bli);
	if (err) {
		return err;
	}
	return 0;
}
