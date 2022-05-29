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
#include <silofs/fs/types.h>
#include <silofs/fs/address.h>
#include <silofs/fs/nodes.h>
#include <silofs/fs/spxmap.h>
#include <silofs/fs/cache.h>
#include <silofs/fs/crypto.h>
#include <silofs/fs/boot.h>
#include <silofs/fs/repo.h>
#include <silofs/fs/super.h>
#include <silofs/fs/uber.h>
#include <silofs/fs/spmaps.h>
#include <silofs/fs/private.h>

struct silofs_uber_ctx {
	struct silofs_repo        *repo;
	struct silofs_cache       *cache;
	struct silofs_mdigest     *mdigest;
};


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void ui_stamp_mark_visible(struct silofs_unode_info *ui)
{
	silofs_zero_stamp_meta(ui->u_si.s_view, ui_stype(ui));
	ui->u_verified = true;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_bkaddr *
sbi_bkaddr(const struct silofs_sb_info *sbi)
{
	return ui_bkaddr(&sbi->sb_ui);
}

static bool sbi_is_stable(const struct silofs_sb_info *sbi)
{
	return (sbi->sb_ui.u_ubi != NULL) && (sbi->sb != NULL);
}

static void sbi_attach_to(struct silofs_sb_info *sbi,
                          struct silofs_ubk_info *ubi)
{
	silofs_ui_attach_to(&sbi->sb_ui, ubi);
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
sti_bkaddr(const struct silofs_spstat_info *sti)
{
	return ui_bkaddr(&sti->sp_ui);
}

static bool sti_is_stable(const struct silofs_spstat_info *sti)
{
	return (sti->sp_ui.u_ubi != NULL) && (sti->sp != NULL);
}

static void sti_attach_to(struct silofs_spstat_info *sti,
                          struct silofs_ubk_info *ubi)
{
	silofs_ui_attach_to(&sti->sp_ui, ubi);
	sti->sp = &sti->sp_ui.u_si.s_view->st;
}

static int sti_verify_view(struct silofs_spstat_info *sti)
{
	return silofs_ui_verify_view(&sti->sp_ui);
}

static void sti_set_spawned(struct silofs_spstat_info *sti)
{
	ui_stamp_mark_visible(&sti->sp_ui);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_bkaddr *
sni_bkaddr(const struct silofs_spnode_info *sni)
{
	return ui_bkaddr(&sni->sn_ui);
}

static bool sni_is_stable(const struct silofs_spnode_info *sni)
{
	return (sni->sn_ui.u_ubi != NULL) && (sni->sn != NULL);
}

static void sni_attach_to(struct silofs_spnode_info *sni,
                          struct silofs_ubk_info *ubi)
{
	silofs_ui_attach_to(&sni->sn_ui, ubi);
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
	return (sli->sl_ui.u_ubi != NULL) && (sli->sl != NULL);
}

static void sli_attach_to(struct silofs_spleaf_info *sli,
                          struct silofs_ubk_info *ubi)
{
	silofs_ui_attach_to(&sli->sl_ui, ubi);
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

static void ubc_setup(struct silofs_uber_ctx *ub_ctx, struct silofs_repo *repo)
{
	ub_ctx->repo = repo;
	ub_ctx->cache = &repo->re_cache;
	ub_ctx->mdigest = &repo->re_bootldr.btl_md;
}

static int ubc_spawn_cached_ubi(const struct silofs_uber_ctx *ub_ctx,
                                const struct silofs_bkaddr *bkaddr,
                                struct silofs_ubk_info **out_ubi)
{
	*out_ubi = silofs_cache_spawn_ubk(ub_ctx->cache, bkaddr);
	return (*out_ubi != NULL) ? 0 : -ENOMEM;
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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int ubc_require_blob(const struct silofs_uber_ctx *ub_ctx,
                            const struct silofs_blobid *blobid,
                            struct silofs_blob_info **out_bli)
{
	int err;

	err = silofs_repo_lookup_blob(ub_ctx->repo, blobid);
	if (!err) {
		err = silofs_repo_stage_blob(ub_ctx->repo, blobid, out_bli);
	} else if (err == -ENOENT) {
		err = silofs_repo_spawn_blob(ub_ctx->repo, blobid, out_bli);
	}
	return err;
}

static int ubc_spawn_ubk(const struct silofs_uber_ctx *ub_ctx,
                         const struct silofs_bkaddr *bkaddr,
                         struct silofs_ubk_info **out_ubi)
{
	struct silofs_blob_info *bli = NULL;
	int err;

	err = ubc_require_blob(ub_ctx, &bkaddr->blobid, &bli);
	if (err) {
		goto out;
	}
	bli_incref(bli);
	err = silofs_repo_spawn_ubk(ub_ctx->repo, bkaddr, out_ubi);
	if (err) {
		goto out;
	}
out:
	bli_decref(bli);
	return err;
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
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sbi_incref(sbi);
	err = silofs_repo_stage_ubk(ub_ctx->repo, sbi_bkaddr(sbi), &ubi);
	if (!err) {
		sbi_attach_to(sbi, ubi);
	}
	sbi_decref(sbi);
	return err;
}

static int ubc_spawn_attach_sbi_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_sb_info *sbi)
{
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sbi_incref(sbi);
	err = ubc_spawn_ubk(ub_ctx, sbi_bkaddr(sbi), &ubi);
	if (!err) {
		sbi_attach_to(sbi, ubi);
	}
	sbi_decref(sbi);
	return err;
}

static int ubc_attach_ghost_sbi_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_sb_info *sbi)
{
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sbi_incref(sbi);
	err = ubc_spawn_cached_ubi(ub_ctx, sbi_bkaddr(sbi), &ubi);
	if (!err) {
		sbi_attach_to(sbi, ubi);
	}
	sbi_decref(sbi);
	return err;
}

int silofs_spawn_super_at(struct silofs_repo *repo,
                          const struct silofs_uaddr *uaddr,
                          struct silofs_sb_info **out_sbi)
{
	struct silofs_uber_ctx ub_ctx;
	int err;

	ubc_setup(&ub_ctx, repo);
	err = ubc_require_cached_sbi(&ub_ctx, uaddr, out_sbi);
	if (err) {
		return err;
	}
	if (sbi_is_stable(*out_sbi)) {
		return -EEXIST;
	}
	err = ubc_spawn_attach_sbi_bk(&ub_ctx, *out_sbi);
	if (err) {
		return err;
	}
	sbi_set_spawned(*out_sbi);
	return 0;
}

int silofs_stage_super_at(struct silofs_repo *repo,
                          const struct silofs_uaddr *uaddr,
                          struct silofs_sb_info **out_sbi)
{
	struct silofs_uber_ctx ub_ctx;
	int err;

	ubc_setup(&ub_ctx, repo);
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

int silofs_shadow_super_at(struct silofs_repo *repo,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_sb_info **out_sbi)
{
	struct silofs_uber_ctx ub_ctx;
	int err;

	ubc_setup(&ub_ctx, repo);
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

static int ubc_require_cached_sti(const struct silofs_uber_ctx *ub_ctx,
                                  const struct silofs_uaddr *uaddr,
                                  struct silofs_spstat_info **out_sti)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = ubc_require_cached_ui(ub_ctx, uaddr, &ui);
	if (!err) {
		*out_sti = silofs_sti_from_ui(ui);
	}
	return err;
}

static int ubc_stage_attach_sti_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_spstat_info *sti)
{
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sti_incref(sti);
	err = silofs_repo_stage_ubk(ub_ctx->repo, sti_bkaddr(sti), &ubi);
	if (!err) {
		sti_attach_to(sti, ubi);
	}
	sti_decref(sti);
	return err;
}

static int ubc_spawn_attach_sti_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_spstat_info *sti)
{
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sti_incref(sti);
	err = ubc_spawn_ubk(ub_ctx, sti_bkaddr(sti), &ubi);
	if (!err) {
		sti_attach_to(sti, ubi);
	}
	sti_decref(sti);
	return err;
}

static int ubc_ghost_attach_sti_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_spstat_info *sti)
{
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sti_incref(sti);
	err = ubc_spawn_cached_ubi(ub_ctx, sti_bkaddr(sti), &ubi);
	if (!err) {
		sti_attach_to(sti, ubi);
	}
	sti_decref(sti);
	return err;
}

int silofs_spawn_stats_at(struct silofs_repo *repo,
                          const struct silofs_uaddr *uaddr,
                          struct silofs_spstat_info **out_sti)
{
	struct silofs_uber_ctx ub_ctx;
	int err;

	ubc_setup(&ub_ctx, repo);
	err = ubc_require_cached_sti(&ub_ctx, uaddr, out_sti);
	if (err) {
		return err;
	}
	if (sti_is_stable(*out_sti)) {
		return -EEXIST;
	}
	err = ubc_spawn_attach_sti_bk(&ub_ctx, *out_sti);
	if (err) {
		return err;
	}
	sti_set_spawned(*out_sti);
	return 0;
}

int silofs_stage_stats_at(struct silofs_repo *repo,
                          const struct silofs_uaddr *uaddr,
                          struct silofs_spstat_info **out_sti)
{
	struct silofs_uber_ctx ub_ctx;
	int err;

	ubc_setup(&ub_ctx, repo);
	err = ubc_require_cached_sti(&ub_ctx, uaddr, out_sti);
	if (err) {
		return err;
	}
	if (sti_is_stable(*out_sti)) {
		return 0;
	}
	err = ubc_stage_attach_sti_bk(&ub_ctx, *out_sti);
	if (err) {
		return err;
	}
	err = sti_verify_view(*out_sti);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_shadow_stats_at(struct silofs_repo *repo,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spstat_info **out_sti)
{
	struct silofs_uber_ctx ub_ctx;
	int err;

	ubc_setup(&ub_ctx, repo);
	err = ubc_require_cached_sti(&ub_ctx, uaddr, out_sti);
	if (err) {
		return err;
	}
	if (sti_is_stable(*out_sti)) {
		return 0;
	}
	err = ubc_ghost_attach_sti_bk(&ub_ctx, *out_sti);
	if (err) {
		return err;
	}
	sti_set_spawned(*out_sti);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sni_incref(sni);
	err = silofs_repo_stage_ubk(ub_ctx->repo, sni_bkaddr(sni), &ubi);
	if (!err) {
		sni_attach_to(sni, ubi);
	}
	sni_decref(sni);
	return err;
}

static int ubc_spawn_attach_sni_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_spnode_info *sni)
{
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sni_incref(sni);
	err = ubc_spawn_ubk(ub_ctx, sni_bkaddr(sni), &ubi);
	if (!err) {
		sni_attach_to(sni, ubi);
	}
	sni_decref(sni);
	return err;
}

static int ubc_ghost_attach_sni_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_spnode_info *sni)
{
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sni_incref(sni);
	err = ubc_spawn_cached_ubi(ub_ctx, sni_bkaddr(sni), &ubi);
	if (!err) {
		sni_attach_to(sni, ubi);
	}
	sni_decref(sni);
	return err;
}

int silofs_spawn_spnode_at(struct silofs_repo *repo,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spnode_info **out_sni)
{
	struct silofs_uber_ctx ub_ctx;
	int err;

	ubc_setup(&ub_ctx, repo);
	err = ubc_require_cached_sni(&ub_ctx, uaddr, out_sni);
	if (err) {
		return err;
	}
	if (sni_is_stable(*out_sni)) {
		return -EEXIST;
	}
	err = ubc_spawn_attach_sni_bk(&ub_ctx, *out_sni);
	if (err) {
		return err;
	}
	sni_set_spawned(*out_sni);
	return 0;
}

int silofs_stage_spnode_at(struct silofs_repo *repo,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spnode_info **out_sni)
{
	struct silofs_uber_ctx ub_ctx;
	int err;

	ubc_setup(&ub_ctx, repo);
	err = ubc_require_cached_sni(&ub_ctx, uaddr, out_sni);
	if (err) {
		return err;
	}
	if (sni_is_stable(*out_sni)) {
		return 0;
	}
	err = ubc_stage_attach_sni_bk(&ub_ctx, *out_sni);
	if (err) {
		return err;
	}
	err = sni_verify_view(*out_sni);
	if (err) {
		return err;
	}
	silofs_sni_update_staged(*out_sni);
	return 0;
}

int silofs_shadow_spnode_at(struct silofs_repo *repo,
                            const struct silofs_uaddr *uaddr,
                            struct silofs_spnode_info **out_sni)
{
	struct silofs_uber_ctx ub_ctx;
	int err;

	ubc_setup(&ub_ctx, repo);
	err = ubc_require_cached_sni(&ub_ctx, uaddr, out_sni);
	if (err) {
		return err;
	}
	if (sni_is_stable(*out_sni)) {
		return 0;
	}
	err = ubc_ghost_attach_sni_bk(&ub_ctx, *out_sni);
	if (err) {
		return err;
	}
	sni_set_spawned(*out_sni);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

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
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sli_incref(sli);
	err = silofs_repo_stage_ubk(ub_ctx->repo, sli_bkaddr(sli), &ubi);
	if (!err) {
		sli_attach_to(sli, ubi);
	}
	sli_decref(sli);
	return err;
}

static int ubc_spawn_attach_sli_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_spleaf_info *sli)
{
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sli_incref(sli);
	err = ubc_spawn_ubk(ub_ctx, sli_bkaddr(sli), &ubi);
	if (!err) {
		sli_attach_to(sli, ubi);
	}
	sli_decref(sli);
	return err;
}

static int ubc_ghost_attach_sli_bk(const struct silofs_uber_ctx *ub_ctx,
                                   struct silofs_spleaf_info *sli)
{
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sli_incref(sli);
	err = ubc_spawn_cached_ubi(ub_ctx, sli_bkaddr(sli), &ubi);
	if (!err) {
		sli_attach_to(sli, ubi);
	}
	sli_decref(sli);
	return err;
}

int silofs_spawn_spleaf_at(struct silofs_repo *repo,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spleaf_info **out_sli)
{
	struct silofs_uber_ctx ub_ctx;
	int err;

	ubc_setup(&ub_ctx, repo);
	err = ubc_require_cached_sli(&ub_ctx, uaddr, out_sli);
	if (err) {
		return err;
	}
	if (sli_is_stable(*out_sli)) {
		return -EEXIST;
	}
	err = ubc_spawn_attach_sli_bk(&ub_ctx, *out_sli);
	if (err) {
		return err;
	}
	sli_set_spawned(*out_sli);
	return 0;
}

int silofs_stage_spleaf_at(struct silofs_repo *repo,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_spleaf_info **out_sli)
{
	struct silofs_uber_ctx ub_ctx;
	int err;

	ubc_setup(&ub_ctx, repo);
	err = ubc_require_cached_sli(&ub_ctx, uaddr, out_sli);
	if (err) {
		return err;
	}
	if (sli_is_stable(*out_sli)) {
		return 0;
	}
	err = ubc_stage_attach_sli_bk(&ub_ctx, *out_sli);
	if (err) {
		return err;
	}
	err = sli_verify_view(*out_sli);
	if (err) {
		return err;
	}
	silofs_sli_update_staged(*out_sli);
	return 0;
}

int silofs_shadow_spleaf_at(struct silofs_repo *repo,
                            const struct silofs_uaddr *uaddr,
                            struct silofs_spleaf_info **out_sli)
{
	struct silofs_uber_ctx ub_ctx;
	int err;

	ubc_setup(&ub_ctx, repo);
	err = ubc_require_cached_sli(&ub_ctx, uaddr, out_sli);
	if (err) {
		return err;
	}
	if (sli_is_stable(*out_sli)) {
		return 0;
	}
	err = ubc_ghost_attach_sli_bk(&ub_ctx, *out_sli);
	if (err) {
		return err;
	}
	sli_set_spawned(*out_sli);
	return 0;
}

