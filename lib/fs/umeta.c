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
#include <silofs/fs/umeta.h>
#include <silofs/fs/spmaps.h>
#include <silofs/fs/private.h>

struct silofs_unop_ctx {
	const struct silofs_uaddr *uaddr;
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
sti_bkaddr(const struct silofs_stats_info *sti)
{
	return ui_bkaddr(&sti->st_ui);
}

static bool sti_is_stable(const struct silofs_stats_info *sti)
{
	return (sti->st_ui.u_ubi != NULL) && (sti->st != NULL);
}

static void sti_attach_to(struct silofs_stats_info *sti,
                          struct silofs_ubk_info *ubi)
{
	silofs_ui_attach_to(&sti->st_ui, ubi);
	sti->st = &sti->st_ui.u_si.s_view->st;
}

static int sti_verify_view(struct silofs_stats_info *sti)
{
	return silofs_ui_verify_view(&sti->st_ui);
}

static void sti_set_spawned(struct silofs_stats_info *sti)
{
	ui_stamp_mark_visible(&sti->st_ui);
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

static int unc_spawn_cached_ubi(const struct silofs_unop_ctx *un_ctx,
                                const struct silofs_bkaddr *bkaddr,
                                struct silofs_ubk_info **out_ubi)
{
	*out_ubi = silofs_cache_spawn_ubk(un_ctx->cache, bkaddr);
	return (*out_ubi != NULL) ? 0 : -ENOMEM;
}

static int unc_stage_cached_ui(const struct silofs_unop_ctx *un_ctx,
                               struct silofs_unode_info **out_ui)
{
	*out_ui = silofs_cache_lookup_unode(un_ctx->cache, un_ctx->uaddr);
	return (*out_ui == NULL) ? -ENOENT : 0;
}

static void unc_bind_spawned_ui(const struct silofs_unop_ctx *un_ctx,
                                struct silofs_unode_info *ui)
{
	ui->u_si.s_md = un_ctx->mdigest;
	ui->u_repo = un_ctx->repo;
}

static int unc_spawn_cached_ui(const struct silofs_unop_ctx *un_ctx,
                               struct silofs_unode_info **out_ui)
{
	*out_ui = silofs_cache_spawn_unode(un_ctx->cache, un_ctx->uaddr);
	if (*out_ui == NULL) {
		return -ENOMEM;
	}
	unc_bind_spawned_ui(un_ctx, *out_ui);
	return 0;
}

static int unc_require_cached_ui(const struct silofs_unop_ctx *un_ctx,
                                 struct silofs_unode_info **out_ui)
{
	int ret;

	ret = unc_stage_cached_ui(un_ctx, out_ui);
	if (ret == -ENOENT) {
		ret = unc_spawn_cached_ui(un_ctx, out_ui);
	}
	return ret;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int unc_require_cached_sbi(const struct silofs_unop_ctx *un_ctx,
                                  struct silofs_sb_info **out_sbi)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = unc_require_cached_ui(un_ctx, &ui);
	if (!err) {
		*out_sbi = silofs_sbi_from_ui(ui);
	}
	return err;
}

static int unc_stage_attach_sbi_bk(const struct silofs_unop_ctx *un_ctx,
                                   struct silofs_sb_info *sbi)
{
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sbi_incref(sbi);
	err = silofs_repo_stage_ubk(un_ctx->repo, sbi_bkaddr(sbi), &ubi);
	if (!err) {
		sbi_attach_to(sbi, ubi);
	}
	sbi_decref(sbi);
	return err;
}

static int unc_spawn_attach_sbi_bk(const struct silofs_unop_ctx *un_ctx,
                                   struct silofs_sb_info *sbi)
{
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sbi_incref(sbi);
	err = silofs_repo_spawn_ubk(un_ctx->repo, sbi_bkaddr(sbi), &ubi);
	if (!err) {
		sbi_attach_to(sbi, ubi);
	}
	sbi_decref(sbi);
	return err;
}

static int unc_attach_ghost_sbi_bk(const struct silofs_unop_ctx *un_ctx,
                                   struct silofs_sb_info *sbi)
{
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sbi_incref(sbi);
	err = unc_spawn_cached_ubi(un_ctx, sbi_bkaddr(sbi), &ubi);
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
	struct silofs_unop_ctx un_ctx = {
		.uaddr = uaddr,
		.repo = repo,
		.cache = &repo->re_cache,
		.mdigest = repo->re_mdigest,
	};
	int err;

	err = unc_require_cached_sbi(&un_ctx, out_sbi);
	if (err) {
		return err;
	}
	if (sbi_is_stable(*out_sbi)) {
		return -EEXIST;
	}
	err = unc_spawn_attach_sbi_bk(&un_ctx, *out_sbi);
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
	struct silofs_unop_ctx un_ctx = {
		.uaddr = uaddr,
		.repo = repo,
		.cache = &repo->re_cache,
		.mdigest = repo->re_mdigest,
	};
	int err;

	err = unc_require_cached_sbi(&un_ctx, out_sbi);
	if (err) {
		return err;
	}
	if (sbi_is_stable(*out_sbi)) {
		return 0;
	}
	err = unc_stage_attach_sbi_bk(&un_ctx, *out_sbi);
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
	struct silofs_unop_ctx un_ctx = {
		.uaddr = uaddr,
		.repo = repo,
		.cache = &repo->re_cache,
		.mdigest = repo->re_mdigest,
	};
	int err;

	err = unc_require_cached_sbi(&un_ctx, out_sbi);
	if (err) {
		return err;
	}
	if (sbi_is_stable(*out_sbi)) {
		return 0;
	}
	err = unc_attach_ghost_sbi_bk(&un_ctx, *out_sbi);
	if (err) {
		return err;
	}
	sbi_set_spawned(*out_sbi);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int unc_require_cached_sti(const struct silofs_unop_ctx *un_ctx,
                                  struct silofs_stats_info **out_sti)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = unc_require_cached_ui(un_ctx, &ui);
	if (!err) {
		*out_sti = silofs_sti_from_ui(ui);
	}
	return err;
}

static int unc_stage_attach_sti_bk(const struct silofs_unop_ctx *un_ctx,
                                   struct silofs_stats_info *sti)
{
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sti_incref(sti);
	err = silofs_repo_stage_ubk(un_ctx->repo, sti_bkaddr(sti), &ubi);
	if (!err) {
		sti_attach_to(sti, ubi);
	}
	sti_decref(sti);
	return err;
}

static int unc_spawn_attach_sti_bk(const struct silofs_unop_ctx *un_ctx,
                                   struct silofs_stats_info *sti)
{
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sti_incref(sti);
	err = silofs_repo_spawn_ubk(un_ctx->repo, sti_bkaddr(sti), &ubi);
	if (!err) {
		sti_attach_to(sti, ubi);
	}
	sti_decref(sti);
	return err;
}

static int unc_ghost_attach_sti_bk(const struct silofs_unop_ctx *un_ctx,
                                   struct silofs_stats_info *sti)
{
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sti_incref(sti);
	err = unc_spawn_cached_ubi(un_ctx, sti_bkaddr(sti), &ubi);
	if (!err) {
		sti_attach_to(sti, ubi);
	}
	sti_decref(sti);
	return err;
}

int silofs_spawn_stats_at(struct silofs_repo *repo,
                          const struct silofs_uaddr *uaddr,
                          struct silofs_stats_info **out_sti)
{
	struct silofs_unop_ctx un_ctx = {
		.uaddr = uaddr,
		.repo = repo,
		.cache = &repo->re_cache,
		.mdigest = repo->re_mdigest,
	};
	int err;

	err = unc_require_cached_sti(&un_ctx, out_sti);
	if (err) {
		return err;
	}
	if (sti_is_stable(*out_sti)) {
		return -EEXIST;
	}
	err = unc_spawn_attach_sti_bk(&un_ctx, *out_sti);
	if (err) {
		return err;
	}
	sti_set_spawned(*out_sti);
	return 0;
}

int silofs_stage_stats_at(struct silofs_repo *repo,
                          const struct silofs_uaddr *uaddr,
                          struct silofs_stats_info **out_sti)
{
	struct silofs_unop_ctx un_ctx = {
		.uaddr = uaddr,
		.repo = repo,
		.cache = &repo->re_cache,
		.mdigest = repo->re_mdigest,
	};
	int err;

	err = unc_require_cached_sti(&un_ctx, out_sti);
	if (err) {
		return err;
	}
	if (sti_is_stable(*out_sti)) {
		return 0;
	}
	err = unc_stage_attach_sti_bk(&un_ctx, *out_sti);
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
                           struct silofs_stats_info **out_sti)
{
	struct silofs_unop_ctx un_ctx = {
		.uaddr = uaddr,
		.repo = repo,
		.cache = &repo->re_cache,
		.mdigest = repo->re_mdigest,
	};
	int err;

	err = unc_require_cached_sti(&un_ctx, out_sti);
	if (err) {
		return err;
	}
	if (sti_is_stable(*out_sti)) {
		return 0;
	}
	err = unc_ghost_attach_sti_bk(&un_ctx, *out_sti);
	if (err) {
		return err;
	}
	sti_set_spawned(*out_sti);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int unc_require_cached_sni(const struct silofs_unop_ctx *un_ctx,
                                  struct silofs_spnode_info **out_sni)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = unc_require_cached_ui(un_ctx, &ui);
	if (!err) {
		*out_sni = silofs_sni_from_ui(ui);
	}
	return err;
}

static int unc_stage_attach_sni_bk(const struct silofs_unop_ctx *un_ctx,
                                   struct silofs_spnode_info *sni)
{
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sni_incref(sni);
	err = silofs_repo_stage_ubk(un_ctx->repo, sni_bkaddr(sni), &ubi);
	if (!err) {
		sni_attach_to(sni, ubi);
	}
	sni_decref(sni);
	return err;
}

static int unc_spawn_attach_sni_bk(const struct silofs_unop_ctx *un_ctx,
                                   struct silofs_spnode_info *sni)
{
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sni_incref(sni);
	err = silofs_repo_spawn_ubk(un_ctx->repo, sni_bkaddr(sni), &ubi);
	if (!err) {
		sni_attach_to(sni, ubi);
	}
	sni_decref(sni);
	return err;
}

static int unc_ghost_attach_sni_bk(const struct silofs_unop_ctx *un_ctx,
                                   struct silofs_spnode_info *sni)
{
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sni_incref(sni);
	err = unc_spawn_cached_ubi(un_ctx, sni_bkaddr(sni), &ubi);
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
	struct silofs_unop_ctx un_ctx = {
		.uaddr = uaddr,
		.repo = repo,
		.cache = &repo->re_cache,
		.mdigest = repo->re_mdigest,
	};
	int err;

	err = unc_require_cached_sni(&un_ctx, out_sni);
	if (err) {
		return err;
	}
	if (sni_is_stable(*out_sni)) {
		return -EEXIST;
	}
	err = unc_spawn_attach_sni_bk(&un_ctx, *out_sni);
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
	struct silofs_unop_ctx un_ctx = {
		.uaddr = uaddr,
		.repo = repo,
		.cache = &repo->re_cache,
		.mdigest = repo->re_mdigest,
	};
	int err;

	err = unc_require_cached_sni(&un_ctx, out_sni);
	if (err) {
		return err;
	}
	if (sni_is_stable(*out_sni)) {
		return 0;
	}
	err = unc_stage_attach_sni_bk(&un_ctx, *out_sni);
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
	struct silofs_unop_ctx un_ctx = {
		.uaddr = uaddr,
		.repo = repo,
		.cache = &repo->re_cache,
		.mdigest = repo->re_mdigest,
	};
	int err;

	err = unc_require_cached_sni(&un_ctx, out_sni);
	if (err) {
		return err;
	}
	if (sni_is_stable(*out_sni)) {
		return 0;
	}
	err = unc_ghost_attach_sni_bk(&un_ctx, *out_sni);
	if (err) {
		return err;
	}
	sni_set_spawned(*out_sni);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int unc_require_cached_sli(const struct silofs_unop_ctx *un_ctx,
                                  struct silofs_spleaf_info **out_sli)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = unc_require_cached_ui(un_ctx, &ui);
	if (!err) {
		*out_sli = silofs_sli_from_ui(ui);
	}
	return err;
}

static int unc_stage_attach_sli_bk(const struct silofs_unop_ctx *un_ctx,
                                   struct silofs_spleaf_info *sli)
{
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sli_incref(sli);
	err = silofs_repo_stage_ubk(un_ctx->repo, sli_bkaddr(sli), &ubi);
	if (!err) {
		sli_attach_to(sli, ubi);
	}
	sli_decref(sli);
	return err;
}

static int unc_spawn_attach_sli_bk(const struct silofs_unop_ctx *un_ctx,
                                   struct silofs_spleaf_info *sli)
{
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sli_incref(sli);
	err = silofs_repo_spawn_ubk(un_ctx->repo, sli_bkaddr(sli), &ubi);
	if (!err) {
		sli_attach_to(sli, ubi);
	}
	sli_decref(sli);
	return err;
}

static int unc_ghost_attach_sli_bk(const struct silofs_unop_ctx *un_ctx,
                                   struct silofs_spleaf_info *sli)
{
	struct silofs_ubk_info *ubi = NULL;
	int err;

	sli_incref(sli);
	err = unc_spawn_cached_ubi(un_ctx, sli_bkaddr(sli), &ubi);
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
	struct silofs_unop_ctx un_ctx = {
		.uaddr = uaddr,
		.repo = repo,
		.cache = &repo->re_cache,
		.mdigest = repo->re_mdigest,
	};
	int err;

	err = unc_require_cached_sli(&un_ctx, out_sli);
	if (err) {
		return err;
	}
	if (sli_is_stable(*out_sli)) {
		return -EEXIST;
	}
	err = unc_spawn_attach_sli_bk(&un_ctx, *out_sli);
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
	struct silofs_unop_ctx un_ctx = {
		.uaddr = uaddr,
		.repo = repo,
		.cache = &repo->re_cache,
		.mdigest = repo->re_mdigest,
	};
	int err;

	err = unc_require_cached_sli(&un_ctx, out_sli);
	if (err) {
		return err;
	}
	if (sli_is_stable(*out_sli)) {
		return 0;
	}
	err = unc_stage_attach_sli_bk(&un_ctx, *out_sli);
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
	struct silofs_unop_ctx un_ctx = {
		.uaddr = uaddr,
		.repo = repo,
		.cache = &repo->re_cache,
		.mdigest = repo->re_mdigest,
	};
	int err;

	err = unc_require_cached_sli(&un_ctx, out_sli);
	if (err) {
		return err;
	}
	if (sli_is_stable(*out_sli)) {
		return 0;
	}
	err = unc_ghost_attach_sli_bk(&un_ctx, *out_sli);
	if (err) {
		return err;
	}
	sli_set_spawned(*out_sli);
	return 0;
}
