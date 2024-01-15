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
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static int fetch_cached_ui(const struct silofs_fsenv *fsenv,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_unode_info **out_ui)
{
	*out_ui = silofs_lcache_lookup_ui(fsenv->fse.lcache, uaddr);
	return (*out_ui == NULL) ? -SILOFS_ENOENT : 0;
}

static void bind_spawned_ui(struct silofs_fsenv *fsenv,
                            struct silofs_unode_info *ui)
{
	ui->u_lni.l_fsenv = fsenv;
}

static int create_cached_ui(struct silofs_fsenv *fsenv,
                            const struct silofs_ulink *ulink,
                            struct silofs_unode_info **out_ui)
{
	*out_ui = silofs_lcache_create_ui(fsenv->fse.lcache, ulink);
	if (*out_ui == NULL) {
		return -SILOFS_ENOMEM;
	}
	bind_spawned_ui(fsenv, *out_ui);
	return 0;
}

static int require_cached_ui(struct silofs_fsenv *fsenv,
                             const struct silofs_ulink *ulink,
                             struct silofs_unode_info **out_ui)
{
	int ret;

	ret = fetch_cached_ui(fsenv, &ulink->uaddr, out_ui);
	if (ret == -SILOFS_ENOENT) {
		ret = create_cached_ui(fsenv, ulink, out_ui);
	}
	return ret;
}

static void forget_cached_ui(const struct silofs_fsenv *fsenv,
                             struct silofs_unode_info *ui)
{
	silofs_lcache_forget_ui(fsenv->fse.lcache, ui);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static bool lsegid_rw_mode(const struct silofs_fsenv *fsenv,
                           const struct silofs_lsegid *lsegid)
{
	const struct silofs_sb_info *sbi = fsenv->fse_sbi;
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
		 * logic has an issue with (off-line) snapshots, thus forcing
		 * read-write mode.
		 */
		rw_mode = true;
	}
	return rw_mode;
}

static int lookup_lseg(const struct silofs_fsenv *fsenv,
                       const struct silofs_lsegid *lsegid)
{
	struct stat st;

	return silofs_repo_stat_lseg(fsenv->fse.repo, lsegid, true, &st);
}

static int stage_lseg(const struct silofs_fsenv *fsenv,
                      const struct silofs_lsegid *lsegid)
{
	int err;
	const bool rw = lsegid_rw_mode(fsenv, lsegid);

	err = silofs_repo_stage_lseg(fsenv->fse.repo, rw, lsegid);
	if (err && (err != -SILOFS_ENOENT)) {
		log_dbg("stage lseg failed: err=%d", err);
	}
	return err;
}

static int spawn_lseg(const struct silofs_fsenv *fsenv,
                      const struct silofs_lsegid *lsegid)
{
	int err;

	err = silofs_repo_spawn_lseg(fsenv->fse.repo, lsegid);
	if (err && (err != -SILOFS_ENOENT)) {
		log_dbg("spawn lseg failed: err=%d", err);
	}
	return err;
}

static int require_lseg(const struct silofs_fsenv *fsenv,
                        const struct silofs_lsegid *lsegid)
{
	int err;

	err = lookup_lseg(fsenv, lsegid);
	if (!err) {
		err = stage_lseg(fsenv, lsegid);
	} else if (err == -SILOFS_ENOENT) {
		err = spawn_lseg(fsenv, lsegid);
	}
	return err;
}

static int require_lseg_by(const struct silofs_fsenv *fsenv,
                           const struct silofs_ulink *ulink)
{
	return require_lseg(fsenv, &ulink->uaddr.laddr.lsegid);
}

static int load_view_at(const struct silofs_fsenv *fsenv,
                        const struct silofs_laddr *laddr,
                        struct silofs_view *view)
{
	return silofs_repo_read_at(fsenv->fse.repo, laddr, view);
}

static int stage_load_view(const struct silofs_fsenv *fsenv,
                           const struct silofs_laddr *laddr,
                           struct silofs_view *view)
{
	int err;

	silofs_assert_not_null(view);

	err = stage_lseg(fsenv, &laddr->lsegid);
	if (err) {
		return err;
	}
	err = load_view_at(fsenv, laddr, view);
	if (err) {
		return err;
	}
	return 0;
}

static int decrypt_ui_view(const struct silofs_fsenv *fsenv,
                           struct silofs_unode_info *ui)
{
	return silofs_decrypt_ui_view(fsenv, ui);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void forget_cached_sbi(const struct silofs_fsenv *fsenv,
                              struct silofs_sb_info *sbi)
{
	if (sbi != NULL) {
		forget_cached_ui(fsenv, &sbi->sb_ui);
	}
}

static int require_cached_sbi(struct silofs_fsenv *fsenv,
                              const struct silofs_ulink *ulink,
                              struct silofs_sb_info **out_sbi)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = require_cached_ui(fsenv, ulink, &ui);
	if (err) {
		return err;
	}
	*out_sbi = silofs_sbi_from_ui(ui);
	sbi_set_fsenv(*out_sbi, fsenv);
	return 0;
}

static int spawn_super_at(struct silofs_fsenv *fsenv,
                          const struct silofs_ulink *ulink,
                          struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = require_cached_sbi(fsenv, ulink, &sbi);
	if (err) {
		goto out_err;
	}
	err = require_lseg_by(fsenv, ulink);
	if (err) {
		goto out_err;
	}
	sbi_set_spawned(sbi);

	*out_sbi = sbi;
	return 0;
out_err:
	forget_cached_sbi(fsenv, sbi);
	*out_sbi = NULL;
	return err;
}

int silofs_spawn_super(struct silofs_fsenv *fsenv,
                       const struct silofs_ulink *ulink,
                       struct silofs_sb_info **out_sbi)
{
	return spawn_super_at(fsenv, ulink, out_sbi);
}

static int decrypt_view_of_sbi(const struct silofs_fsenv *fsenv,
                               struct silofs_sb_info *sbi)
{
	return decrypt_ui_view(fsenv, &sbi->sb_ui);
}

static int load_view_of_sbi(const struct silofs_fsenv *fsenv,
                            struct silofs_sb_info *sbi)
{
	return stage_load_view(fsenv, sbi_laddr(sbi),
	                       sbi->sb_ui.u_lni.l_view);
}

static int stage_super_at(struct silofs_fsenv *fsenv,
                          const struct silofs_ulink *ulink,
                          struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = require_cached_sbi(fsenv, ulink, &sbi);
	if (err) {
		return err;
	}
	if (sbi_is_active(sbi)) {
		goto out_ok;
	}
	err = require_lseg_by(fsenv, ulink);
	if (err) {
		goto out_err;
	}
	err = load_view_of_sbi(fsenv, sbi);
	if (err) {
		goto out_err;
	}
	err = decrypt_view_of_sbi(fsenv, sbi);
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
	forget_cached_sbi(fsenv, sbi);
	*out_sbi = NULL;
	return err;
}

int silofs_stage_super(struct silofs_fsenv *fsenv,
                       const struct silofs_ulink *ulink,
                       struct silofs_sb_info **out_sbi)
{
	return stage_super_at(fsenv, ulink, out_sbi);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void forget_cached_sni(const struct silofs_fsenv *fsenv,
                              struct silofs_spnode_info *sni)
{
	if (sni != NULL) {
		forget_cached_ui(fsenv, &sni->sn_ui);
	}
}

static int require_cached_sni(struct silofs_fsenv *fsenv,
                              const struct silofs_ulink *ulink,
                              struct silofs_spnode_info **out_sni)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = require_cached_ui(fsenv, ulink, &ui);
	if (err) {
		return err;
	}
	*out_sni = silofs_sni_from_ui(ui);
	sni_set_fsenv(*out_sni, fsenv);
	return 0;
}

static int spawn_spnode_at(struct silofs_fsenv *fsenv,
                           const struct silofs_ulink *ulink,
                           struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni = NULL;
	int err;

	err = require_cached_sni(fsenv, ulink, &sni);
	if (err) {
		return err;
	}
	if (sni_is_active(sni)) {
		goto out_ok;
	}
	err = require_lseg_by(fsenv, ulink);
	if (err) {
		goto out_err;
	}
	sni_set_spawned(sni);
out_ok:
	*out_sni = sni;
	return 0;
out_err:
	forget_cached_sni(fsenv, sni);
	*out_sni = NULL;
	return err;
}

int silofs_spawn_spnode(struct silofs_fsenv *fsenv,
                        const struct silofs_ulink *ulink,
                        struct silofs_spnode_info **out_sni)
{
	return spawn_spnode_at(fsenv, ulink, out_sni);
}

static int decrypt_view_of_sni(const struct silofs_fsenv *fsenv,
                               struct silofs_spnode_info *sni)
{
	return decrypt_ui_view(fsenv, &sni->sn_ui);
}

static int load_view_of_sni(const struct silofs_fsenv *fsenv,
                            struct silofs_spnode_info *sni)
{
	return stage_load_view(fsenv, sni_laddr(sni),
	                       sni->sn_ui.u_lni.l_view);
}

static int stage_spnode_at(struct silofs_fsenv *fsenv,
                           const struct silofs_ulink *ulink,
                           struct silofs_spnode_info **out_sni)
{
	struct silofs_spnode_info *sni = NULL;
	int err;

	err = require_cached_sni(fsenv, ulink, &sni);
	if (err) {
		return err;
	}
	if (sni_is_active(sni)) {
		goto out_ok;
	}
	err = require_lseg_by(fsenv, ulink);
	if (err) {
		goto out_err;
	}
	err = load_view_of_sni(fsenv, sni);
	if (err) {
		goto out_err;
	}
	err = decrypt_view_of_sni(fsenv, sni);
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
	forget_cached_sni(fsenv, sni);
	*out_sni = NULL;
	return err;
}

int silofs_stage_spnode(struct silofs_fsenv *fsenv,
                        const struct silofs_ulink *ulink,
                        struct silofs_spnode_info **out_sni)
{
	return stage_spnode_at(fsenv, ulink, out_sni);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void forget_cached_sli(const struct silofs_fsenv *fsenv,
                              struct silofs_spleaf_info *sli)
{
	if (sli != NULL) {
		forget_cached_ui(fsenv, &sli->sl_ui);
	}
}

static int require_cached_sli(struct silofs_fsenv *fsenv,
                              const struct silofs_ulink *ulink,
                              struct silofs_spleaf_info **out_sli)
{
	struct silofs_unode_info *ui = NULL;
	int err;

	err = require_cached_ui(fsenv, ulink, &ui);
	if (err) {
		return err;
	}
	*out_sli = silofs_sli_from_ui(ui);
	sli_set_fsenv(*out_sli, fsenv);
	return 0;
}

static int spawn_spleaf_at(struct silofs_fsenv *fsenv,
                           const struct silofs_ulink *ulink,
                           struct silofs_spleaf_info **out_sli)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = require_cached_sli(fsenv, ulink, &sli);
	if (err) {
		goto out_err;
	}
	if (sli_is_active(sli)) {
		goto out_ok;
	}
	err = require_lseg_by(fsenv, ulink);
	if (err) {
		goto out_err;
	}
	sli_set_spawned(sli);
out_ok:
	*out_sli = sli;
	return 0;
out_err:
	forget_cached_sli(fsenv, sli);
	*out_sli = NULL;
	return err;
}

int silofs_spawn_spleaf(struct silofs_fsenv *fsenv,
                        const struct silofs_ulink *ulink,
                        struct silofs_spleaf_info **out_sli)
{
	return spawn_spleaf_at(fsenv, ulink, out_sli);
}

static int decrypt_view_of_sli(const struct silofs_fsenv *fsenv,
                               struct silofs_spleaf_info *sli)
{
	return decrypt_ui_view(fsenv, &sli->sl_ui);
}

static int load_view_of_sli(const struct silofs_fsenv *fsenv,
                            struct silofs_spleaf_info *sli)
{
	return stage_load_view(fsenv, sli_laddr(sli),
	                       sli->sl_ui.u_lni.l_view);
}

static int stage_spleaf_at(struct silofs_fsenv *fsenv,
                           const struct silofs_ulink *ulink,
                           struct silofs_spleaf_info **out_sli)
{
	struct silofs_spleaf_info *sli = NULL;
	int err;

	err = require_cached_sli(fsenv, ulink, &sli);
	if (err) {
		goto out_err;
	}
	if (sli_is_active(sli)) {
		goto out_ok;
	}
	err = require_lseg_by(fsenv, ulink);
	if (err) {
		goto out_err;
	}
	err = load_view_of_sli(fsenv, sli);
	if (err) {
		goto out_err;
	}
	err = decrypt_view_of_sli(fsenv, sli);
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
	forget_cached_sli(fsenv, sli);
	*out_sli = NULL;
	return err;
}

int silofs_stage_spleaf(struct silofs_fsenv *fsenv,
                        const struct silofs_ulink *ulink,
                        struct silofs_spleaf_info **out_sli)
{
	return stage_spleaf_at(fsenv, ulink, out_sli);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int require_no_lseg(const struct silofs_fsenv *fsenv,
                           const struct silofs_lsegid *lsegid)
{
	int err;

	err = lookup_lseg(fsenv, lsegid);
	if (!err) {
		return -SILOFS_EEXIST;
	}
	if (err != -SILOFS_ENOENT) {
		return err;
	}
	return 0;
}

int silofs_spawn_lseg(struct silofs_fsenv *fsenv,
                      const struct silofs_lsegid *lsegid)
{
	int err;

	err = require_no_lseg(fsenv, lsegid);
	if (err) {
		return err;
	}
	err = spawn_lseg(fsenv, lsegid);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_stage_lseg(struct silofs_fsenv *fsenv,
                      const struct silofs_lsegid *lsegid)
{
	int err;

	err = lookup_lseg(fsenv, lsegid);
	if (err) {
		return err;
	}
	err = stage_lseg(fsenv, lsegid);
	if (err) {
		return err;
	}
	return 0;
}
