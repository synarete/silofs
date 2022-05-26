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
#include <silofs/fs/boot.h>
#include <silofs/fs/nodes.h>
#include <silofs/fs/spxmap.h>
#include <silofs/fs/cache.h>
#include <silofs/fs/repo.h>
#include <silofs/fs/itable.h>
#include <silofs/fs/super.h>
#include <silofs/fs/stats.h>
#include <silofs/fs/namei.h>
#include <silofs/fs/apex.h>
#include <silofs/fs/uber.h>
#include <silofs/fs/private.h>
#include <stdlib.h>
#include <iconv.h>


static size_t apex_calc_iopen_limit(const struct silofs_fs_apex *apex)
{
	size_t lim;
	const size_t align = 128;
	struct silofs_alloc_stat st;

	silofs_allocstat(apex->ap_alloc, &st);
	lim = (st.memsz_data / (2 * SILOFS_BK_SIZE));
	return div_round_up(lim, align) * align;
}

static void apex_init_commons(struct silofs_fs_apex *apex,
                              struct silofs_alloc *alloc,
                              struct silofs_kivam *kivam,
                              struct silofs_crypto *crypto)

{
	apex->ap_initime = silofs_time_now();
	apex->ap_alloc = alloc;
	apex->ap_kivam = kivam;
	apex->ap_crypto = crypto;
	apex->ap_iconv = (iconv_t)(-1);
	apex->ap_sbi = NULL;
	apex->ap_slock_fd = -1;

	apex->ap_ops.op_iopen_max = 0;
	apex->ap_ops.op_iopen = 0;
	apex->ap_ops.op_time = silofs_time_now();
	apex->ap_ops.op_count = 0;
	apex->ap_ops.op_iopen_max = apex_calc_iopen_limit(apex);
}

static void apex_fini_commons(struct silofs_fs_apex *apex)
{
	silofs_sys_closefd(&apex->ap_slock_fd);
	apex->ap_alloc = NULL;
	apex->ap_kivam = NULL;
	apex->ap_crypto = NULL;
	apex->ap_iconv = (iconv_t)(-1);
	apex->ap_sbi = NULL;
}

static void apex_init_repos(struct silofs_fs_apex *apex,
                            struct silofs_repo *mrepo,
                            struct silofs_repo *crepo)
{
	apex->ap_mrepo = mrepo;
	apex->ap_crepo = crepo;
}

static void apex_fini_repos(struct silofs_fs_apex *apex)
{
	apex->ap_mrepo = NULL;
	apex->ap_crepo = NULL;
}

static int apex_init_piper(struct silofs_fs_apex *apex)
{
	return silofs_piper_init(&apex->ap_piper, SILOFS_BK_SIZE);
}

static void apex_fini_piper(struct silofs_fs_apex *apex)
{
	silofs_piper_fini(&apex->ap_piper);
}

static int apex_init_iconv(struct silofs_fs_apex *apex)
{
	/* Using UTF32LE to avoid BOM (byte-order-mark) character */
	apex->ap_iconv = iconv_open("UTF32LE", "UTF8");
	if (apex->ap_iconv == (iconv_t)(-1)) {
		return errno ? -errno : -EOPNOTSUPP;
	}
	return 0;
}

static void apex_fini_iconv(struct silofs_fs_apex *apex)
{
	if (apex->ap_iconv != (iconv_t)(-1)) {
		iconv_close(apex->ap_iconv);
		apex->ap_iconv = (iconv_t)(-1);
	}
}

int silofs_apex_init(struct silofs_fs_apex *apex,
                     struct silofs_alloc *alloc,
                     struct silofs_kivam *kivam,
                     struct silofs_crypto *crypto,
                     struct silofs_repo *mrepo,
                     struct silofs_repo *crepo)
{
	int err;

	apex_init_commons(apex, alloc, kivam, crypto);
	apex_init_repos(apex, mrepo, crepo);

	err = apex_init_piper(apex);
	if (err) {
		goto out_err;
	}
	err = apex_init_iconv(apex);
	if (err) {
		goto out_err;
	}
	return 0;
out_err:
	silofs_apex_fini(apex);
	return err;
}

void silofs_apex_fini(struct silofs_fs_apex *apex)
{
	apex_fini_iconv(apex);
	apex_fini_piper(apex);
	apex_fini_repos(apex);
	apex_fini_commons(apex);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_apex_relax_caches(const struct silofs_fs_apex *apex, int flags)
{
	if (apex->ap_sbi) {
		silofs_relax_inomap_of(apex->ap_sbi, flags);
	}
	if (apex->ap_mrepo) {
		silofs_repo_relax_cache(apex->ap_mrepo, flags);
	}
	if (apex->ap_crepo) {
		silofs_repo_relax_cache(apex->ap_crepo, flags);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void make_supers_blobid(struct silofs_blobid *out_blobid)
{
	struct silofs_xid treeid;
	const size_t obj_size = SILOFS_BK_SIZE;
	const size_t nobjs = SILOFS_NBK_IN_VSEC;

	silofs_xid_generate(&treeid);
	silofs_blobid_make_tas(out_blobid, &treeid, obj_size, nobjs);
}

static void make_super_uaddr(const struct silofs_blobid *blobid,
                             struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr_setup(out_uaddr, blobid, 0,
	                   SILOFS_STYPE_SUPER, SILOFS_SUPER_HEIGHT, 0);
}

static void make_stats_uaddr(const struct silofs_blobid *blobid,
                             struct silofs_uaddr *out_uaddr)
{
	silofs_uaddr_setup(out_uaddr, blobid, SILOFS_BK_SIZE,
	                   SILOFS_STYPE_STATS, SILOFS_SUPER_HEIGHT, 0);
}

/*. . . . . . . . . . . . . . . b. . . . . . . . . . . . . . . . . . . . . .*/

static void apex_bind_sbi(struct silofs_fs_apex *apex,
                          struct silofs_sb_info *sbi_new)
{
	struct silofs_sb_info *sbi_cur = apex->ap_sbi;

	if (sbi_cur != NULL) {
		silofs_sbi_decref(sbi_cur);
	}
	if (sbi_new != NULL) {
		silofs_sbi_incref(sbi_new);
	}
	apex->ap_sbi = sbi_new;
}

static int apex_spawn_super_at(struct silofs_fs_apex *apex,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = silofs_spawn_super_at(apex->ap_mrepo, uaddr, &sbi);
	if (err) {
		return err;
	}
	silofs_sbi_setup_spawned(sbi);
	silofs_sbi_bind_apex(sbi, apex);

	*out_sbi = sbi;
	return 0;
}

static int apex_spawn_super_of(struct silofs_fs_apex *apex,
                               struct silofs_sb_info **out_sbi)
{
	struct silofs_blobid blobid = { .size = 0 };
	struct silofs_uaddr uaddr = { .voff = -1 };

	make_supers_blobid(&blobid);
	make_super_uaddr(&blobid, &uaddr);

	return apex_spawn_super_at(apex, &uaddr, out_sbi);
}

static int apex_spawn_stats_at(struct silofs_fs_apex *apex,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_stats_info **out_sti)
{
	int err;

	err = silofs_spawn_stats_at(apex->ap_mrepo, uaddr, out_sti);
	if (err) {
		return err;
	}
	silofs_sti_setup_spawned(*out_sti);
	silofs_sti_bind_apex(*out_sti, apex);
	return 0;
}

static int apex_spawn_stats_of(struct silofs_fs_apex *apex,
                               struct silofs_sb_info *sbi,
                               struct silofs_stats_info **out_sti)
{
	struct silofs_uaddr uaddr;
	int ret;

	make_stats_uaddr(sbi_blobid(sbi), &uaddr);
	sbi_incref(sbi);
	ret = apex_spawn_stats_at(apex, &uaddr, out_sti);
	sbi_decref(sbi);
	return ret;
}

int silofs_apex_spawn_supers(struct silofs_fs_apex *apex, size_t capacity,
                             struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = NULL;
	struct silofs_stats_info *sti = NULL;
	int err;

	err = apex_spawn_super_of(apex, &sbi);
	if (err) {
		return err;
	}
	silofs_sbi_setup_btime(sbi);

	err = apex_spawn_stats_of(apex, sbi, &sti);
	if (err) {
		return err;
	}

	silofs_sti_set_capacity(sti, capacity);
	silofs_sbi_set_stats_uaddr(sbi, sti_uaddr(sti));
	silofs_sbi_bind_stats(sbi, sti);

	*out_sbi = sbi;
	return 0;
}

static int apex_stage_super_at(struct silofs_fs_apex *apex,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_sb_info **out_sbi)
{
	int err;

	err = silofs_stage_super_at(apex->ap_mrepo, uaddr, out_sbi);
	if (err) {
		return err;
	}
	silofs_sbi_bind_apex(*out_sbi, apex);
	return 0;
}

static int apex_stage_stats_at(struct silofs_fs_apex *apex,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_stats_info **out_sti)
{
	int err;

	err = silofs_stage_stats_at(apex->ap_mrepo, uaddr, out_sti);
	if (err) {
		return err;
	}
	silofs_sti_bind_apex(*out_sti, apex);
	return 0;
}

static int apex_stage_stats_of(struct silofs_fs_apex *apex,
                               struct silofs_sb_info *sbi,
                               struct silofs_stats_info **out_sti)
{
	struct silofs_uaddr uaddr;
	int err;

	err = silofs_sbi_stats_uaddr(sbi, &uaddr);
	if (!err) {
		sbi_incref(sbi);
		err = apex_stage_stats_at(apex, &uaddr, out_sti);
		sbi_decref(sbi);
	}
	return err;
}

int silofs_apex_stage_supers(struct silofs_fs_apex *apex,
                             const struct silofs_uaddr *uaddr,
                             struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = NULL;
	struct silofs_stats_info *sti = NULL;
	int err;

	err = apex_stage_super_at(apex, uaddr, &sbi);
	if (err) {
		return err;
	}
	err = apex_stage_stats_of(apex, sbi, &sti);
	if (err) {
		return err;
	}
	silofs_sbi_bind_stats(sbi, sti);
	*out_sbi = sbi;
	return 0;
}

static void sbi_account_supers_of(struct silofs_sb_info *sbi)
{
	struct silofs_stats_info *sti = sbi->sb_sti;

	silofs_sti_update_curr(sti, SILOFS_STYPE_SUPER, 1);
	silofs_sti_update_curr(sti, SILOFS_STYPE_STATS, 1);
}

int silofs_apex_format_supers(struct silofs_fs_apex *apex, size_t capacity)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = silofs_apex_spawn_supers(apex, capacity, &sbi);
	if (err) {
		return err;
	}
	sbi_account_supers_of(sbi);
	apex_bind_sbi(apex, sbi);
	return 0;
}

int silofs_apex_reload_supers(struct silofs_fs_apex *apex,
                              const struct silofs_uaddr *sb_uaddr)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = silofs_apex_stage_supers(apex, sb_uaddr, &sbi);
	if (err) {
		return err;
	}
	apex_bind_sbi(apex, sbi);
	return 0;
}

static void sbi_make_clone(struct silofs_sb_info *sbi_new,
                           const struct silofs_sb_info *sbi_cur)
{
	struct silofs_stats_info *sti_new = sbi_new->sb_sti;
	struct silofs_stats_info *sti_cur = sbi_cur->sb_sti;

	silofs_sti_make_clone(sti_new, sti_cur);
	silofs_sbi_make_clone(sbi_new, sbi_cur);
	silofs_sbi_set_stats_uaddr(sbi_new, sti_uaddr(sti_new));
	silofs_sbi_setup_ctime(sbi_new);

	sbi_account_supers_of(sbi_new);
}

void silofs_apex_shut(struct silofs_fs_apex *apex)
{
	apex_bind_sbi(apex, NULL);
}

static int apex_clone_rebind_supers(struct silofs_fs_apex *apex,
                                    const struct silofs_sb_info *sbi_cur,
                                    struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = silofs_apex_spawn_supers(apex, 0, &sbi);
	if (err) {
		return err;
	}
	sbi_make_clone(sbi, sbi_cur);
	apex_bind_sbi(apex, sbi);

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

int silofs_apex_forkfs(struct silofs_fs_apex *apex,
                       struct silofs_bootsec *out_bsec)
{
	struct silofs_sb_info *sbi_fork = NULL;
	struct silofs_sb_info *sbi_next = NULL;
	struct silofs_sb_info *sbi_curr = apex->ap_sbi;
	int err;

	err = apex_clone_rebind_supers(apex, sbi_curr, &sbi_fork);
	if (err) {
		return err;
	}
	err = apex_clone_rebind_supers(apex, sbi_curr, &sbi_next);
	if (err) {
		return err;
	}
	sbi_mark_fossil(sbi_curr);
	sbi_export_bootsec(sbi_fork, out_bsec);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_exec_kcopy_by(struct silofs_fs_apex *apex,
                         const struct silofs_xiovec *xiov_src,
                         const struct silofs_xiovec *xiov_dst, size_t len)
{
	struct silofs_piper *piper = &apex->ap_piper;
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

