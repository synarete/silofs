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
#include <silofs/fs/cache.h>
#include <silofs/fs/boot.h>
#include <silofs/fs/nodes.h>
#include <silofs/fs/repo.h>
#include <silofs/fs/itable.h>
#include <silofs/fs/super.h>
#include <silofs/fs/namei.h>
#include <silofs/fs/apex.h>
#include <silofs/fs/private.h>
#include <stdlib.h>
#include <iconv.h>


static size_t apex_calc_iopen_limit(const struct silofs_fs_apex *apex)
{
	size_t lim;
	const size_t align = 128;
	struct silofs_alloc_stat st;

	silofs_allocstat(apex->ap_alif, &st);
	lim = (st.memsz_data / (2 * SILOFS_BK_SIZE));
	return div_round_up(lim, align) * align;
}

static void apex_init_commons(struct silofs_fs_apex *apex,
                              struct silofs_alloc_if *alif,
                              struct silofs_crypto *crypto)

{
	apex->ap_initime = silofs_time_now();
	apex->ap_alif = alif;
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
	apex->ap_alif = NULL;
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
                     struct silofs_alloc_if *alif,
                     struct silofs_crypto *crypto,
                     struct silofs_repo *mrepo,
                     struct silofs_repo *crepo)
{
	int err;

	apex_init_commons(apex, alif, crypto);
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

int silofs_apex_flush_dirty(const struct silofs_fs_apex *apex, int flags)
{
	return silofs_repo_collect_flush(apex->ap_mrepo, flags);
}

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

static void apex_make_super_blobid(const struct silofs_fs_apex *apex,
                                   struct silofs_blobid *out_blobid)
{
	struct silofs_xid treeid;
	const size_t obj_size = stype_size(SILOFS_STYPE_SUPER);

	silofs_xid_generate(&treeid);
	silofs_blobid_make_tas(out_blobid, &treeid, obj_size, 1);
	silofs_unused(apex);
}

static void apex_make_super_uaddr(const struct silofs_fs_apex *apex,
                                  struct silofs_uaddr *out_uaddr)
{
	struct silofs_blobid blobid;

	apex_make_super_blobid(apex, &blobid);
	silofs_uaddr_make_super(out_uaddr, &blobid);
}

int silofs_apex_spawn_super(struct silofs_fs_apex *apex, size_t capacity,
                            struct silofs_sb_info **out_sbi)
{
	struct silofs_uaddr uaddr;
	int err;

	apex_make_super_uaddr(apex, &uaddr);
	err = silofs_repo_spawn_super(apex->ap_mrepo, &uaddr, out_sbi);
	if (err) {
		return err;
	}
	silofs_sbi_setup_spawned(*out_sbi, capacity, silofs_time_now());
	silofs_sbi_bind_apex(*out_sbi, apex);
	return 0;
}

int silofs_apex_stage_super(struct silofs_fs_apex *apex,
                            const struct silofs_uaddr *uaddr,
                            struct silofs_sb_info **out_sbi)
{
	struct silofs_repo *repo = apex->ap_mrepo;
	struct silofs_sb_info *sbi = NULL;
	int err;

	err = silofs_repo_stage_super(repo, uaddr, &sbi);
	if (!err) {
		goto out_ok;
	}
	if (err != -ENOMEM) {
		goto out_err;
	}
	err = silofs_apex_flush_dirty(apex, SILOFS_F_NOW);
	if (err) {
		goto out_err;
	}
	err = silofs_repo_stage_super(repo, uaddr, &sbi);
	if (err) {
		goto out_err;
	}
out_ok:
	silofs_sbi_bind_apex(sbi, apex);
	*out_sbi = sbi;
	return 0;
out_err:
	return err;
}

static int apex_fork_super(struct silofs_fs_apex *apex,
                           struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi_new = NULL;
	struct silofs_sb_info *sbi_cur = apex->ap_sbi;
	size_t capacity;
	int err;

	silofs_assert_not_null(sbi_cur);

	capacity = silofs_sbi_vspace_capacity(sbi_cur);
	err = silofs_apex_spawn_super(apex, capacity, &sbi_new);
	if (err) {
		return err;
	}
	silofs_sbi_clone_from(sbi_new, sbi_cur);
	*out_sbi = sbi_new;
	return 0;
}

void silofs_apex_bind_to_sbi(struct silofs_fs_apex *apex,
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

void silofs_apex_shut(struct silofs_fs_apex *apex)
{
	silofs_apex_unlock_boot(apex);
	silofs_apex_bind_to_sbi(apex, NULL);
}

static bool apex_is_cold_source(const struct silofs_fs_apex *apex)
{
	return apex->ap_args->restore && (apex->ap_crepo != NULL);
}

static const char *apex_boot_name(const struct silofs_fs_apex *apex)
{
	return apex_is_cold_source(apex) ?
	       apex->ap_args->cold_name : apex->ap_args->main_name;
}

static const struct silofs_repo *
apex_boot_repo(const struct silofs_fs_apex *apex)
{
	return apex_is_cold_source(apex) ? apex->ap_crepo : apex->ap_mrepo;
}

int silofs_apex_boot_name(const struct silofs_fs_apex *apex,
                          struct silofs_namestr *out_name)
{
	const char *name = apex_boot_name(apex);
	int ret;

	silofs_namestr_init(out_name, name);
	ret = silofs_check_fs_name(out_name);
	if (ret) {
		log_warn("illegal name: %s", name);
	}
	return ret;
}

int silofs_apex_save_boot(const struct silofs_fs_apex *apex,
                          const struct silofs_bootsec *bsec,
                          const struct silofs_namestr *name)
{
	return silofs_repo_save_bsec(apex_boot_repo(apex), bsec, name);
}

int silofs_apex_load_boot(const struct silofs_fs_apex *apex,
                          const struct silofs_namestr *name,
                          struct silofs_bootsec *out_bsec)
{
	int err;

	err = silofs_repo_load_bsec(apex_boot_repo(apex), name, out_bsec);
	if (err) {
		log_warn("failed to load bootsec: %s err=%d",
		         name->str.str, err);
	}
	return err;
}

int silofs_apex_lock_boot(struct silofs_fs_apex *apex)
{
	struct silofs_namestr name;
	int *pfd = &apex->ap_slock_fd;
	int err;

	if (*pfd > 0) {
		return 0;
	}
	err = silofs_apex_boot_name(apex, &name);
	if (err) {
		return err;
	}
	err = silofs_repo_lock_bsec(apex_boot_repo(apex), &name, pfd);
	if (err) {
		log_warn("failed to lock: %s err=%d", name.str.str, err);
		return err;
	}
	return 0;
}

int silofs_apex_unlock_boot(struct silofs_fs_apex *apex)
{
	struct silofs_namestr name;
	int *pfd = &apex->ap_slock_fd;
	int err;

	if (*pfd < 0) {
		return 0;
	}
	err = silofs_apex_boot_name(apex, &name);
	if (err) {
		return err;
	}
	err = silofs_repo_unlock_bsec(apex_boot_repo(apex), &name, pfd);
	if (err && (err != -ENOENT)) {
		log_warn("failed to unlock: %s err=%d", name.str.str, err);
		return err;
	}
	return 0;
}

static int apex_relock_boot(struct silofs_fs_apex *apex)
{
	int err;

	err = silofs_apex_unlock_boot(apex);
	if (err) {
		return err;
	}
	err = silofs_apex_lock_boot(apex);
	if (err) {
		return err;
	}
	return 0;
}

static void sbi_set_fossil(struct silofs_sb_info *sbi)
{
	silofs_sbi_add_flags(sbi, SILOFS_SUPERF_FOSSIL);
	silofs_sbi_dirtify(sbi);
}

static int apex_save_bootsec_of(struct silofs_fs_apex *apex,
                                const struct silofs_sb_info *sbi,
                                const struct silofs_namestr *name)
{
	struct silofs_bootsec bsec;

	silofs_bootsec_init(&bsec);
	silofs_bootsec_set_uaddr(&bsec, sbi_uaddr(sbi));
	return silofs_apex_save_boot(apex, &bsec, name);
}

int silofs_apex_forkfs(struct silofs_fs_apex *apex,
                       const struct silofs_namestr *name)
{
	struct silofs_namestr ncur = { .str.len = 0 };
	struct silofs_sb_info *sbi_fork = NULL;
	struct silofs_sb_info *sbi_next = NULL;
	struct silofs_sb_info *sbi_curr = apex->ap_sbi;
	int err;

	silofs_apex_main_fsname(apex, &ncur);
	err = apex_fork_super(apex, &sbi_fork);
	if (err) {
		return err;
	}
	err = apex_fork_super(apex, &sbi_next);
	if (err) {
		return err;
	}
	err = apex_save_bootsec_of(apex, sbi_fork, name);
	if (err) {
		return err;
	}
	err = apex_save_bootsec_of(apex, sbi_next, &ncur);
	if (err) {
		return err;
	}
	silofs_apex_bind_to_sbi(apex, sbi_next);
	err = apex_relock_boot(apex);
	if (err) {
		return err;
	}
	sbi_set_fossil(sbi_curr);
	return 0;
}

void silofs_apex_main_fsname(const struct silofs_fs_apex *apex,
                             struct silofs_namestr *out_name)
{
	const struct silofs_fs_args *fs_args = apex->ap_args;

	silofs_namestr_init(out_name, fs_args->main_name);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_apex_kcopy(struct silofs_fs_apex *apex,
                      const struct silofs_xiovec *xiov_src,
                      const struct silofs_xiovec *xiov_dst, size_t len)
{
	loff_t off_src = xiov_src->xiov_off;
	loff_t off_dst = xiov_dst->xiov_off;

	return silofs_piper_kcopy(&apex->ap_piper,
	                          xiov_src->xiov_fd, &off_src,
	                          xiov_dst->xiov_fd, &off_dst, len);
}

