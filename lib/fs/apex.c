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
#include <silofs/fs/repo.h>
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
                              struct silofs_repo *repo,
                              struct silofs_crypto *crypto)
{
	apex->ap_initime = silofs_time_now();
	apex->ap_repo = repo;
	apex->ap_cache = repo->re_cache;
	apex->ap_alif = apex->ap_cache->c_alif;
	apex->ap_qalloc = apex->ap_cache->c_qalloc;
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
	apex->ap_repo = NULL;
	apex->ap_cache = NULL;
	apex->ap_alif = NULL;
	apex->ap_qalloc = NULL;
	apex->ap_crypto = NULL;
	apex->ap_iconv = (iconv_t)(-1);
	apex->ap_sbi = NULL;
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
                     struct silofs_repo *repo, struct silofs_crypto *crypto)
{
	int err;

	apex_init_commons(apex, repo, crypto);
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
	apex_fini_commons(apex);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_apex_flush_dirty(struct silofs_fs_apex *apex, int flags)
{
	return silofs_repo_collect_flush(apex->ap_repo, flags);
}

int silofs_apex_spawn_blob(const struct silofs_fs_apex *apex,
                           const struct silofs_blobid *bid,
                           struct silofs_blob_info **out_bli)
{
	return silofs_repo_spawn_blob(apex->ap_repo, bid, out_bli);
}

int silofs_apex_stage_blob(const struct silofs_fs_apex *apex,
                           const struct silofs_blobid *bid,
                           struct silofs_blob_info **out_bli)
{
	return silofs_repo_stage_blob(apex->ap_repo, bid, out_bli);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int apex_spawn_sb_blob(const struct silofs_fs_apex *apex,
                              const struct silofs_uaddr *uaddr,
                              struct silofs_blob_info **out_bli)
{
	const struct silofs_blobid *bid = &uaddr->oaddr.bid;

	return silofs_repo_spawn_blob(apex->ap_repo, bid, out_bli);
}

static int apex_spawn_sb_ubi(const struct silofs_fs_apex *apex,
                             const struct silofs_uaddr *uaddr,
                             struct silofs_ubk_info **out_ubi)
{
	*out_ubi = silofs_cache_spawn_ubk(apex->ap_cache, &uaddr->oaddr);

	return (*out_ubi != NULL) ? 0 : -ENOMEM;
}

static int apex_spawn_sb_block(const struct silofs_fs_apex *apex,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_blob_info **out_bli,
                               struct silofs_ubk_info **out_ubi)
{
	int err;
	struct silofs_blob_info *bli = NULL;

	err = apex_spawn_sb_blob(apex, uaddr, &bli);
	if (err) {
		return err;
	}
	bli_incref(bli);
	err = apex_spawn_sb_ubi(apex, uaddr, out_ubi);
	bli_decref(bli);
	if (err) {
		return err;
	}
	*out_bli = bli;
	return 0;
}

static int apex_spawn_sbi(struct silofs_fs_apex *apex,
                          const struct silofs_uaddr *uaddr,
                          struct silofs_sb_info **out_sbi)
{
	int err;
	struct silofs_unode_info *ui = NULL;
	struct silofs_sb_info *sbi = NULL;

	ui = silofs_cache_spawn_unode(apex->ap_cache, uaddr);
	if (ui == NULL) {
		return -ENOMEM;
	}
	sbi = silofs_sbi_from_ui(ui);
	err = silofs_sbi_xinit(sbi, apex);
	if (err) {
		silofs_cache_forget_unode(apex->ap_cache, ui);
		return err;
	}
	silofs_sbi_update_by_args(sbi, apex->ap_args);
	*out_sbi = sbi;
	return 0;
}

static void apex_make_super_blobid(const struct silofs_fs_apex *apex,
                                   struct silofs_blobid *out_bid)
{
	struct silofs_metaid treeid;
	const size_t height = SILOFS_SUPER_HEIGHT;
	const size_t obj_size = stype_size(SILOFS_STYPE_SUPER);

	silofs_metaid_generate(&treeid);
	treeid.id[0] ^= (uint64_t)(apex->ap_initime);
	silofs_blobid_make(out_bid, &treeid, obj_size, 1, height);
}


static void apex_make_super_uaddr(const struct silofs_fs_apex *apex,
                                  struct silofs_uaddr *out_uaddr)
{
	struct silofs_blobid bid;

	apex_make_super_blobid(apex, &bid);
	silofs_uaddr_make_super(out_uaddr, &bid);
}

int silofs_apex_spawn_super(struct silofs_fs_apex *apex, size_t cap_want,
                            const struct silofs_namestr *name,
                            struct silofs_sb_info **out_sbi)
{
	int err;
	size_t capacity;
	struct silofs_uaddr uaddr;
	struct silofs_blob_info *bli = NULL;
	struct silofs_ubk_info *ubi = NULL;
	struct silofs_sb_info *sbi = NULL;
	const time_t btime = silofs_time_now();

	err = silofs_calc_fs_capacity(cap_want, &capacity);
	if (err) {
		log_err("illegal capacity: cap=%lu err=%d", cap_want, err);
		return err;
	}
	apex_make_super_uaddr(apex, &uaddr);
	err = apex_spawn_sbi(apex, &uaddr, &sbi);
	if (err) {
		return err;
	}
	err = apex_spawn_sb_block(apex, &uaddr, &bli, &ubi);
	if (err) {
		return err;
	}
	silofs_sbi_attach_ubi(sbi, ubi);
	silofs_sbi_setup_spawned(sbi, name, capacity, btime);

	*out_sbi = sbi;
	return 0;
}

int silofs_apex_stage_super(struct silofs_fs_apex *apex,
                            const struct silofs_namestr *name,
                            const struct silofs_uaddr *uaddr,
                            struct silofs_sb_info **out_sbi)
{
	int err;
	struct silofs_ubk_info *ubi = NULL;
	struct silofs_blob_info *bli = NULL;
	struct silofs_sb_info *sbi = NULL;

	err = apex_spawn_sbi(apex, uaddr, &sbi);
	if (err) {
		return err;
	}
	err = apex_spawn_sb_block(apex, uaddr, &bli, &ubi);
	if (err) {
		return err;
	}
	err = silofs_bli_load_bk(bli, ubi->ubk, &uaddr->oaddr);
	if (err) {
		return err;
	}
	silofs_sbi_attach_ubi(sbi, ubi);
	silofs_sbi_update_bootsec(sbi, name);
	*out_sbi = sbi;
	return 0;
}

static int apex_fork_super(struct silofs_fs_apex *apex,
                           const struct silofs_namestr *name,
                           struct silofs_sb_info **out_sbi)
{
	struct silofs_sb_info *sbi_new = NULL;
	struct silofs_sb_info *sbi_cur = apex->ap_sbi;
	size_t capacity;
	int err;

	silofs_assert_not_null(sbi_cur);

	capacity = silofs_sbi_vspace_capacity(sbi_cur);
	err = silofs_apex_spawn_super(apex, capacity, name, &sbi_new);
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
	silofs_apex_unlock_bootsec(apex);
	silofs_apex_bind_to_sbi(apex, NULL);
}

static int apex_boot_fsname(const struct silofs_fs_apex *apex,
                            struct silofs_namestr *out_name)
{
	const char *fsname = apex->ap_args->fsname;
	int ret;

	silofs_namestr_init(out_name, fsname);
	ret = silofs_check_fs_name(out_name);
	if (ret) {
		log_warn("illegal fs name: %s", fsname);
	}
	return ret;
}

bool silofs_apex_has_bootsec(const struct silofs_fs_apex *apex,
                             const struct silofs_namestr *name)
{
	struct silofs_bootsec bsec;
	int err;

	err = silofs_repo_load_bsec(apex->ap_repo, name, &bsec);
	return (err == 0);
}

int silofs_apex_load_bootsec(const struct silofs_fs_apex *apex,
                             struct silofs_bootsec *out_bsec)
{
	struct silofs_namestr name;
	int err;

	err = apex_boot_fsname(apex, &name);
	if (err) {
		return err;
	}
	err = silofs_repo_load_bsec(apex->ap_repo, &name, out_bsec);
	if (err) {
		log_warn("failed to load bootsec: %s err=%d",
		         name.str.str, err);
		return err;
	}
	return 0;
}

int silofs_apex_lock_bootsec(struct silofs_fs_apex *apex)
{
	struct silofs_namestr name;
	int *pfd = &apex->ap_slock_fd;
	int err;

	if (*pfd > 0) {
		return 0;
	}
	err = apex_boot_fsname(apex, &name);
	if (err) {
		return err;
	}
	err = silofs_repo_lock_bsec(apex->ap_repo, &name, pfd);
	if (err) {
		log_warn("failed to lock bootsec: %s err=%d",
		         name.str.str, err);
		return err;
	}
	return 0;
}

int silofs_apex_unlock_bootsec(struct silofs_fs_apex *apex)
{
	struct silofs_namestr name;
	int *pfd = &apex->ap_slock_fd;
	int err;

	if (*pfd < 0) {
		return 0;
	}
	err = apex_boot_fsname(apex, &name);
	if (err) {
		return err;
	}
	err = silofs_repo_unlock_bsec(apex->ap_repo, &name, pfd);
	if (err && (err != -ENOENT)) {
		log_warn("failed to unlock bootsec: %s err=%d",
		         name.str.str, err);
		return err;
	}
	return 0;
}

static int apex_relock_bootsec(struct silofs_fs_apex *apex)
{
	int err;

	err = silofs_apex_unlock_bootsec(apex);
	if (err) {
		return err;
	}
	err = silofs_apex_lock_bootsec(apex);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_apex_forkfs(struct silofs_fs_apex *apex,
                       const struct silofs_namestr *name)
{
	struct silofs_namestr ncur = { .str.len = 0 };
	struct silofs_sb_info *sbi_fork = NULL;
	struct silofs_sb_info *sbi_next = NULL;
	struct silofs_sb_info *sbi_curr = apex->ap_sbi;
	int err;

	silofs_sbi_name(sbi_curr, &ncur);
	err = apex_fork_super(apex, name, &sbi_fork);
	if (err) {
		return err;
	}
	err = apex_fork_super(apex, &ncur, &sbi_next);
	if (err) {
		return err;
	}
	err = silofs_sbi_save_bootsec(sbi_fork);
	if (err) {
		return err;
	}
	err = silofs_sbi_save_bootsec(sbi_next);
	if (err) {
		return err;
	}
	silofs_apex_bind_to_sbi(apex, sbi_next);
	err = apex_relock_bootsec(apex);
	if (err) {
		return err;
	}

	silofs_sbi_set_fossil(sbi_curr);
	err = silofs_apex_flush_dirty(apex, SILOFS_F_NOW);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_apex_kcopy(struct silofs_fs_apex *apex,
                      const struct silofs_fiovec *fiov_src,
                      const struct silofs_fiovec *fiov_dst, size_t len)
{
	loff_t off_src = fiov_src->fv_off;
	loff_t off_dst = fiov_dst->fv_off;

	return silofs_piper_kcopy(&apex->ap_piper,
	                          fiov_src->fv_fd, &off_src,
	                          fiov_dst->fv_fd, &off_dst, len);
}


