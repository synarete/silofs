/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2021 Shachar Sharon
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
#include <silofs/fs/repo.h>
#include <silofs/fs/boot.h>
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

	silofs_allocstat(apex->fa_alif, &st);
	lim = (st.memsz_data / (2 * SILOFS_BK_SIZE));
	return div_round_up(lim, align) * align;
}

static void apex_init_commons(struct silofs_fs_apex *apex,
                              struct silofs_repo *repo,
                              struct silofs_crypto *crypto)
{
	apex->fa_initime = silofs_time_now();
	apex->fa_repo = repo;
	apex->fa_cache = repo->re_cache;
	apex->fa_alif = apex->fa_cache->c_alif;
	apex->fa_qalloc = apex->fa_cache->c_qalloc;
	apex->fa_crypto = crypto;
	apex->fa_iconv = (iconv_t)(-1);
	apex->fa_mbr = NULL;
	apex->fa_sbi = NULL;

	apex->fa_ops.op_iopen_max = 0;
	apex->fa_ops.op_iopen = 0;
	apex->fa_ops.op_time = silofs_time_now();
	apex->fa_ops.op_count = 0;
	apex->fa_ops.op_iopen_max = apex_calc_iopen_limit(apex);
}

static void apex_fini_commons(struct silofs_fs_apex *apex)
{
	apex->fa_repo = NULL;
	apex->fa_cache = NULL;
	apex->fa_alif = NULL;
	apex->fa_qalloc = NULL;
	apex->fa_crypto = NULL;
	apex->fa_iconv = (iconv_t)(-1);
	apex->fa_mbr = NULL;
	apex->fa_sbi = NULL;
}

static int apex_init_piper(struct silofs_fs_apex *apex)
{
	int err;
	struct silofs_pipe *pipe = &apex->fa_pipe;
	struct silofs_nilfd *nilfd = &apex->fa_nilfd;
	const size_t pipe_size_want = SILOFS_BK_SIZE;

	silofs_pipe_init(pipe);
	err = silofs_pipe_open(pipe);
	if (err) {
		return err;
	}
	err = silofs_pipe_setsize(pipe, pipe_size_want);
	if (err) {
		silofs_pipe_fini(pipe);
		return err;
	}
	err = silofs_nilfd_init(nilfd);
	if (err) {
		silofs_pipe_fini(pipe);
		return err;
	}
	return 0;
}

static void apex_fini_piper(struct silofs_fs_apex *apex)
{
	struct silofs_pipe *pipe = &apex->fa_pipe;
	struct silofs_nilfd *nilfd = &apex->fa_nilfd;

	silofs_nilfd_fini(nilfd);
	silofs_pipe_fini(pipe);
}

static int apex_init_iconv(struct silofs_fs_apex *apex)
{
	/* Using UTF32LE to avoid BOM (byte-order-mark) character */
	apex->fa_iconv = iconv_open("UTF32LE", "UTF8");
	if (apex->fa_iconv == (iconv_t)(-1)) {
		return errno ? -errno : -EOPNOTSUPP;
	}
	return 0;
}

static void apex_fini_iconv(struct silofs_fs_apex *apex)
{
	if (apex->fa_iconv != (iconv_t)(-1)) {
		iconv_close(apex->fa_iconv);
		apex->fa_iconv = (iconv_t)(-1);
	}
}

static int apex_init_mbr(struct silofs_fs_apex *apex)
{
	apex->fa_mbr = silofs_mbr_new(apex->fa_alif);

	return (apex->fa_mbr != NULL) ? 0 : -ENOMEM;
}

static void apex_fini_mbr(struct silofs_fs_apex *apex)
{
	if (apex->fa_mbr != NULL) {
		silofs_mbr_del(apex->fa_mbr, apex->fa_alif);
		apex->fa_mbr = NULL;
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
	err = apex_init_mbr(apex);
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
	apex_fini_mbr(apex);
	apex_fini_iconv(apex);
	apex_fini_piper(apex);
	apex_fini_commons(apex);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_apex_flush_dirty(struct silofs_fs_apex *apex, int flags)
{
	return silofs_repo_collect_flush(apex->fa_repo, flags);
}

int silofs_apex_spawn_blob(const struct silofs_fs_apex *apex,
                           const struct silofs_blobid *bid,
                           struct silofs_blob_info **out_bli)
{
	return silofs_repo_spawn_blob(apex->fa_repo, bid, out_bli);
}

int silofs_apex_stage_blob(const struct silofs_fs_apex *apex,
                           const struct silofs_blobid *bid,
                           struct silofs_blob_info **out_bli)
{
	return silofs_repo_stage_blob(apex->fa_repo, bid, out_bli);
}

int silofs_apex_resolve_sb_addr(const struct silofs_fs_apex *apex,
                                struct silofs_uaddr *out_uaddr)
{
	silofs_mbr_sb_ref(apex->fa_mbr, out_uaddr);
	return  0;
}

int silofs_apex_rebind_sb_addr(struct silofs_fs_apex *apex,
                               const struct silofs_uaddr *uaddr)
{
	silofs_mbr_set_sb_ref(apex->fa_mbr, uaddr);
	return  0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int apex_spawn_sb_blob(const struct silofs_fs_apex *apex,
                              const struct silofs_uaddr *uaddr,
                              struct silofs_blob_info **out_bli)
{
	const struct silofs_blobid *bid = &uaddr->oaddr.bid;

	return silofs_repo_spawn_blob(apex->fa_repo, bid, out_bli);
}

static int apex_spawn_sb_ubi(const struct silofs_fs_apex *apex,
                             const struct silofs_uaddr *uaddr,
                             struct silofs_ubk_info **out_ubi)
{
	*out_ubi = silofs_cache_spawn_ubk(apex->fa_cache, &uaddr->oaddr);

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

	ui = silofs_cache_spawn_unode(apex->fa_cache, uaddr);
	if (ui == NULL) {
		return -ENOMEM;
	}
	sbi = silofs_sbi_from_ui(ui);
	err = silofs_sbi_xinit(sbi, apex);
	if (err) {
		silofs_cache_forget_unode(apex->fa_cache, ui);
		return err;
	}
	silofs_sbi_update_by_args(sbi, apex->fa_args);
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
	treeid.id[0] ^= (uint64_t)(apex->fa_initime);
	silofs_blobid_make(out_bid, &treeid, obj_size, 1, height);
}


static void apex_make_super_uaddr(const struct silofs_fs_apex *apex,
                                  struct silofs_uaddr *out_uaddr)
{
	struct silofs_blobid bid;

	apex_make_super_blobid(apex, &bid);
	silofs_uaddr_make_for_super(out_uaddr, &bid);
}

static void
apex_setup_spawned_super(const struct silofs_fs_apex *apex,
                         struct silofs_sb_info *sbi, size_t capacity)
{
	silofs_sbi_setup_sb(sbi, capacity);
	silofs_sbi_update_birth_time(sbi, apex->fa_initime);
	silofs_sbi_dirtify(sbi);
}

int silofs_apex_spawn_super(struct silofs_fs_apex *apex,
                            struct silofs_sb_info **out_sbi)
{
	int err;
	size_t capacity;
	struct silofs_uaddr uaddr;
	struct silofs_blob_info *bli = NULL;
	struct silofs_ubk_info *ubi = NULL;
	struct silofs_sb_info *sbi = NULL;
	const size_t capacity_want = apex->fa_args->capacity;

	err = silofs_calc_fs_capacity(capacity_want, &capacity);
	if (err) {
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
	apex_setup_spawned_super(apex, sbi, capacity);

	*out_sbi = sbi;
	return 0;
}

int silofs_apex_stage_super(struct silofs_fs_apex *apex,
                            const struct silofs_uaddr *uaddr,
                            struct silofs_sb_info **out_sbi)
{
	int err;
	struct silofs_ubk_info *ubi = NULL;
	struct silofs_blob_info *bli = NULL;

	err = apex_spawn_sbi(apex, uaddr, out_sbi);
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
	silofs_sbi_attach_ubi(*out_sbi, ubi);
	return 0;
}

static int apex_fork_super(struct silofs_fs_apex *apex,
                           struct silofs_sb_info **out_sbi)
{
	int err;
	struct silofs_sb_info *sbi_new = NULL;
	struct silofs_sb_info *sbi_cur = apex->fa_sbi;

	silofs_assert_not_null(sbi_cur);

	err = silofs_apex_spawn_super(apex, &sbi_new);
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
	struct silofs_sb_info *sbi_cur = apex->fa_sbi;

	if (sbi_cur != NULL) {
		silofs_sbi_decref(sbi_cur);
	}
	if (sbi_new != NULL) {
		silofs_sbi_incref(sbi_new);
	}
	apex->fa_sbi = sbi_new;
}

static int apex_reref_sb_addr(struct silofs_fs_apex *apex,
                              const struct silofs_uaddr *uaddr)
{
	silofs_mbr_set_sb_ref(apex->fa_mbr, uaddr);
	return 0;
}

static int apex_make_root_name(const struct silofs_fs_apex *apex,
                               struct silofs_namestr *out_name)
{
	int err;
	const char *root_name = apex->fa_args->fsname;

	err = silofs_check_name(root_name);
	if (err) {
		return err;
	}
	out_name->str.str = root_name;
	out_name->str.len = strlen(root_name);
	return 0;
}

int silofs_apex_save_mbr_at(struct silofs_fs_apex *apex,
                            const struct silofs_sb_info *sbi,
                            const struct silofs_namestr *name)
{
	int err;
	struct silofs_main_bootrec *mbr = apex->fa_mbr;

	silofs_assert_not_null(mbr);

	err = apex_reref_sb_addr(apex, &sbi->s_ui.u_uaddr);
	if (err) {
		return err;
	}
	err = silofs_repo_save_ref(apex->fa_repo, name, mbr);
	if (err) {
		log_err("failed to save mbr: err=%d", err);
		return err;
	}
	return 0;
}

int silofs_apex_save_root_mbr(struct silofs_fs_apex *apex)
{
	int err;
	struct silofs_namestr name;

	err = apex_make_root_name(apex, &name);
	if (err) {
		return err;
	}
	err = silofs_apex_save_mbr_at(apex, apex->fa_sbi, &name);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_apex_load_mbr_at(struct silofs_fs_apex *apex,
                            const struct silofs_namestr *name)
{
	int err;
	struct silofs_main_bootrec *mbr = apex->fa_mbr;

	err = silofs_repo_load_ref(apex->fa_repo, name, mbr);
	if (err) {
		log_err("failed to load mbr: err=%d", err);
		return err;
	}
	err = silofs_mbr_check(mbr);
	if (err) {
		log_err("loaded bad mbr: err=%d", err);
		return err;
	}
	return 0;
}

int silofs_apex_load_root_mbr(struct silofs_fs_apex *apex)
{
	int err;
	struct silofs_namestr name;

	err = apex_make_root_name(apex, &name);
	if (err) {
		return err;
	}
	err = silofs_apex_load_mbr_at(apex, &name);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_apex_forkfs(struct silofs_fs_apex *apex,
                       const struct silofs_namestr *name)
{
	int err;
	struct silofs_sb_info *sbi_fork = NULL;
	struct silofs_sb_info *sbi_next = NULL;

	err = silofs_apex_flush_dirty(apex, SILOFS_F_NOW);
	if (err) {
		return err;
	}
	err = apex_fork_super(apex, &sbi_fork);
	if (err) {
		return err;
	}
	err = silofs_apex_save_mbr_at(apex, sbi_fork, name);
	if (err) {
		return err;
	}
	err = apex_fork_super(apex, &sbi_next);
	if (err) {
		return err;
	}
	silofs_apex_bind_to_sbi(apex, sbi_next);
	err = silofs_apex_save_root_mbr(apex);
	if (err) {
		return err;
	}
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_apex_kcopy(struct silofs_fs_apex *apex,
                      const struct silofs_fiovec *fiov_src,
                      const struct silofs_fiovec *fiov_dst, size_t n)
{
	loff_t off_src = fiov_src->fv_off;
	loff_t off_dst = fiov_dst->fv_off;
	const int fd_src = fiov_src->fv_fd;
	const int fd_dst = fiov_dst->fv_fd;

	return silofs_kcopy_with_splice(&apex->fa_pipe, &apex->fa_nilfd,
	                                fd_src, &off_src, fd_dst, &off_dst, n);
}


