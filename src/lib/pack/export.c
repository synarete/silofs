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
#include <silofs/infra.h>
#include <silofs/vol.h>
#include <silofs/fs.h>
#include <silofs/pack.h>


struct silofs_pack_export_ctx {
	struct silofs_mdigest   pex_mdigest;
	struct silofs_listq     pex_descq;
	struct silofs_pack_args pex_args;
	struct silofs_task     *pex_task;
	struct silofs_alloc    *pex_alloc;
	struct silofs_repo     *pex_repo;
	int pex_dfd;
};

struct silofs_pack_desc_info {
	struct silofs_list_head pdi_lh;
	struct silofs_pack_desc pd;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_pack_desc_info *pdi_from_lh(struct silofs_list_head *lh)
{
	struct silofs_pack_desc_info *pdi = NULL;

	if (lh != NULL) {
		pdi = container_of(lh, struct silofs_pack_desc_info, pdi_lh);
	}
	return pdi;
}

static struct silofs_pack_desc_info *pdi_malloc(struct silofs_alloc *alloc)
{
	struct silofs_pack_desc_info *pdi = NULL;

	pdi = silofs_memalloc(alloc, sizeof(*pdi), 0);
	return pdi;
}

static void pdi_free(struct silofs_pack_desc_info *pdi,
                     struct silofs_alloc *alloc)
{
	silofs_memfree(alloc, pdi, sizeof(*pdi), 0);
}

static void pdi_init(struct silofs_pack_desc_info *pdi,
                     const struct silofs_laddr *laddr)
{
	silofs_list_head_init(&pdi->pdi_lh);
	silofs_pkdesc_init(&pdi->pd, laddr);
}

static void pdi_fini(struct silofs_pack_desc_info *pdi)
{
	silofs_list_head_fini(&pdi->pdi_lh);
	silofs_pkdesc_fini(&pdi->pd);
}

static struct silofs_pack_desc_info *
pdi_new(const struct silofs_laddr *laddr, struct silofs_alloc *alloc)
{
	struct silofs_pack_desc_info *pdi;

	pdi = pdi_malloc(alloc);
	if (pdi != NULL) {
		pdi_init(pdi, laddr);
	}
	return pdi;
}

static void pdi_del(struct silofs_pack_desc_info *pdi,
                    struct silofs_alloc *alloc)
{
	if (pdi != NULL) {
		pdi_fini(pdi);
		pdi_free(pdi, alloc);
	}
}

static void pdi_to_name(const struct silofs_pack_desc_info *pdi,
                        struct silofs_strbuf *out_name)
{
	silofs_pkdesc_to_name(&pdi->pd, out_name);
}

static bool pdi_isbootrec(const struct silofs_pack_desc_info *pdi)
{
	return (pdi->pd.pd_laddr.ltype == SILOFS_LTYPE_BOOTREC);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void pec_push_desc(struct silofs_pack_export_ctx *pe_ctx,
                          struct silofs_pack_desc_info *pdi)
{
	silofs_listq_push_back(&pe_ctx->pex_descq, &pdi->pdi_lh);
}

static struct silofs_pack_desc_info *
pec_pop_desc(struct silofs_pack_export_ctx *pe_ctx)
{
	struct silofs_list_head *lh;
	struct silofs_pack_desc_info *pdi = NULL;

	lh = silofs_listq_pop_front(&pe_ctx->pex_descq);
	if (lh != NULL) {
		pdi = pdi_from_lh(lh);
	}
	return pdi;
}

static void pec_clear_descq(struct silofs_pack_export_ctx *pe_ctx)
{
	struct silofs_pack_desc_info *pdi;

	pdi = pec_pop_desc(pe_ctx);
	while (pdi != NULL) {
		pdi_del(pdi, pe_ctx->pex_alloc);
		pdi = pec_pop_desc(pe_ctx);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int pec_init(struct silofs_pack_export_ctx *pe_ctx,
                    struct silofs_task *task,
                    const struct silofs_pack_args *pargs)
{
	silofs_memzero(pe_ctx, sizeof(*pe_ctx));
	silofs_listq_init(&pe_ctx->pex_descq);
	memcpy(&pe_ctx->pex_args, pargs, sizeof(pe_ctx->pex_args));
	pe_ctx->pex_task = task;
	pe_ctx->pex_alloc = task->t_fsenv->fse.alloc;
	pe_ctx->pex_repo = task->t_fsenv->fse.repo;
	pe_ctx->pex_dfd = -1;
	return silofs_mdigest_init(&pe_ctx->pex_mdigest);
}

static void pec_fini(struct silofs_pack_export_ctx *pe_ctx)
{
	pec_clear_descq(pe_ctx);
	silofs_listq_fini(&pe_ctx->pex_descq);
	silofs_mdigest_fini(&pe_ctx->pex_mdigest);
	silofs_memffff(pe_ctx, sizeof(*pe_ctx));
}

static int pec_connect_target(struct silofs_pack_export_ctx *pe_ctx)
{
	const char *path = pe_ctx->pex_args.remotedir;
	int dfd = -1;
	int err;

	err = silofs_sys_open(path, O_DIRECTORY | O_RDONLY, 0, &dfd);
	if (err) {
		log_err("failed to open remote: %s err=%d", path, err);
		return err;
	}
	log_dbg("opened archive-dir: %s", path);
	pe_ctx->pex_dfd = dfd;
	return 0;
}

static void pec_disconnect_target(struct silofs_pack_export_ctx *pe_ctx)
{
	int err;

	if (pe_ctx->pex_dfd > 0) {
		err = silofs_sys_closefd(&pe_ctx->pex_dfd);
		if (err) {
			log_err("failed to close remote: %s err=%d",
			        pe_ctx->pex_args.remotedir, err);
		}
	}
}

static int pec_send_to_remote(const struct silofs_pack_export_ctx *pe_ctx,
                              const struct silofs_pack_desc_info *pdi,
                              const void *data)
{
	struct silofs_strbuf name;
	int fd = -1;
	int err;

	pdi_to_name(pdi, &name);
	err = silofs_sys_openat(pe_ctx->pex_dfd, name.str,
	                        O_CREAT | O_RDWR, 0600, &fd);
	if (err) {
		log_dbg("remote: failed to create: %s err=%d", name.str, err);
		goto out;
	}
	err = silofs_sys_writen(fd, data, pdi->pd.pd_laddr.len);
	if (err) {
		log_dbg("remote: failed to write: %s len=%zu err=%d",
		        name.str, pdi->pd.pd_laddr.len, err);
		goto out;
	}
out:
	silofs_sys_closefd(&fd);
	return err;
}

static int pec_load_seg(const struct silofs_pack_export_ctx *pe_ctx,
                        const struct silofs_laddr *laddr, void *seg)
{
	int err;

	err = silofs_repo_read_at(pe_ctx->pex_repo, laddr, seg);
	if (err) {
		log_err("failed to read: ltype=%d len=%zu err=%d",
		        laddr->ltype, laddr->len, err);
	}
	return err;
}

static int pec_load_brec(const struct silofs_pack_export_ctx *pe_ctx,
                         const struct silofs_laddr *laddr,
                         struct silofs_bootrec1k *out_brec1k)
{
	int err;

	err = silofs_repo_load_obj(pe_ctx->pex_repo, laddr, out_brec1k);
	if (err) {
		log_err("failed to load: ltype=%d len=%zu err=%d",
		        laddr->ltype, laddr->len, err);
	}
	return err;
}

static int
pec_update_hash_of(const struct silofs_pack_export_ctx *pe_ctx,
                   struct silofs_pack_desc_info *pdi, const void *dat)
{
	const struct silofs_mdigest *md = &pe_ctx->pex_mdigest;
	const size_t len = pdi->pd.pd_laddr.len;

	silofs_pkdesc_update_hash(&pdi->pd, md, dat, len);
	return 0;
}

static int pec_process_segdata(const struct silofs_pack_export_ctx *pe_ctx,
                               struct silofs_pack_desc_info *pdi)
{
	const size_t seg_len = pdi->pd.pd_laddr.len;
	void *seg = NULL;
	int err = -SILOFS_ENOMEM;

	seg = silofs_memalloc(pe_ctx->pex_alloc, seg_len, 0);
	if (seg == NULL) {
		goto out;
	}
	err = pec_load_seg(pe_ctx, &pdi->pd.pd_laddr, seg);
	if (err) {
		goto out;
	}
	err = pec_update_hash_of(pe_ctx, pdi, seg);
	if (err) {
		goto out;
	}
	err = pec_send_to_remote(pe_ctx, pdi, seg);
	if (err) {
		goto out;
	}
out:
	silofs_memfree(pe_ctx->pex_alloc, seg, seg_len, 0);
	return err;
}

static int pec_process_bootrec(const struct silofs_pack_export_ctx *pe_ctx,
                               struct silofs_pack_desc_info *pdi)
{
	struct silofs_bootrec1k brec = { .br_magic = 0xFFFFFFFF };
	int err;

	err = pec_load_brec(pe_ctx, &pdi->pd.pd_laddr, &brec);
	if (err) {
		return err;
	}
	err = pec_update_hash_of(pe_ctx, pdi, &brec);
	if (err) {
		return err;
	}
	err = pec_send_to_remote(pe_ctx, pdi, &brec);
	if (err) {
		return err;
	}
	return 0;
}

static int pec_process_pdi(struct silofs_pack_export_ctx *pe_ctx,
                           struct silofs_pack_desc_info *pdi)
{
	int err;

	if (pdi_isbootrec(pdi)) {
		err = pec_process_bootrec(pe_ctx, pdi);
	} else {
		err = pec_process_segdata(pe_ctx, pdi);
	}
	return err;
}

static int pec_process_by_laddr(struct silofs_pack_export_ctx *pe_ctx,
                                const struct silofs_laddr *laddr)
{
	struct silofs_pack_desc_info *pdi = NULL;
	int err;

	pdi = pdi_new(laddr, pe_ctx->pex_alloc);
	if (pdi == NULL) {
		return -SILOFS_ENOMEM;
	}
	err = pec_process_pdi(pe_ctx, pdi);
	if (err) {
		pdi_del(pdi, pe_ctx->pex_alloc);
		return err;
	}
	pec_push_desc(pe_ctx, pdi);
	return 0;
}

static int pec_visit_laddr_cb(void *ctx, const struct silofs_laddr *laddr)
{
	struct silofs_pack_export_ctx *pe_ctx = ctx;

	return pec_process_by_laddr(pe_ctx, laddr);
}

static int pec_archive_fs(struct silofs_pack_export_ctx *pe_ctx)
{
	int err;

	err = pec_connect_target(pe_ctx);
	if (err) {
		goto out;
	}
	err = silofs_fs_inspect(pe_ctx->pex_task, pec_visit_laddr_cb, pe_ctx);
	if (err) {
		goto out;
	}
out:
	pec_disconnect_target(pe_ctx);
	return err;
}

int silofs_fs_export(struct silofs_task *task,
                     const struct silofs_pack_args *pargs)
{
	struct silofs_pack_export_ctx pe_ctx = {
		.pex_dfd = -1,
	};
	int err;

	err = pec_init(&pe_ctx, task, pargs);
	if (!err) {
		err = pec_archive_fs(&pe_ctx);
		pec_fini(&pe_ctx);
	}
	return err;
}
