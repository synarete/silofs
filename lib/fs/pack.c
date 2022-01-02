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
#include <silofs/infra.h>
#include <silofs/fs/address.h>
#include <silofs/fs/types.h>
#include <silofs/fs/crypto.h>
#include <silofs/fs/cache.h>
#include <silofs/fs/nodes.h>
#include <silofs/fs/boot.h>
#include <silofs/fs/repo.h>
#include <silofs/fs/apex.h>
#include <silofs/fs/super.h>
#include <silofs/fs/spmaps.h>
#include <silofs/fs/walk.h>
#include <silofs/fs/pack.h>
#include <silofs/fs/private.h>


struct silofs_pack_ctx {
	struct silofs_visitor           vis;
	struct silofs_fs_apex          *apex;
	struct silofs_sb_info          *sbi;
	struct silofs_alloc_if         *alif;
	const struct silofs_namestr    *name;
};

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_sb_info *sbi_from_ui(const struct silofs_unode_info *ui)
{
	silofs_assert_not_null(ui);
	silofs_assert(silofs_ui_has_stype(ui, SILOFS_STYPE_SUPER));

	return silofs_sbi_from_ui(ui);
}

static struct silofs_spnode_info *
sni_from_ui(const struct silofs_unode_info *ui)
{
	silofs_assert_not_null(ui);
	silofs_assert(silofs_ui_has_stype(ui, SILOFS_STYPE_SPNODE));

	return silofs_sni_from_ui(ui);
}

static struct silofs_spleaf_info *
sli_from_ui(const struct silofs_unode_info *ui)
{
	silofs_assert_not_null(ui);
	silofs_assert(silofs_ui_has_stype(ui, SILOFS_STYPE_SPLEAF));

	return silofs_sli_from_ui(ui);
}

static void ui_bytebuf(const struct silofs_unode_info *ui,
                       struct silofs_bytebuf *bb)
{
	union silofs_view *view = ui->u_ti.t_view;
	const struct silofs_uaddr *uaddr = ui_uaddr(ui);

	silofs_bytebuf_init(bb, view, uaddr->oaddr.len);
	bb->len = uaddr->oaddr.len;
}


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int pac_allocate_blob(struct silofs_pack_ctx *pa_ctx,
                             size_t bsz, struct silofs_bytebuf *bb)
{
	void *blob = NULL;

	blob = silofs_allocate(pa_ctx->alif, bsz);
	if (blob == NULL) {
		return -ENOMEM;
	}
	silofs_bytebuf_init(bb, blob, bsz);
	return 0;
}

static void pac_deallocate_blob(struct silofs_pack_ctx *pa_ctx,
                                struct silofs_bytebuf *bb)
{
	silofs_deallocate(pa_ctx->alif, bb->ptr, bb->cap);
	silofs_bytebuf_fini(bb);
}

static void pac_calc_cas_blobid(struct silofs_pack_ctx *pa_ctx,
                                const struct silofs_bytebuf *bb,
                                struct silofs_blobid *out_blobid)
{
	struct silofs_hash256 hash;
	struct silofs_fs_apex *apex = pa_ctx->apex;

	silofs_sha256_of(&apex->ap_crypto->md, bb->ptr, bb->len, &hash);
	silofs_blobid_make_cas(out_blobid, &hash, bb->len);
}

static void pac_resolve_packid_of(struct silofs_pack_ctx *pa_ctx,
                                  const struct silofs_bytebuf *bb,
                                  struct silofs_packid *out_packid)
{
	struct silofs_blobid cas_blobid;

	pac_calc_cas_blobid(pa_ctx, bb, &cas_blobid);
	packid_setup(out_packid, &cas_blobid);
}

static int pac_load_blob_at(struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_blobid *blobid,
                            struct silofs_bytebuf *bb)
{
	struct silofs_oaddr oaddr;
	struct silofs_blob_info *bli = NULL;
	const struct silofs_repo *repo = pa_ctx->apex->ap_repo;
	int err;

	err = silofs_repo_stage_blob(repo, blobid, &bli);
	if (err) {
		return err;
	}
	err = pac_allocate_blob(pa_ctx, blobid->size, bb);
	if (err) {
		return err;
	}
	silofs_oaddr_setup_all(&oaddr, blobid);
	err = silofs_bli_load(bli, &oaddr, bb);
	if (err) {
		pac_deallocate_blob(pa_ctx, bb);
		return err;
	}
	return 0;
}

static int pac_save_blob_at(struct silofs_pack_ctx *pa_ctx,
                            const struct silofs_packid *packid,
                            const struct silofs_bytebuf *bb)
{
	struct silofs_oaddr oaddr;
	struct silofs_blob_info *bli = NULL;
	const struct silofs_blobid *blobid = &packid->blobid;
	const struct silofs_repo *repo = pa_ctx->apex->ap_repo;
	int err;

	err = silofs_repo_lookup_blob(repo, blobid);
	if (!err) {
		return 0; /* ok -- already exists */
	}
	err = silofs_repo_spawn_blob(repo, blobid, &bli);
	if (err) {
		return err;
	}
	silofs_oaddr_setup_all(&oaddr, blobid);
	err = silofs_bli_store(bli, &oaddr, bb);
	if (err) {
		return err;
	}
	return 0;
}

static int pac_archive_blob_of(struct silofs_pack_ctx *pa_ctx,
                               const struct silofs_blobid *blobid,
                               struct silofs_packid *out_packid)
{
	struct silofs_bytebuf bb;
	int err;

	silofs_bytebuf_init(&bb, NULL, 0);
	err = pac_load_blob_at(pa_ctx, blobid, &bb);
	if (err) {
		goto out;
	}
	pac_resolve_packid_of(pa_ctx, &bb, out_packid);
	err = pac_save_blob_at(pa_ctx, out_packid, &bb);
	if (err) {
		goto out;
	}
out:
	pac_deallocate_blob(pa_ctx, &bb);
	return err;
}

static int pac_archive_spleaf_sub(struct silofs_pack_ctx *pa_ctx,
                                  struct silofs_spleaf_info *sli, loff_t voff)
{
	struct silofs_ulink ulink;
	struct silofs_packid packid;
	const struct silofs_blobid *blobid;
	int err;

	err = silofs_sli_subref_of(sli, voff, &ulink);
	if (err) {
		return err;
	}
	blobid = uaddr_blobid(&ulink.child);
	err = silofs_sli_lookup_packid(sli, blobid, &packid);
	if (!err) {
		goto out_ok;
	}
	err = pac_archive_blob_of(pa_ctx, blobid, &packid);
	if (err) {
		return err;
	}
out_ok:
	silofs_sli_rebind_packid(sli, voff, &packid);
	return 0;
}

static int pac_archive_spleaf_subrefs(struct silofs_pack_ctx *pa_ctx,
                                      struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange;
	loff_t voff;
	int err;

	silofs_sli_vspace_range(sli, &vrange);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = pac_archive_spleaf_sub(pa_ctx, sli, voff);
		if (err == -ENOENT) {
			break;
		}
		if (err) {
			return err;
		}
		voff = off_next(voff, vrange.stepsz);
	}
	return 0;
}

static int pac_archive_spnode_sub(struct silofs_pack_ctx *pa_ctx,
                                  struct silofs_spnode_info *sni, loff_t voff)
{
	struct silofs_ulink ulink;
	struct silofs_packid packid;
	const struct silofs_blobid *blobid;
	int err;

	err = silofs_sni_subref_of(sni, voff, &ulink);
	if (err) {
		return err;
	}
	blobid = uaddr_blobid(&ulink.child);
	err = silofs_sni_lookup_packid(sni, blobid, &packid);
	if (!err) {
		goto out_ok;
	}
	err = pac_archive_blob_of(pa_ctx, blobid, &packid);
	if (err) {
		return err;
	}
out_ok:
	silofs_sni_rebind_packid(sni, voff, &packid);
	return 0;
}

static int pac_archive_spnode_subrefs(struct silofs_pack_ctx *pa_ctx,
                                      struct silofs_spnode_info *sni)
{
	struct silofs_vrange vrange;
	loff_t voff;
	int err;

	silofs_sni_vspace_range(sni, &vrange);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = pac_archive_spnode_sub(pa_ctx, sni, voff);
		if (err == -ENOENT) {
			break;
		}
		if (err) {
			return err;
		}
		voff = off_next(voff, vrange.stepsz);
	}
	return 0;
}

static int pac_archive_super_sub(struct silofs_pack_ctx *pa_ctx,
                                 struct silofs_sb_info *sbi, loff_t voff)
{
	struct silofs_ulink ulink;
	struct silofs_packid packid;
	const struct silofs_blobid *blobid;
	int err;

	err = silofs_sbi_subref_of(sbi, voff, &ulink);
	if (err) {
		return err;
	}
	blobid = uaddr_blobid(&ulink.child);
	err = silofs_sbi_lookup_packid(sbi, blobid, &packid);
	if (!err) {
		goto out_ok;
	}
	err = pac_archive_blob_of(pa_ctx, blobid, &packid);
	if (err) {
		return err;
	}
out_ok:
	silofs_sbi_rebind_packid(sbi, voff, &packid);
	return 0;
}

static int pac_archive_super_subrefs(struct silofs_pack_ctx *pa_ctx,
                                     struct silofs_sb_info *sbi)
{
	struct silofs_vrange vrange;
	loff_t voff;
	int err;

	silofs_sbi_vspace_range(sbi, &vrange);
	voff = vrange.beg;
	while (voff < vrange.end) {
		err = pac_archive_super_sub(pa_ctx, sbi, voff);
		if (err == -ENOENT) {
			break;
		}
		if (err) {
			return err;
		}
		voff = off_next(voff, vrange.stepsz);
	}
	return 0;
}

static int pac_archive_subrefs(struct silofs_pack_ctx *pa_ctx,
                               struct silofs_unode_info *ui)
{
	const enum silofs_stype stype = ui_stype(ui);
	int err = 0;

	if (stype_isspleaf(stype)) {
		err = pac_archive_spleaf_subrefs(pa_ctx, sli_from_ui(ui));
	} else if (stype_isspnode(stype)) {
		err = pac_archive_spnode_subrefs(pa_ctx, sni_from_ui(ui));
	} else if (stype_issuper(stype)) {
		err = pac_archive_super_subrefs(pa_ctx, sbi_from_ui(ui));
	} else {
		err = -EFSCORRUPTED;
	}
	if (!err) {
		err = silofs_apex_flush_dirty(pa_ctx->apex, SILOFS_F_NOW);
	}
	return err;
}

static int pac_prepare_archive_at(struct silofs_pack_ctx *pa_ctx,
                                  struct silofs_unode_info *ui)
{
	const enum silofs_stype stype = ui_stype(ui);

	silofs_unused(pa_ctx);
	return silofs_stype_isunode(stype) ? 0 : -EFSCORRUPTED;
}

static int pac_archive_top_down(struct silofs_pack_ctx *pa_ctx,
                                struct silofs_unode_info *ui)
{
	int err = 0;

	if (ui != NULL) { /* make clangscan happy */
		err = pac_prepare_archive_at(pa_ctx, ui);
	}
	return err;
}

static int pac_archive_bottom_up(struct silofs_pack_ctx *pa_ctx,
                                 struct silofs_unode_info *ui)
{
	int err = 0;

	if (ui != NULL) { /* make clangscan happy */
		err = pac_archive_subrefs(pa_ctx, ui);
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/


static void pac_resolve_by_unode(struct silofs_pack_ctx *pa_ctx,
                                 const struct silofs_unode_info *ui,
                                 struct silofs_packid *out_packid,
                                 struct silofs_bytebuf *out_bb)
{
	struct silofs_blobid cas_blobid;

	ui_bytebuf(ui, out_bb);
	pac_calc_cas_blobid(pa_ctx, out_bb, &cas_blobid);
	packid_setup(out_packid, &cas_blobid);
}

static int pac_archive_super(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_packid packid;
	struct silofs_bytebuf bb;
	struct silofs_sb_info *sbi = pa_ctx->sbi;
	int err;

	silofs_sbi_add_flags(sbi, SILOFS_SUPERF_PACKED);
	pac_resolve_by_unode(pa_ctx, &sbi->s_ui, &packid, &bb);
	err = pac_save_blob_at(pa_ctx, &packid, &bb);
	if (err) {
		return err;
	}
	silofs_bootsec_set_packid(&sbi->s_bsec, &packid);
	return 0;
}

static int pac_save_bootsec(struct silofs_pack_ctx *pa_ctx)
{
	const struct silofs_sb_info *sbi = pa_ctx->sbi;
	const struct silofs_bootsec *bsec = &sbi->s_bsec;

	return silofs_repo_save_bsec(sbi_repo(sbi), bsec, pa_ctx->name);
}

static int pac_load_bootsec(struct silofs_pack_ctx *pa_ctx)
{
	struct silofs_sb_info *sbi = pa_ctx->sbi;
	struct silofs_bootsec *bsec = &sbi->s_bsec;

	return silofs_repo_load_bsec(sbi_repo(sbi), pa_ctx->name, bsec);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static struct silofs_pack_ctx *pack_ctx_of(struct silofs_visitor *vis)
{
	return silofs_container_of(vis, struct silofs_pack_ctx, vis);
}

static int pack_start(struct silofs_visitor *vis,
                      struct silofs_unode_info *ui)
{
	struct silofs_pack_ctx *pa_ctx = pack_ctx_of(vis);

	return pac_archive_top_down(pa_ctx, ui);
}

static int pack_finish(struct silofs_visitor *vis,
                       struct silofs_unode_info *ui)
{
	struct silofs_pack_ctx *pa_ctx = pack_ctx_of(vis);

	return pac_archive_bottom_up(pa_ctx, ui);
}

int silofs_apex_pack_fs(struct silofs_fs_apex *apex,
                        const struct silofs_namestr *name)
{
	struct silofs_pack_ctx pa_ctx = {
		.vis.start_hook = pack_start,
		.vis.finish_hook = pack_finish,
		.apex = apex,
		.sbi = apex->ap_sbi,
		.alif = apex->ap_alif,
		.name = name,
	};
	int err;

	err = silofs_walk_space_tree(apex, &pa_ctx.vis);
	if (err) {
		return err;
	}
	err = pac_archive_super(&pa_ctx);
	if (err) {
		return err;
	}
	err = pac_save_bootsec(&pa_ctx);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int unpack_start(struct silofs_visitor *vis,
                        struct silofs_unode_info *ui)
{
	struct silofs_pack_ctx *pa_ctx = pack_ctx_of(vis);

	silofs_unused(pa_ctx);
	silofs_unused(ui);
	return 0;
}

static int unpack_finish(struct silofs_visitor *vis,
                         struct silofs_unode_info *ui)
{
	struct silofs_pack_ctx *pa_ctx = pack_ctx_of(vis);

	silofs_unused(pa_ctx);
	silofs_unused(ui);
	return 0;
}

int silofs_apex_unpack_fs(struct silofs_fs_apex *apex,
                          const struct silofs_namestr *name)
{
	struct silofs_pack_ctx pa_ctx = {
		.vis.start_hook = unpack_start,
		.vis.finish_hook = unpack_finish,
		.apex = apex,
		.sbi = apex->ap_sbi,
		.alif = apex->ap_alif,
		.name = name,
	};
	int err;

	err = pac_load_bootsec(&pa_ctx);
	if (err) {
		return err;
	}
	err = silofs_walk_space_tree(apex, &pa_ctx.vis);
	if (err) {
		return err;
	}
	return 0;
}


