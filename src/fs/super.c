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
#include <silofs/fs/nodes.h>
#include <silofs/fs/crypto.h>
#include <silofs/fs/cache.h>
#include <silofs/fs/repo.h>
#include <silofs/fs/apex.h>
#include <silofs/fs/super.h>
#include <silofs/fs/spmaps.h>
#include <silofs/fs/spclaim.h>
#include <silofs/fs/itable.h>
#include <silofs/fs/inode.h>
#include <silofs/fs/namei.h>
#include <silofs/fs/private.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/mount.h>
#include <limits.h>


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void iv_snap(const struct silofs_iv *iv, struct silofs_iv *other)
{
	memcpy(other, iv, sizeof(*other));
}

static void iv_rand(struct silofs_iv *iv, size_t n)
{
	silofs_gcry_randomize(iv, n * sizeof(*iv), false);
}

static void key_snap(const struct silofs_key *key, struct silofs_key *other)
{
	memcpy(other, key, sizeof(*other));
}

static void key_rand(struct silofs_key *key, size_t n)
{
	silofs_gcry_randomize(key, n * sizeof(*key), true);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void hash512_assign(struct silofs_hash512 *hash,
                           const struct silofs_hash512 *other)
{
	memcpy(hash, other, sizeof(*hash));
}

static bool hash512_isequal(const struct silofs_hash512 *hash,
                            const struct silofs_hash512 *other)
{
	return (memcmp(hash, other, sizeof(*hash)) == 0);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static enum silofs_stype ui_stype(const struct silofs_unode_info *ui)
{
	return ui->u_uaddr.stype;
}

static void ui_stamp_mark_visible(struct silofs_unode_info *ui)
{
	silofs_zero_stamp_view(ui->u_ti.t_view, ui_stype(ui));
	ui->u_verified = true;
	ui_dirtify(ui);
}

static void ui_bind_to(struct silofs_unode_info *ui,
                       struct silofs_fs_apex *apex,
                       struct silofs_ubk_info *ubi)
{
	struct silofs_tnode_info *ti = &ui->u_ti;

	silofs_ti_bind_hyper(ti, apex);
	silofs_ui_attach_bk(ui, ubi);
	silofs_ui_bind_view(ui);
}

static void vi_stamp_mark_visible(struct silofs_vnode_info *vi)
{
	const enum silofs_stype stype = vi_stype(vi);

	if (!stype_isdata(stype)) {
		silofs_zero_stamp_view(vi->v_ti.t_view, stype);
	}
	vi->v_verified = true;
	vi_dirtify(vi);
}

static void vi_bind_to(struct silofs_vnode_info *vi,
                       struct silofs_fs_apex *apex,
                       struct silofs_vbk_info *vbi)
{
	struct silofs_tnode_info *ti = &vi->v_ti;

	silofs_ti_bind_hyper(ti, apex);
	silofs_vi_attach_bk(vi, vbi);
	silofs_vi_bind_view(vi);
}

static void ii_stamp_mark_visible(struct silofs_inode_info *ii)
{
	vi_stamp_mark_visible(ii_to_vi(ii));
}

static void ii_iaddr(const struct silofs_inode_info *ii,
                     struct silofs_iaddr *iaddr)
{
	vaddr_assign(&iaddr->vaddr, ii_vaddr(ii));
	iaddr->ino = ii_ino(ii);
}

static void
ii_setup_inode_by(struct silofs_inode_info *ii, const struct silofs_oper *op,
                  ino_t parent, mode_t parent_mode, mode_t mode, dev_t rdev)
{
	const struct silofs_ucred *ucred = &op->ucred;

	ii_stamp_mark_visible(ii);
	silofs_setup_inode(ii, ucred, parent, parent_mode, mode, rdev);
	update_itimes(op, ii, SILOFS_IATTR_TIMES);
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static uint64_t sbr_magic(const struct silofs_sb_root *sbr)
{
	return silofs_le64_to_cpu(sbr->sb_magic);
}

static void sbr_set_magic(struct silofs_sb_root *sbr, uint64_t magic)
{
	sbr->sb_magic = silofs_cpu_to_le64(magic);
}

static long sbr_version(const struct silofs_sb_root *sbr)
{
	return (long)silofs_le64_to_cpu(sbr->sb_version);
}

static void sbr_set_version(struct silofs_sb_root *sbr, long version)
{
	sbr->sb_version = silofs_cpu_to_le64((uint64_t)version);
}

static void sbr_set_sw_version(struct silofs_sb_root *sbr,
                               const char *sw_version)
{
	const size_t len = strlen(sw_version);
	const size_t len_max = ARRAY_SIZE(sbr->sb_sw_version) - 1;

	memcpy(sbr->sb_sw_version, sw_version, min(len, len_max));
}

static void sbr_generate_uuid(struct silofs_sb_root *sbr)
{
	silofs_uuid_generate(&sbr->sb_uuid);
}

static void sbr_init(struct silofs_sb_root *sbr)
{
	sbr_set_magic(sbr, SILOFS_SUPER_MAGIC);
	sbr_set_version(sbr, SILOFS_FMT_VERSION);
	sbr_set_sw_version(sbr, silofs_version.string);
	sbr_generate_uuid(sbr);
	sbr->sb_endianness = SILOFS_ENDIANNESS_LE;
}

int silofs_sb_check_root(const struct silofs_super_block *sb)
{
	const struct silofs_sb_root *sbr = &sb->sb_root;

	if (sbr_magic(sbr) != SILOFS_SUPER_MAGIC) {
		return -EINVAL;
	}
	if (sbr_version(sbr) != SILOFS_FMT_VERSION) {
		return -EFSCORRUPTED;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sbh_set_pass_hash(struct silofs_sb_hash *sbh,
                              const struct silofs_hash512 *hash)
{
	hash512_assign(&sbh->sh_pass_hash, hash);
}

static bool sbh_has_pass_hash(const struct silofs_sb_hash *sbh,
                              const struct silofs_hash512 *hash)
{
	return hash512_isequal(&sbh->sh_pass_hash, hash);
}

static void sbh_fill_random(struct silofs_sb_hash *sbh)
{
	silofs_getentropy(sbh->sh_fill, sizeof(sbh->sh_fill));
}

static void sbh_calc_fill_hash(const struct silofs_sb_hash *sbh,
                               const struct silofs_mdigest *md,
                               struct silofs_hash512 *out_hash)
{
	silofs_sha3_512_of(md, sbh->sh_fill, sizeof(sbh->sh_fill), out_hash);
}

static void sb_set_fill_hash(struct silofs_sb_hash *sbh,
                             const struct silofs_hash512 *hash)
{
	hash512_assign(&sbh->sh_fill_hash, hash);
}

static bool sbh_has_hash(const struct silofs_sb_hash *sbh,
                         const struct silofs_hash512 *hash)
{
	return hash512_isequal(&sbh->sh_fill_hash, hash);
}

static void sbh_setup(struct silofs_sb_hash *sbh,
                      const struct silofs_mdigest *md)
{
	struct silofs_hash512 hash;

	sbh_fill_random(sbh);
	sbh_calc_fill_hash(sbh, md, &hash);
	sb_set_fill_hash(sbh, &hash);
}

static int sbh_check(const struct silofs_sb_hash *sbh,
                     const struct silofs_mdigest *md)
{
	struct silofs_hash512 hash;

	sbh_calc_fill_hash(sbh, md, &hash);
	return sbh_has_hash(sbh, &hash) ? 0 : -EFSCORRUPTED;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static uint32_t sbk_cipher_algo(const struct silofs_sb_keys *sbk)
{
	return silofs_le32_to_cpu(sbk->sk_cipher_algo);
}

static void sbk_set_cipher_algo(struct silofs_sb_keys *sbk, uint32_t algo)
{
	sbk->sk_cipher_algo = silofs_cpu_to_le32(algo);
}

static uint32_t sbk_cipher_mode(const struct silofs_sb_keys *sbk)
{
	return silofs_le32_to_cpu(sbk->sk_cipher_mode);
}

static void sbk_set_cipher_mode(struct silofs_sb_keys *sbk, uint32_t mode)
{
	sbk->sk_cipher_mode = silofs_cpu_to_le32(mode);
}

static void sbk_setup(struct silofs_sb_keys *sbk)
{
	sbk_set_cipher_algo(sbk, SILOFS_CIPHER_AES256);
	sbk_set_cipher_mode(sbk, SILOFS_CIPHER_MODE_GCM);
	silofs_memzero(sbk->sk_reserved1, sizeof(sbk->sk_reserved1));
	iv_rand(sbk->sk_iv, ARRAY_SIZE(sbk->sk_iv));
	key_rand(sbk->sk_key, ARRAY_SIZE(sbk->sk_key));
}

static const struct silofs_key *
sbk_key_by_lba(const struct silofs_sb_keys *sbk, silofs_lba_t lba)
{
	const size_t key_slot = (uint64_t)lba % ARRAY_SIZE(sbk->sk_key);

	return &sbk->sk_key[key_slot];
}

static const struct silofs_iv *
sbk_iv_by_voff(const struct silofs_sb_keys *sbk, loff_t voff)
{
	const size_t iv_slot = (uint64_t)(voff >> 10) % ARRAY_SIZE(sbk->sk_iv);

	return &sbk->sk_iv[iv_slot];
}

static void sbk_kivam_of(const struct silofs_sb_keys *sbk,
                         const struct silofs_vaddr *vaddr,
                         struct silofs_kivam *kivam)
{
	const struct silofs_iv *iv;
	const struct silofs_key *key;

	iv = sbk_iv_by_voff(sbk, vaddr_off(vaddr));
	key = sbk_key_by_lba(sbk, vaddr_lba(vaddr));

	silofs_kivam_init(kivam);
	key_snap(key, &kivam->key);
	iv_snap(iv, &kivam->iv);
	kivam->cipher_algo = sbk_cipher_algo(sbk);
	kivam->cipher_mode = sbk_cipher_mode(sbk);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t sbu_height(const struct silofs_sb_usmap *sbu)
{
	return sbu->su_height;
}

static void sbu_set_height(struct silofs_sb_usmap *sbu, size_t height)
{
	sbu->su_height = (uint8_t)height;
}

static void sbu_vrange(const struct silofs_sb_usmap *sbu,
                       struct silofs_vrange *out_vrange)
{
	silofs_vrange128_parse(&sbu->su_vrange, out_vrange);
}

static void sbu_set_vrange(struct silofs_sb_usmap *sbu,
                           const struct silofs_vrange *vrange)
{
	silofs_vrange128_set(&sbu->su_vrange, vrange);
}

static void sbu_main_treeid(const struct silofs_sb_usmap *sbu,
                            struct silofs_metaid *out_mid)
{
	silofs_metaid128_parse(&sbu->su_main_treeid, out_mid);
}

static void sbu_set_main_treeid(struct silofs_sb_usmap *sbu,
                                const struct silofs_metaid *mid)
{
	silofs_metaid128_set(&sbu->su_main_treeid, mid);
}

static void sbu_main_blobid(const struct silofs_sb_usmap *sbu,
                            struct silofs_blobid *out_bid)
{
	silofs_blobid40b_parse(&sbu->su_main_blobid, out_bid);
}

static void sbu_set_main_blobid(struct silofs_sb_usmap *sbu,
                                const struct silofs_blobid *bid)
{
	silofs_blobid40b_set(&sbu->su_main_blobid, bid);
}

static void sbu_reset_main_blobid(struct silofs_sb_usmap *sbu)
{
	silofs_blobid40b_reset(&sbu->su_main_blobid);
}

static size_t sbu_nchilds_max(const struct silofs_sb_usmap *sbu)
{
	return ARRAY_SIZE(sbu->su_child);
}

static bool sbu_is_in_vrange(const struct silofs_sb_usmap *sbu, loff_t voff)
{
	struct silofs_vrange vrange;

	sbu_vrange(sbu, &vrange);
	return (vrange.beg <= voff) && (voff < vrange.end);
}

static size_t sbu_voff_to_slot(const struct silofs_sb_usmap *sbu, loff_t voff)
{
	long span;
	long roff;
	size_t slot;
	struct silofs_vrange vrange;
	const long nslots = (long)sbu_nchilds_max(sbu);

	sbu_vrange(sbu, &vrange);
	span = (long)silofs_vrange_length(&vrange);
	roff = off_diff(vrange.beg, voff);
	slot = (size_t)((roff * nslots) / span);
	silofs_assert_lt(slot, nslots);
	return slot;
}

static struct silofs_uobj_ref *
sbu_child_at(const struct silofs_sb_usmap *sbu, size_t slot)
{
	const struct silofs_uobj_ref *uor = &sbu->su_child[slot];

	silofs_assert_lt(slot, ARRAY_SIZE(sbu->su_child));
	return unconst(uor);
}

static struct silofs_uobj_ref *
sbu_child_of(const struct silofs_sb_usmap *sbu, loff_t voff)
{
	return sbu_child_at(sbu, sbu_voff_to_slot(sbu, voff));
}

static void sbu_child_uaddr_at(const struct silofs_sb_usmap *sbu, size_t slot,
                               struct silofs_uaddr *out_uaddr)
{
	const struct silofs_uobj_ref *uor = sbu_child_at(sbu, slot);

	silofs_uaddr56b_parse(&uor->uor_uadr, out_uaddr);
}

static void sbu_child(const struct silofs_sb_usmap *sbu,
                      loff_t voff, struct silofs_uaddr *out_uaddr)
{
	const struct silofs_uobj_ref *uor;

	if (sbu_is_in_vrange(sbu, voff)) {
		uor = sbu_child_of(sbu, voff);
		silofs_uaddr56b_parse(&uor->uor_uadr, out_uaddr);
	} else {
		silofs_uaddr_reset(out_uaddr);
	}
}

static void sbu_set_child(struct silofs_sb_usmap *usm, loff_t voff,
                          const struct silofs_uaddr *uaddr)
{
	struct silofs_uobj_ref *uor = sbu_child_of(usm, voff);

	silofs_uaddr56b_set(&uor->uor_uadr, uaddr);
}

static size_t sbu_num_active_slots(const struct silofs_sb_usmap *sbu)
{
	size_t nslots_active = 0;
	struct silofs_uaddr uaddr;
	const size_t nslots_max = sbu_nchilds_max(sbu);

	for (size_t slot = 0; slot < nslots_max; ++slot) {
		sbu_child_uaddr_at(sbu, slot, &uaddr);
		if (uaddr_isnull(&uaddr)) {
			break;
		}
		nslots_active++;
	}
	return nslots_active;
}

static void sbu_generate_main_treeid(struct silofs_sb_usmap *sbu)
{
	struct silofs_metaid mid;

	silofs_metaid_generate(&mid);
	sbu_set_main_treeid(sbu, &mid);
}

static void sbu_init(struct silofs_sb_usmap *sbu)
{
	struct silofs_uobj_ref *uor;
	const size_t nslots = sbu_nchilds_max(sbu);

	sbu_generate_main_treeid(sbu);
	silofs_blobid40b_reset(&sbu->su_main_blobid);
	silofs_blobid40b_reset(&sbu->su_arch_blobid);
	for (size_t slot = 0; slot < nslots; ++slot) {
		uor = sbu_child_at(sbu, slot);
		silofs_uaddr56b_reset(&uor->uor_uadr);
	}
}

static void sb_resolve_spnode(const struct silofs_super_block *sb,
                              loff_t voff, struct silofs_uaddr *out_uaddr)
{
	sbu_child(&sb->sb_usm, voff, out_uaddr);
}

static void sb_bind_spnode(struct silofs_super_block *sb, loff_t voff,
                           const struct silofs_uaddr *uaddr)
{
	sbu_set_child(&sb->sb_usm, voff, uaddr);
}

static bool sb_has_spnode(struct silofs_super_block *sb, loff_t voff)
{
	struct silofs_uaddr uaddr;

	sb_resolve_spnode(sb, voff, &uaddr);
	return !uaddr_isnull(&uaddr);
}

static void sb_span_vrange(const struct silofs_super_block *sb,
                           struct silofs_vrange *out_vrange)
{
	sbu_vrange(&sb->sb_usm, out_vrange);
}

static size_t sb_slot_of(const struct silofs_super_block *sb, loff_t voff)
{
	return sbu_voff_to_slot(&sb->sb_usm, voff);
}

static void sb_main_treeid(const struct silofs_super_block *sb,
                           struct silofs_metaid *out_mid)
{
	sbu_main_treeid(&sb->sb_usm, out_mid);
}

static void sb_regenerate_main_treeid(struct silofs_super_block *sb)
{
	sbu_generate_main_treeid(&sb->sb_usm);
}

static void sb_main_blobid(const struct silofs_super_block *sb,
                           struct silofs_blobid *out_bid)
{
	sbu_main_blobid(&sb->sb_usm, out_bid);
}

static void sb_reset_main_blobid(struct silofs_super_block *sb)
{
	sbu_reset_main_blobid(&sb->sb_usm);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sb_init(struct silofs_super_block *sb)
{
	sbr_init(&sb->sb_root);
	sbu_init(&sb->sb_usm);
}

void silofs_sb_set_pass_hash(struct silofs_super_block *sb,
                             const struct silofs_hash512 *hash)
{
	sbh_set_pass_hash(&sb->sb_hash, hash);
}

static bool sb_has_pass_hash(const struct silofs_super_block *sb,
                             const struct silofs_hash512 *hash)
{
	return sbh_has_pass_hash(&sb->sb_hash, hash);
}

static void sb_set_birth_time(struct silofs_super_block *sb, time_t btime)
{
	sb->sb_base.sb_birth_time = silofs_cpu_to_le64((uint64_t)btime);
}

static void sb_itable_root(const struct silofs_super_block *sb,
                           struct silofs_vaddr *out_vaddr)
{
	silofs_vaddr64_parse(&sb->sb_base.sb_itable_root, out_vaddr);
}

static void sb_set_itable_root(struct silofs_super_block *sb,
                               const struct silofs_vaddr *vaddr)
{
	silofs_vaddr64_set(&sb->sb_base.sb_itable_root, vaddr);
}

static void sb_setup_keys(struct silofs_super_block *sb)
{
	sbk_setup(&sb->sb_keys);
}

static void sb_kivam_of(const struct silofs_super_block *sb,
                        const struct silofs_vaddr *vaddr,
                        struct silofs_kivam *out_kivam)
{
	return sbk_kivam_of(&sb->sb_keys, vaddr, out_kivam);
}

static void sb_setup_rand(struct silofs_super_block *sb,
                          const struct silofs_mdigest *md)
{
	sbh_setup(&sb->sb_hash, md);
}

int silofs_sb_check_pass_hash(const struct silofs_super_block *sb,
                              const struct silofs_hash512 *hash)
{
	return sb_has_pass_hash(sb, hash) ? 0 : -EKEYEXPIRED;
}

int silofs_sb_check_rand(const struct silofs_super_block *sb,
                         const struct silofs_mdigest *md)
{
	return sbh_check(&sb->sb_hash, md);
}

int silofs_sb_encrypt(const struct silofs_super_block *sb_in,
                      const struct silofs_cipher *ci,
                      const struct silofs_kivam *kivam,
                      struct silofs_super_block *sb_out)
{
	int err;

	err = silofs_encrypt_buf(ci, kivam, sb_in, sb_out, sizeof(*sb_out));
	if (err) {
		log_err("failed to encrypt sb: err=%d", err);
	}
	return err;
}

int silofs_sb_decrypt(const struct silofs_super_block *sb_in,
                      const struct silofs_cipher *ci,
                      const struct silofs_kivam *kivam,
                      struct silofs_super_block *sb_out)
{
	int err;

	err = silofs_decrypt_buf(ci, kivam, sb_in, sb_out, sizeof(*sb_out));
	if (err) {
		log_dbg("failed to decrypt sb: err=%d", err);
	}
	return err;
}

static size_t sb_uspace_nmeta(const struct silofs_super_block *sb)
{
	return silofs_le64_to_cpu(sb->sb_base.sb_uspace_nmeta);
}

static void sb_set_uspace_nmeta(struct silofs_super_block *sb, size_t nmeta)
{
	sb->sb_base.sb_uspace_nmeta = silofs_cpu_to_le64(nmeta);
}

static size_t sb_vspace_nmeta(const struct silofs_super_block *sb)
{
	return silofs_le64_to_cpu(sb->sb_base.sb_vspace_nmeta);
}

static void sb_set_vspace_nmeta(struct silofs_super_block *sb, size_t nmeta)
{
	sb->sb_base.sb_vspace_nmeta = silofs_cpu_to_le64(nmeta);
}

static size_t sb_vspace_nfiles(const struct silofs_super_block *sb)
{
	return silofs_le64_to_cpu(sb->sb_base.sb_vspace_nfiles);
}

static void sb_set_vspace_nfiles(struct silofs_super_block *sb, size_t nfiles)
{
	sb->sb_base.sb_vspace_nfiles = silofs_cpu_to_le64(nfiles);
}

static size_t sb_vspace_ndata(const struct silofs_super_block *sb)
{
	return silofs_le64_to_cpu(sb->sb_base.sb_vspace_ndata);
}

static void sb_set_vspace_ndata(struct silofs_super_block *sb, size_t ndata)
{
	sb->sb_base.sb_vspace_ndata = silofs_cpu_to_le64(ndata);
}

loff_t silofs_sb_vspace_last(const struct silofs_super_block *sb)
{
	return silofs_off_to_cpu(sb->sb_base.sb_vspace_last);
}

static void sb_set_vspace_last(struct silofs_super_block *sb, loff_t voff)
{
	sb->sb_base.sb_vspace_last = silofs_cpu_to_off(voff);
}

static size_t sb_total_capacity(const struct silofs_super_block *sb)
{
	return silofs_le64_to_cpu(sb->sb_base.sb_total_capacity);
}

static void sb_set_total_capacity(struct silofs_super_block *sb, size_t cap)
{
	sb->sb_base.sb_total_capacity = silofs_cpu_to_le64(cap);
}

static void sb_setup_fresh(struct silofs_super_block *sb,
                           time_t btime, size_t capacity)
{
	sb_set_birth_time(sb, btime);
	sb_set_itable_root(sb, silofs_vaddr_none());
	sb_setup_keys(sb);
	sb_set_uspace_nmeta(sb, sizeof(*sb));
	sb_set_vspace_last(sb, 0);
	sb_set_total_capacity(sb, capacity);
	sb_set_vspace_ndata(sb, 0);
	sb_set_vspace_nmeta(sb, 0);
	sb_set_vspace_nfiles(sb, 0);
}

static void sb_set_vspace_span(struct silofs_super_block *sb, size_t height,
                               const struct silofs_vrange *vrange_span)
{
	struct silofs_sb_usmap *sbu = &sb->sb_usm;

	sbu_set_height(sbu, height);
	sbu_set_vrange(sbu, vrange_span);
}

static void sb_space_stat(const struct silofs_super_block *sb,
                          struct silofs_space_stat *out_spst)
{
	out_spst->uspace_nmeta = (ssize_t)sb_uspace_nmeta(sb);
	out_spst->vspace_ndata = (ssize_t)sb_vspace_ndata(sb);
	out_spst->vspace_nmeta = (ssize_t)sb_vspace_nmeta(sb);
	out_spst->vspace_nfiles = (ssize_t)sb_vspace_nfiles(sb);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int64_t *
sb_vspa_last_of(const struct silofs_super_block *sb, enum silofs_stype stype)
{
	const int64_t *vspa_last;

	switch (stype) {
	case SILOFS_STYPE_DATA1K:
		vspa_last = &sb->sb_base.sb_vspa_data1k;
		break;
	case SILOFS_STYPE_DATA4K:
		vspa_last = &sb->sb_base.sb_vspa_data4k;
		break;
	case SILOFS_STYPE_DATABK:
		vspa_last = &sb->sb_base.sb_vspa_databk;
		break;
	case SILOFS_STYPE_ITNODE:
		vspa_last = &sb->sb_base.sb_vspa_itnode;
		break;
	case SILOFS_STYPE_INODE:
		vspa_last = &sb->sb_base.sb_vspa_inode;
		break;
	case SILOFS_STYPE_XANODE:
		vspa_last = &sb->sb_base.sb_vspa_xanode;
		break;
	case SILOFS_STYPE_DTNODE:
		vspa_last = &sb->sb_base.sb_vspa_dirnode;
		break;
	case SILOFS_STYPE_FTNODE:
		vspa_last = &sb->sb_base.sb_vspa_filenode;
		break;
	case SILOFS_STYPE_SYMVAL:
		vspa_last = &sb->sb_base.sb_vspa_symval;
		break;
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
	case SILOFS_STYPE_ANONBK:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_MAX:
	default:
		vspa_last = NULL;
		break;
	}
	return unconst(vspa_last);
}

loff_t silofs_sb_vlast_by_stype(const struct silofs_super_block *sb,
                                enum silofs_stype stype)
{
	const int64_t *vspa_last = sb_vspa_last_of(sb, stype);

	silofs_assert_not_null(vspa_last);
	return (vspa_last != NULL) ? silofs_off_to_cpu(*vspa_last) : 0;
}

void silofs_sb_set_voff_last(struct silofs_super_block *sb,
                             enum silofs_stype stype, loff_t voff_last)
{
	int64_t *vspa_last = sb_vspa_last_of(sb, stype);

	silofs_assert_not_null(vspa_last);
	if (vspa_last != NULL) {
		*vspa_last = silofs_cpu_to_off(voff_last);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_verify_super_block(const struct silofs_super_block *sb)
{
	size_t height;
	size_t nactive_slots;
	const struct silofs_sb_usmap *sbu = &sb->sb_usm;

	height = sbu_height(sbu);
	if (height != SILOFS_SUPER_HEIGHT) {
		log_err("illegal sb height: height=%lu", height);
		return -EFSCORRUPTED;
	}
	nactive_slots = sbu_num_active_slots(sbu);
	if (nactive_slots >= ARRAY_SIZE(sbu->su_child)) {
		return -EFSCORRUPTED;
	}
	/* TODO: complete me */
	return 0;
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

size_t silofs_sbi_nused_bytes(const struct silofs_sb_info *sbi)
{
	ssize_t sum;
	struct silofs_space_stat sp_st;

	sb_space_stat(sbi->sb, &sp_st);
	sum = sp_st.uspace_nmeta + sp_st.vspace_nmeta + sp_st.vspace_ndata;
	return (size_t)sum;
}

size_t silofs_sbi_vspace_capacity(const struct silofs_sb_info *sbi)
{
	return sb_total_capacity(sbi->sb);
}

fsfilcnt_t silofs_sbi_inodes_limit(const struct silofs_sb_info *sbi)
{
	const size_t inode_size = SILOFS_INODE_SIZE;

	return (silofs_sbi_vspace_capacity(sbi) / inode_size) >> 2;
}

fsfilcnt_t silofs_sbi_inodes_current(const struct silofs_sb_info *sbi)
{
	return sb_vspace_nfiles(sbi->sb);
}

static size_t safe_sum(size_t cur, ssize_t dif)
{
	size_t val = cur;

	if (dif > 0) {
		val += (size_t)dif;
		silofs_assert_gt(val, cur);
	} else if (dif < 0) {
		val -= (size_t)(-dif);
		silofs_assert_lt(val, cur);
	}
	return val;
}

static void sbi_dirtify(struct silofs_sb_info *sbi)
{
	silofs_sbi_dirtify(sbi);
}

void silofs_sbi_update_stats(struct silofs_sb_info *sbi,
                             const struct silofs_space_stat *spst_dif)
{
	size_t cur;
	ssize_t dif;
	struct silofs_super_block *sb = sbi->sb;

	dif = spst_dif->uspace_nmeta;
	if (dif) {
		cur = sb_uspace_nmeta(sb);
		sb_set_uspace_nmeta(sb, safe_sum(cur, dif));
	}
	dif = spst_dif->vspace_ndata;
	if (dif) {
		cur = sb_vspace_ndata(sb);
		sb_set_vspace_ndata(sb, safe_sum(cur, dif));
	}
	dif = spst_dif->vspace_nmeta;
	if (dif) {
		cur = sb_vspace_nmeta(sb);
		sb_set_vspace_nmeta(sb, safe_sum(cur, dif));
	}
	dif = spst_dif->vspace_nfiles;
	if (dif) {
		cur = sb_vspace_nfiles(sb);
		sb_set_vspace_nfiles(sb, safe_sum(cur, dif));
	}
	sbi_dirtify(sbi);
}

static void sbi_update_uspace_meta(struct silofs_sb_info *sbi,
                                   enum silofs_stype stype)
{
	const struct silofs_space_stat sp_st = {
		.uspace_nmeta = stype_ssize(stype)
	};
	silofs_sbi_update_stats(sbi, &sp_st);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

/*
 * TODO-0028: Use statvfs.f_bsize=BK (64K) and KB to statvfs.f_frsize=KB (1K)
 *
 * The semantics of statvfs and statfs are not entirely clear; in particular,
 * statvfs(3p) states that statvfs.f_blocks define the file-system's size in
 * f_frsize units, where f_bfree is number of free blocks (but without stating
 * explicit units). For now, we force 4K units to both, but need more
 * investigations before changing, especially with respect to various
 * user-space tools.
 */
static fsblkcnt_t bytes_to_fsblkcnt(size_t nbytes, size_t unit)
{
	return (fsblkcnt_t)nbytes / unit;
}

void silofs_statvfs_of(const struct silofs_sb_info *sbi,
                       struct statvfs *out_stvfs)
{
	const size_t funit = 4 * SILOFS_KB_SIZE;
	const size_t bsize = funit;
	const size_t frsize = funit;
	const size_t nbytes_max = silofs_sbi_vspace_capacity(sbi);
	const size_t nbytes_use = silofs_sbi_nused_bytes(sbi);
	const size_t nbytes_free = nbytes_max - nbytes_use;
	const fsfilcnt_t nfiles_max = silofs_sbi_inodes_limit(sbi);
	const fsfilcnt_t nfiles_cur = silofs_sbi_inodes_current(sbi);

	silofs_assert_ge(nbytes_max, nbytes_use);

	silofs_memzero(out_stvfs, sizeof(*out_stvfs));
	out_stvfs->f_bsize = bsize;
	out_stvfs->f_frsize = frsize;
	out_stvfs->f_blocks = bytes_to_fsblkcnt(nbytes_max, frsize);
	out_stvfs->f_bfree = bytes_to_fsblkcnt(nbytes_free, bsize);
	out_stvfs->f_bavail = out_stvfs->f_bfree;
	out_stvfs->f_files = nfiles_max;
	out_stvfs->f_ffree = nfiles_max - nfiles_cur;
	out_stvfs->f_favail = out_stvfs->f_ffree;
	out_stvfs->f_namemax = SILOFS_NAME_MAX;
	out_stvfs->f_fsid = SILOFS_FSID_MAGIC;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sbi_spawn_blob_at(const struct silofs_sb_info *sbi,
                             const struct silofs_blobid *bid,
                             struct silofs_blob_info **out_bli)
{
	return silofs_apex_spawn_blob(sbi_apex(sbi), bid, out_bli);
}

static int sbi_stage_blob_at(const struct silofs_sb_info *sbi,
                             const struct silofs_blobid *bid,
                             struct silofs_blob_info **out_bli)
{
	return silofs_apex_stage_blob(sbi_apex(sbi), bid, out_bli);
}

static int sbi_stage_blob_of(const struct silofs_sb_info *sbi,
                             const struct silofs_oaddr *oaddr,
                             struct silofs_blob_info **out_bli)
{
	return sbi_stage_blob_at(sbi, &oaddr->bid, out_bli);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t sbi_cache_ndirty(const struct silofs_sb_info *sbi)
{
	const struct silofs_cache *cache = sbi_cache(sbi);

	return cache->c_dq.dq_accum_nbytes;
}

static int sbi_lookup_cached_ui(struct silofs_sb_info *sbi,
                                const struct silofs_uaddr *uaddr,
                                struct silofs_unode_info **out_ui)
{
	struct silofs_cache *cache = sbi_cache(sbi);

	*out_ui = silofs_cache_lookup_unode(cache, uaddr);
	return (*out_ui != NULL) ? 0 : -ENOENT;
}

static int sbi_lookup_cached_vi(const struct silofs_sb_info *sbi,
                                const struct silofs_vaddr *vaddr,
                                struct silofs_vnode_info **out_vi)
{
	if (vaddr_isnull(vaddr)) {
		return -ENOENT;
	}
	*out_vi = silofs_cache_lookup_vnode(sbi_cache(sbi), vaddr);
	if (*out_vi == NULL) {
		return -ENOENT;
	}
	return 0;
}

static int sbi_lookup_cached_ii(const struct silofs_sb_info *sbi,
                                const struct silofs_vaddr *vaddr,
                                struct silofs_inode_info **out_ii)
{
	int err;
	struct silofs_vnode_info *vi = NULL;

	silofs_assert(!vaddr_isnull(vaddr));
	err = sbi_lookup_cached_vi(sbi, vaddr, &vi);
	if (err) {
		return err;
	}
	*out_ii = silofs_ii_from_vi(vi);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sbi_commit_dirty_now(struct silofs_sb_info *sbi)
{
	int err;

	err = silofs_apex_flush_dirty(sbi_apex(sbi), SILOFS_F_NOW);
	if (err) {
		log_dbg("commit dirty failure: ndirty=%lu err=%d",
		        sbi_cache_ndirty(sbi), err);
	}
	return err;
}

static int sbi_try_spawn_ubi(struct silofs_sb_info *sbi,
                             const struct silofs_oaddr *oaddr,
                             struct silofs_ubk_info **out_ubi)
{
	*out_ubi = silofs_cache_spawn_ubk(sbi_cache(sbi), oaddr);
	return (*out_ubi != NULL) ? 0 : -ENOMEM;
}

static int sbi_spawn_ubi(struct silofs_sb_info *sbi,
                         const struct silofs_oaddr *oaddr,
                         struct silofs_ubk_info **out_ubi)
{
	int err = -ENOMEM;

	for (int i = 0; i < 4; ++i) {
		err = sbi_try_spawn_ubi(sbi, oaddr, out_ubi);
		if (!err) {
			break;
		}
		err = sbi_commit_dirty_now(sbi);
		if (err) {
			break;
		}
	}
	return err;
}

static void sbi_forget_cached_ubi(const struct silofs_sb_info *sbi,
                                  struct silofs_ubk_info *ubi)
{
	silofs_cache_forget_ubk(sbi_cache(sbi), ubi);
}

static int sbi_do_spawn_load_bk(struct silofs_sb_info *sbi,
                                struct silofs_blob_info *bli,
                                const struct silofs_oaddr *oaddr,
                                struct silofs_ubk_info **out_ubi)
{
	int err;
	struct silofs_ubk_info *ubi = NULL;

	err = sbi_spawn_ubi(sbi, oaddr, &ubi);
	if (err) {
		return err;
	}
	err = silofs_bli_load_bk(bli, ubi->ubk, oaddr);
	if (err) {
		sbi_forget_cached_ubi(sbi, ubi);
		return err;
	}
	*out_ubi = ubi;
	return 0;
}

static int sbi_spawn_load_bk(struct silofs_sb_info *sbi,
                             struct silofs_blob_info *bli,
                             const struct silofs_oaddr *oaddr,
                             struct silofs_ubk_info **out_ubi)
{
	int err;

	bli_incref(bli);
	err = sbi_do_spawn_load_bk(sbi, bli, oaddr, out_ubi);
	bli_decref(bli);
	return err;
}

static int sbi_stage_load_block(struct silofs_sb_info *sbi,
                                const struct silofs_oaddr *oaddr,
                                struct silofs_ubk_info **out_ubi)
{
	int err;
	struct silofs_blob_info *bli = NULL;

	err = sbi_stage_blob_of(sbi, oaddr, &bli);
	if (err) {
		return err;
	}
	err = sbi_spawn_load_bk(sbi, bli, oaddr, out_ubi);
	if (err) {
		return err;
	}
	return 0;
}

static int sbi_lookup_cached_ubi(struct silofs_sb_info *sbi,
                                 const struct silofs_oaddr *oaddr,
                                 struct silofs_ubk_info **out_ubi)
{
	*out_ubi = silofs_cache_lookup_ubk(sbi_cache(sbi), oaddr);
	return (*out_ubi != NULL) ? 0 : -ENOENT;
}

static int sbi_stage_block(struct silofs_sb_info *sbi,
                           const struct silofs_oaddr *oaddr,
                           struct silofs_ubk_info **out_ubi)
{
	int err;

	err = sbi_lookup_cached_ubi(sbi, oaddr, out_ubi);
	if (!err) {
		return 0; /* Cache hit */
	}
	err = sbi_stage_load_block(sbi, oaddr, out_ubi);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sbi_try_spawn_vbi(struct silofs_sb_info *sbi, loff_t voff,
                             struct silofs_vbk_info **out_vbi)
{
	*out_vbi = silofs_cache_spawn_vbk(sbi_cache(sbi), voff);
	return (*out_vbi != NULL) ? 0 : -ENOMEM;
}

static int sbi_spawn_vbi(struct silofs_sb_info *sbi, loff_t voff,
                         struct silofs_vbk_info **out_vbi)
{
	int err = -ENOMEM;

	for (int i = 0; i < 4; ++i) {
		err = sbi_try_spawn_vbi(sbi, voff, out_vbi);
		if (!err) {
			break;
		}
		err = sbi_commit_dirty_now(sbi);
		if (err) {
			break;
		}
	}
	return err;
}

static void sbi_forget_cached_vbi(const struct silofs_sb_info *sbi,
                                  struct silofs_vbk_info *vbi)
{
	silofs_cache_forget_vbk(sbi_cache(sbi), vbi);
}

static int sbi_do_spawn_load_vbk(struct silofs_sb_info *sbi,
                                 struct silofs_blob_info *bli,
                                 const struct silofs_ovaddr *ova,
                                 struct silofs_vbk_info **out_vbi)
{
	int err;
	struct silofs_vbk_info *vbi = NULL;

	err = sbi_spawn_vbi(sbi, ova->vaddr.voff, &vbi);
	if (err) {
		return err;
	}
	err = silofs_bli_load_bk(bli, vbi->vbk, &ova->oaddr);
	if (err) {
		sbi_forget_cached_vbi(sbi, vbi);
		return err;
	}
	*out_vbi = vbi;
	return 0;
}

static int sbi_spawn_load_vbk(struct silofs_sb_info *sbi,
                              struct silofs_blob_info *bli,
                              const struct silofs_ovaddr *ova,
                              struct silofs_vbk_info **out_vbi)
{
	int err;

	bli_incref(bli);
	err = sbi_do_spawn_load_vbk(sbi, bli, ova, out_vbi);
	bli_decref(bli);
	return err;
}

static int sbi_stage_load_vblock(struct silofs_sb_info *sbi,
                                 const struct silofs_ovaddr *ova,
                                 struct silofs_vbk_info **out_vbi)
{
	int err;
	struct silofs_blob_info *bli = NULL;

	err = sbi_stage_blob_of(sbi, &ova->oaddr, &bli);
	if (err) {
		return err;
	}
	err = sbi_spawn_load_vbk(sbi, bli, ova, out_vbi);
	if (err) {
		return err;
	}
	return 0;
}

static int sbi_lookup_cached_vbi(struct silofs_sb_info *sbi, loff_t voff,
                                 struct silofs_vbk_info **out_vbi)
{
	*out_vbi = silofs_cache_lookup_vbk(sbi_cache(sbi), voff);
	return (*out_vbi != NULL) ? 0 : -ENOENT;
}

static int sbi_stage_vblock(struct silofs_sb_info *sbi,
                            const struct silofs_ovaddr *ova,
                            struct silofs_vbk_info **out_vbi)
{
	int err;

	err = sbi_lookup_cached_vbi(sbi, ova->vaddr.voff, out_vbi);
	if (!err) {
		return 0; /* Cache hit */
	}
	err = sbi_stage_load_vblock(sbi, ova, out_vbi);
	if (err) {
		return err;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sbi_calc_allowed_vrange(const struct silofs_sb_info *sbi,
                                    struct silofs_vrange *out_vrange)
{
	size_t length;
	struct silofs_vrange vrange_span;
	const size_t capacity = sb_total_capacity(sbi->sb);

	sb_span_vrange(sbi->sb, &vrange_span);

	length = min(silofs_vrange_length(&vrange_span), 2 * capacity);
	silofs_vrange_setup(out_vrange, vrange_span.beg,
	                    off_end(vrange_span.beg, length));
}

static int
sbi_resolve_unformatted_end(const struct silofs_sb_info *sbi, loff_t *out_voff)
{
	struct silofs_vrange allowed_vrange;

	sbi_calc_allowed_vrange(sbi, &allowed_vrange);
	*out_voff = silofs_sb_vspace_last(sbi->sb);
	return (*out_voff < allowed_vrange.end) ? 0 : -ENOSPC;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int try_spawn_vi(struct silofs_sb_info *sbi,
                        const struct silofs_vaddr *vaddr,
                        struct silofs_vnode_info **out_vi)
{
	*out_vi = silofs_cache_spawn_vnode(sbi_cache(sbi), vaddr);
	return (*out_vi == NULL) ? -ENOMEM : 0;
}

static int sbi_spawn_vi(struct silofs_sb_info *sbi,
                        const struct silofs_vaddr *vaddr,
                        struct silofs_vnode_info **out_vi)
{
	int err;
	int retry = 2;
	struct silofs_cache *cache = sbi_cache(sbi);

	while (retry-- > 0) {
		err = try_spawn_vi(sbi, vaddr, out_vi);
		if (!err) {
			return 0;
		}
		err = sbi_commit_dirty_now(sbi);
		if (err) {
			return err;
		}
	}
	log_dbg("can not spawn vi: nodes=%lu ndirty=%lu",
	        cache->c_vi_lm.lm_htbl_sz, sbi_cache_ndirty(sbi));
	return -ENOMEM;
}

static int sbi_spawn_bind_vi(struct silofs_sb_info *sbi,
                             const struct silofs_vaddr *vaddr,
                             struct silofs_vbk_info *vbi,
                             struct silofs_vnode_info **out_vi)
{
	int err;

	err = sbi_spawn_vi(sbi, vaddr, out_vi);
	if (err) {
		return err;
	}
	vi_bind_to(*out_vi, sbi_apex(sbi), vbi);
	return 0;
}

static int sbi_stage_spnode_spleaf(struct silofs_sb_info *sbi, loff_t voff,
                                   enum silofs_stage_flags stg_flags,
                                   struct silofs_spnode_info **out_sni,
                                   struct silofs_spleaf_info **out_sli)
{
	int err;

	err = silofs_stage_spnode(sbi, voff, stg_flags, out_sni);
	if (err) {
		return err;
	}
	silofs_sni_incref(*out_sni);
	err = silofs_stage_spleaf(sbi, voff, stg_flags, out_sli);
	silofs_sni_decref(*out_sni);
	if (err) {
		return err;
	}
	return 0;
}

static int sbi_require_stable_at(struct silofs_sb_info *sbi,
                                 const struct silofs_vaddr *vaddr,
                                 enum silofs_stage_flags stg_flags)
{
	int err;
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spleaf_info *sli = NULL;
	const loff_t voff = vaddr_off(vaddr);

	err = sbi_stage_spnode_spleaf(sbi, voff, stg_flags, &sni, &sli);
	if (err) {
		return err;
	}
	err = silofs_sli_check_stable_at(sli, vaddr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_spawn_bind_vnode_at(struct silofs_sb_info *sbi,
                               const struct silofs_ovaddr *ova,
                               enum silofs_stage_flags stg_flags,
                               struct silofs_vnode_info **out_vi)
{
	int err;
	struct silofs_vbk_info *vbi = NULL;

	err = sbi_require_stable_at(sbi, &ova->vaddr, stg_flags);
	if (err) {
		return err;
	}
	err = sbi_stage_vblock(sbi, ova, &vbi);
	if (err) {
		return err;
	}
	err = sbi_spawn_bind_vi(sbi, &ova->vaddr, vbi, out_vi);
	if (err) {
		return err;
	}
	return 0;
}

static void sbi_forget_cached_vi(struct silofs_sb_info *sbi,
                                 struct silofs_vnode_info *vi)
{
	if (vi != NULL) {
		silofs_cache_forget_vnode(sbi_cache(sbi), vi);
	}
}

static void sbi_forget_cached_ii(struct silofs_sb_info *sbi,
                                 struct silofs_inode_info *ii)
{
	if (ii != NULL) {
		sbi_forget_cached_vi(sbi, ii_to_vi(ii));
	}
}

static int sbi_try_spawn_ui(struct silofs_sb_info *sbi,
                            const struct silofs_uaddr *uaddr,
                            struct silofs_unode_info **out_ui)
{
	*out_ui = silofs_cache_spawn_unode(sbi_cache(sbi), uaddr);
	return (*out_ui == NULL) ? -ENOMEM : 0;
}

static int sbi_spawn_ui(struct silofs_sb_info *sbi,
                        const struct silofs_uaddr *uaddr,
                        struct silofs_unode_info **out_ui)
{
	int err;
	int retry = 2;
	struct silofs_cache *cache = sbi_cache(sbi);

	while (retry-- > 0) {
		err = sbi_try_spawn_ui(sbi, uaddr, out_ui);
		if (!err) {
			return 0;
		}
		err = sbi_commit_dirty_now(sbi);
		if (err) {
			return err;
		}
	}
	log_dbg("can not spawn ui: nodes=%lu ndirty=%lu",
	        cache->c_ui_lm.lm_htbl_sz, sbi_cache_ndirty(sbi));
	return -ENOMEM;
}

static int sbi_spawn_bind_ui(struct silofs_sb_info *sbi,
                             const struct silofs_uaddr *uaddr,
                             struct silofs_ubk_info *ubi,
                             struct silofs_unode_info **out_ui)
{
	int err;
	struct silofs_unode_info *ui = NULL;

	err = sbi_spawn_ui(sbi, uaddr, &ui);
	if (err) {
		return err;
	}
	ui_bind_to(ui, sbi_apex(sbi), ubi);
	*out_ui = ui;
	return 0;
}

static int sbi_spawn_spmap(struct silofs_sb_info *sbi,
                           const struct silofs_uaddr *uaddr,
                           struct silofs_unode_info **out_ui)
{
	int err;
	struct silofs_ubk_info *ubi = NULL;

	err = sbi_stage_block(sbi, &uaddr->oaddr, &ubi);
	if (err) {
		return err;
	}
	err = sbi_spawn_bind_ui(sbi, uaddr, ubi, out_ui);
	if (err) {
		return err;
	}
	ui_stamp_mark_visible(*out_ui);
	return 0;
}

int silofs_sbi_shut(struct silofs_sb_info *sbi)
{
	const struct silofs_fs_apex *apex = sbi_apex(sbi);

	log_dbg("shut-super: op_count=%lu", apex->fa_ops.op_count);
	silofs_itbi_reinit(&sbi->s_itbi);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sbi_main_treeid(const struct silofs_sb_info *sbi,
                            struct silofs_metaid *out_mid)
{
	sb_main_treeid(sbi->sb, out_mid);
}

static void sbi_main_blobid(const struct silofs_sb_info *sbi,
                            struct silofs_blobid *out_bid)
{
	sb_main_blobid(sbi->sb, out_bid);
}

static void sbi_bind_main_blob(struct silofs_sb_info *sbi,
                               const struct silofs_blobid *bid)
{
	sbu_set_main_blobid(&sbi->sb->sb_usm, bid);
	sbi_dirtify(sbi);
}

static bool sbi_has_main_blob(const struct silofs_sb_info *sbi)
{
	struct silofs_blobid blob_id;

	sbi_main_blobid(sbi, &blob_id);
	return (blobid_size(&blob_id) > 0);
}

static size_t sbi_space_tree_height(const struct silofs_sb_info *sbi)
{
	const struct silofs_super_block *sb = sbi->sb;

	return sbu_height(&sb->sb_usm);
}

static loff_t
sbi_bpos_of_child_spnode(const struct silofs_sb_info *sbi, loff_t voff)
{
	const size_t slot = sb_slot_of(sbi->sb, voff);

	return (long)slot * SILOFS_SPNODE_SIZE;
}

static loff_t
sbi_base_voff_of_child(const struct silofs_sb_info *sbi, loff_t voff)
{
	struct silofs_vrange vrange;
	const size_t child_height = sbi_space_tree_height(sbi) - 1;

	silofs_assert_eq(child_height, SILOFS_SPNODE_HEIGHT_MAX);

	silofs_vrange_setup_by(&vrange, child_height, voff);
	return vrange.beg;
}

static void sbi_main_child_uaddr(const struct silofs_sb_info *sbi,
                                 loff_t voff, struct silofs_uaddr *out_uaddr)
{
	loff_t base;
	loff_t bpos;
	struct silofs_blobid bid;
	const size_t child_height = SILOFS_SPNODE_HEIGHT_MAX;
	const enum silofs_stype child_stype = SILOFS_STYPE_SPNODE;

	sbi_main_blobid(sbi, &bid);
	silofs_assert_eq(bid.height, child_height);

	base = sbi_base_voff_of_child(sbi, voff);
	bpos = sbi_bpos_of_child_spnode(sbi, voff);
	silofs_uaddr_setup(out_uaddr, &bid, child_stype, bpos, base);
}

static int flush_dirty_cache(struct silofs_sb_info *sbi, bool all)
{
	return silofs_apex_flush_dirty(sbi_apex(sbi), all ? SILOFS_F_NOW : 0);
}

static void sbi_update_vspace_last(struct silofs_sb_info *sbi, loff_t voff)
{
	const loff_t voff_last = silofs_sb_vspace_last(sbi->sb);

	if (voff > voff_last) {
		sb_set_vspace_last(sbi->sb, voff);
		sbi_dirtify(sbi);
	}
}

static void
sbi_update_vspace_last_by_spnode(struct silofs_sb_info *sbi,
                                 const struct silofs_spnode_info *sni)
{
	struct silofs_vrange vrange;

	silofs_sni_vspace_range(sni, &vrange);
	sbi_update_vspace_last(sbi, vrange.beg);
}

static void
sbi_update_vspace_last_by_spleaf(struct silofs_sb_info *sbi,
                                 const struct silofs_spleaf_info *sli)
{
	struct silofs_vrange vrange;

	silofs_sli_vspace_range(sli, &vrange);
	sbi_update_vspace_last(sbi, vrange.end);
}

static void sbi_bind_child_spnode(struct silofs_sb_info *sbi,
                                  struct silofs_spnode_info *sni)
{
	struct silofs_vrange vrange;

	silofs_sni_vspace_range(sni, &vrange);
	sb_bind_spnode(sbi->sb, vrange.beg, ui_uaddr(&sni->sn_ui));
	sbi_update_vspace_last_by_spnode(sbi, sni);
	sbi_dirtify(sbi);
}

static int sbi_stage_main_blob(struct silofs_sb_info *sbi)
{
	struct silofs_blobid bid;
	struct silofs_blob_info *bli = NULL;

	sbi_main_blobid(sbi, &bid);
	return sbi_stage_blob_at(sbi, &bid, &bli);
}

static void sbi_make_blobid_for(const struct silofs_sb_info *sbi,
                                enum silofs_stype stype, size_t nobjs,
                                size_t height, struct silofs_blobid *out_bid)
{
	struct silofs_metaid tree_id;
	const size_t obj_size = stype_size(stype);

	sbi_main_treeid(sbi, &tree_id);
	silofs_blobid_make(out_bid, &tree_id, obj_size, nobjs, height);
}

static int sbi_spawn_main_blob(struct silofs_sb_info *sbi)
{
	struct silofs_blobid bid;
	struct silofs_blob_info *bli = NULL;
	const size_t nchilds = ARRAY_SIZE(sbi->sb->sb_usm.su_child);
	const size_t height = SILOFS_SPNODE_HEIGHT_MAX;
	int err;

	sbi_make_blobid_for(sbi, SILOFS_STYPE_SPNODE, nchilds, height, &bid);
	err = sbi_spawn_blob_at(sbi, &bid, &bli);
	if (err) {
		return err;
	}
	sbi_bind_main_blob(sbi, &bli->bl_bid);
	return 0;
}

static int sbi_require_main_blob(struct silofs_sb_info *sbi)
{
	int err;

	if (sbi_has_main_blob(sbi)) {
		err = sbi_stage_main_blob(sbi);
	} else {
		err = sbi_spawn_main_blob(sbi);
	}
	return err;
}

static int sbi_spawn_top_spnode_of(struct silofs_sb_info *sbi, loff_t voff,
                                   struct silofs_spnode_info **out_sni)
{
	struct silofs_uaddr uaddr;
	struct silofs_vrange vrange;
	struct silofs_unode_info *ui = NULL;
	struct silofs_spnode_info *sni = NULL;
	const size_t height = sbi_space_tree_height(sbi) - 1;
	int err;

	err = sbi_require_main_blob(sbi);
	if (err) {
		return err;
	}

	silofs_vrange_of_spnode(&vrange, height, voff);
	sbi_main_child_uaddr(sbi, voff, &uaddr);

	err = sbi_spawn_spmap(sbi, &uaddr, &ui);
	if (err) {
		return err;
	}
	sni = silofs_sni_from_ui(ui);
	silofs_sni_rebind_view(sni);
	silofs_sni_setup_spawned(sni, height, &vrange);
	*out_sni = sni;
	return 0;
}

static int sbi_stage_spnode_main_blob(struct silofs_sb_info *sbi,
                                      struct silofs_spnode_info *sni)
{
	struct silofs_blobid bid;
	struct silofs_blob_info *bli = NULL;

	silofs_sni_main_blob(sni, &bid);
	return sbi_stage_blob_at(sbi, &bid, &bli);
}

static int sbi_spawn_spnode_main_blob(struct silofs_sb_info *sbi,
                                      struct silofs_spnode_info *sni)
{
	int err;
	struct silofs_blobid bid;
	struct silofs_blob_info *bli = NULL;
	const size_t nchilds = ARRAY_SIZE(sni->sn->sn_child);
	const size_t height = silofs_sni_child_height(sni);
	const enum silofs_stype stype = silofs_sni_child_stype(sni);

	sbi_make_blobid_for(sbi, stype, nchilds, height, &bid);
	err = sbi_spawn_blob_at(sbi, &bid, &bli);
	if (err) {
		return err;
	}
	silofs_sni_bind_main_blob(sni, &bli->bl_bid);
	return 0;
}

static int sbi_require_spnode_main_blob(struct silofs_sb_info *sbi,
                                        struct silofs_spnode_info *sni)
{
	int err;

	if (silofs_sni_has_main_blob(sni)) {
		err = sbi_stage_spnode_main_blob(sbi, sni);
	} else {
		err = sbi_spawn_spnode_main_blob(sbi, sni);
	}
	return err;
}

static int sbi_spawn_sub_spnode_of(struct silofs_sb_info *sbi, loff_t voff,
                                   struct silofs_spnode_info *sni_parent,
                                   struct silofs_spnode_info **out_sni)
{
	struct silofs_uaddr uaddr;
	struct silofs_vrange vrange;
	struct silofs_unode_info *ui = NULL;
	struct silofs_spnode_info *sni = NULL;
	const size_t height = silofs_sni_height(sni_parent) - 1;
	int err;

	err = sbi_require_spnode_main_blob(sbi, sni_parent);
	if (err) {
		return err;
	}

	silofs_vrange_of_spnode(&vrange, height, voff);
	silofs_sni_main_child_uaddr(sni_parent, voff, &uaddr);

	err = sbi_spawn_spmap(sbi, &uaddr, &ui);
	if (err) {
		return err;
	}
	sni = silofs_sni_from_ui(ui);
	silofs_sni_rebind_view(sni);
	silofs_sni_setup_spawned(sni, height, &vrange);
	*out_sni = sni;
	return 0;
}

static int sbi_format_head_spmaps_of(struct silofs_sb_info *sbi)
{
	int err;
	loff_t voff = -1;

	err = silofs_sbi_expand_vspace(sbi, SILOFS_STYPE_DATABK, &voff);
	if (err) {
		log_err("failed to format head spmaps: err=%d", err);
	}
	return err;
}

int silofs_sbi_format_spmaps(struct silofs_sb_info *sbi)
{
	int err;

	err = sbi_format_head_spmaps_of(sbi);
	if (err) {
		return err;
	}
	err = flush_dirty_cache(sbi, true);
	if (err) {
		return err;
	}
	return 0;
}

static int
sbi_resolve_child_spnode(const struct silofs_sb_info *sbi,
                         loff_t voff, struct silofs_uaddr *out_uaddr)
{
	sb_resolve_spnode(sbi->sb, voff, out_uaddr);
	return uaddr_isnull(out_uaddr) ? -ENOENT : 0;
}

static int sbi_try_stage_cached_spnode(struct silofs_sb_info *sbi,
                                       const struct silofs_uaddr *uaddr,
                                       struct silofs_spnode_info **out_sni)
{
	int err;
	struct silofs_unode_info *ui = NULL;

	err = sbi_lookup_cached_ui(sbi, uaddr, &ui);
	if (err) {
		return err;
	}
	*out_sni = silofs_sni_from_ui(ui);
	return 0;
}

static int sbi_try_stage_cached_spleaf(struct silofs_sb_info *sbi,
                                       const struct silofs_uaddr *uaddr,
                                       struct silofs_spleaf_info **out_sli)
{
	int err;
	struct silofs_unode_info *ui = NULL;

	err = sbi_lookup_cached_ui(sbi, uaddr, &ui);
	if (err) {
		return err;
	}
	*out_sli = silofs_sli_from_ui(ui);
	return 0;
}

static int sbi_stage_spmap_at(struct silofs_sb_info *sbi,
                              const struct silofs_uaddr *uaddr,
                              struct silofs_unode_info **out_ui)
{
	int err;
	struct silofs_ubk_info *ubi = NULL;

	err = sbi_stage_block(sbi, &uaddr->oaddr, &ubi);
	if (err) {
		return err;
	}
	err = sbi_spawn_bind_ui(sbi, uaddr, ubi, out_ui);
	if (err) {
		return err;
	}
	err = silofs_ui_verify_view(*out_ui);
	if (err) {
		/* TODO: unbind forget here */
		return err;
	}
	return 0;
}

static int sbi_stage_spnode_at(struct silofs_sb_info *sbi,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_spnode_info **out_sni)
{
	int err;
	struct silofs_unode_info *ui = NULL;
	struct silofs_spnode_info *sni = NULL;

	err = sbi_try_stage_cached_spnode(sbi, uaddr, out_sni);
	if (!err) {
		return 0; /* cache hit */
	}
	err = sbi_stage_spmap_at(sbi, uaddr, &ui);
	if (err) {
		return err;
	}
	sni = silofs_sni_from_ui(ui);
	silofs_sni_rebind_view(sni);
	silofs_sni_update_staged(sni);

	*out_sni = sni;
	return 0;
}

static int sbi_stage_spleaf_at(struct silofs_sb_info *sbi,
                               const struct silofs_uaddr *uaddr,
                               struct silofs_spleaf_info **out_sli)
{
	int err;
	struct silofs_unode_info *ui = NULL;
	struct silofs_spleaf_info *sli = NULL;

	err = sbi_try_stage_cached_spleaf(sbi, uaddr, out_sli);
	if (!err) {
		return 0; /* cache hit */
	}
	err = sbi_stage_spmap_at(sbi, uaddr, &ui);
	if (err) {
		return err;
	}
	sli = silofs_sli_from_ui(ui);
	silofs_sli_rebind_view(sli);
	silofs_sli_update_staged(sli);
	*out_sli = sli;
	return 0;
}

static bool sbi_ismutable_blobid(const struct silofs_sb_info *sbi,
                                 const struct silofs_blobid *bid)
{
	struct silofs_metaid tree_id;

	sbi_main_treeid(sbi, &tree_id);
	return metaid_isequal(&tree_id, &bid->tree_id);
}

static bool sbi_ismutable_oaddr(const struct silofs_sb_info *sbi,
                                const struct silofs_oaddr *oaddr)
{
	return sbi_ismutable_blobid(sbi, &oaddr->bid);
}

static int sbi_inspect_oaddr(const struct silofs_sb_info *sbi,
                             const struct silofs_oaddr *oaddr,
                             enum silofs_stage_flags stg_flags)
{
	const bool want_mut = (stg_flags & SILOFS_STAGE_MUTABLE) > 0;

	return (want_mut && !sbi_ismutable_oaddr(sbi, oaddr)) ? -EPERM : 0;
}

static int sbi_inspect_ova(const struct silofs_sb_info *sbi,
                           const struct silofs_ovaddr *ova,
                           enum silofs_stage_flags stg_flags)
{
	return sbi_inspect_oaddr(sbi, &ova->oaddr, stg_flags);
}

static int sbi_inspect_cached_ui(const struct silofs_sb_info *sbi,
                                 const struct silofs_unode_info *ui,
                                 enum silofs_stage_flags stg_flags)
{
	const struct silofs_uaddr *uaddr = ui_uaddr(ui);

	return sbi_inspect_oaddr(sbi, &uaddr->oaddr, stg_flags);
}

static int sbi_inspect_cached_sni(const struct silofs_sb_info *sbi,
                                  const struct silofs_spnode_info *sni,
                                  enum silofs_stage_flags stg_flags)
{
	return sbi_inspect_cached_ui(sbi, &sni->sn_ui, stg_flags);
}

static int sbi_inspect_cached_sli(const struct silofs_sb_info *sbi,
                                  const struct silofs_spleaf_info *sli,
                                  enum silofs_stage_flags stg_flags)
{
	return sbi_inspect_cached_ui(sbi, &sli->sl_ui, stg_flags);
}

static int sbi_spawn_top_spnode(struct silofs_sb_info *sbi, loff_t voff,
                                struct silofs_spnode_info **out_sni)
{
	int err;
	struct silofs_spnode_info *sni = NULL;

	err = sbi_spawn_top_spnode_of(sbi, voff, &sni);
	if (err) {
		return err;
	}
	sbi_update_uspace_meta(sbi, ui_stype(&sni->sn_ui));
	*out_sni = sni;
	return 0;
}

static int sbi_spawn_bind_top_spnode(struct silofs_sb_info *sbi, loff_t voff,
                                     struct silofs_spnode_info **out_sni)
{
	int err;
	struct silofs_spnode_info *sni = NULL;

	err = sbi_spawn_top_spnode(sbi, voff, &sni);
	if (err) {
		return err;
	}
	sbi_bind_child_spnode(sbi, sni);
	*out_sni = sni;
	return 0;
}

static int
sbi_spawn_sub_spnode(struct silofs_sb_info *sbi,
                     struct silofs_spnode_info *sni_parent,
                     loff_t voff, struct silofs_spnode_info **out_sni)
{
	int err;
	struct silofs_spnode_info *sni = NULL;

	err = sbi_spawn_sub_spnode_of(sbi, voff, sni_parent, &sni);
	if (err) {
		return err;
	}
	sbi_update_uspace_meta(sbi, ui_stype(&sni->sn_ui));
	*out_sni = sni;
	return 0;
}

static int
sbi_spawn_bind_sub_spnode(struct silofs_sb_info *sbi, loff_t voff,
                          struct silofs_spnode_info *sni_parent,
                          struct silofs_spnode_info **out_sni)
{
	int err;
	struct silofs_spnode_info *sni = NULL;

	err = sbi_spawn_sub_spnode(sbi, sni_parent, voff, &sni);
	if (err) {
		return err;
	}
	silofs_sni_bind_child_spnode(sni_parent, sni);
	*out_sni = sni;
	return 0;
}

static int sbi_do_clone_top_spnode(struct silofs_sb_info *sbi,
                                   struct silofs_spnode_info *sni_curr,
                                   struct silofs_spnode_info **out_sni)
{
	int err;
	struct silofs_metaid mid;
	struct silofs_vrange vrange;
	struct silofs_spnode_info *sni_next = NULL;
	const struct silofs_uaddr *uaddr = silofs_sni_uaddr(sni_curr);

	sbi_main_treeid(sbi, &mid);
	silofs_assert_ne(uaddr->oaddr.bid.tree_id.id[0], mid.id[0]);
	silofs_assert_ne(uaddr->oaddr.bid.tree_id.id[1], mid.id[1]);

	silofs_sni_vspace_range(sni_curr, &vrange);
	err = sbi_spawn_top_spnode(sbi, vrange.beg, &sni_next);
	if (err) {
		return err;
	}
	silofs_sni_clone_childs(sni_next, sni_curr);
	sbi_bind_child_spnode(sbi, sni_next);
	*out_sni = sni_next;
	return 0;
}

static int sbi_clone_top_spnode(struct silofs_sb_info *sbi,
                                struct silofs_spnode_info *sni,
                                struct silofs_spnode_info **out_sni)
{
	int err;

	silofs_sni_incref(sni);
	err = sbi_do_clone_top_spnode(sbi, sni, out_sni);
	silofs_sni_decref(sni);
	return err;
}

static int sbi_stage_top_spnode(struct silofs_sb_info *sbi, loff_t voff,
                                enum silofs_stage_flags stg_flags,
                                struct silofs_spnode_info **out_sni)
{
	int err;
	struct silofs_uaddr uaddr;
	struct silofs_spnode_info *sni = NULL;

	err = sbi_resolve_child_spnode(sbi, voff, &uaddr);
	if (err) {
		return err;
	}
	err = sbi_stage_spnode_at(sbi, &uaddr, &sni);
	if (err) {
		return err;
	}
	err = sbi_inspect_cached_sni(sbi, sni, stg_flags);
	if (!err) {
		goto out_ok;
	}
	err = sbi_clone_top_spnode(sbi, sni, &sni);
	if (err) {
		return err;
	}
out_ok:
	*out_sni = sni;
	return 0;
}

static int sbi_do_clone_sub_spnode(struct silofs_sb_info *sbi,
                                   struct silofs_spnode_info *sni_parent,
                                   struct silofs_spnode_info *sni_curr,
                                   struct silofs_spnode_info **out_sni)
{
	int err;
	struct silofs_spnode_info *sni_next = NULL;
	const loff_t voff = silofs_sni_base_voff(sni_curr);

	err = sbi_spawn_sub_spnode(sbi, sni_parent, voff, &sni_next);
	if (err) {
		return err;
	}
	silofs_sni_clone_childs(sni_next, sni_curr);
	silofs_sni_bind_child_spnode(sni_parent, sni_next);
	*out_sni = sni_next;
	return 0;
}

static int sbi_clone_sub_spnode(struct silofs_sb_info *sbi,
                                struct silofs_spnode_info *sni_parent,
                                struct silofs_spnode_info *sni_curr,
                                struct silofs_spnode_info **out_sni)
{
	int err;

	silofs_sni_incref(sni_parent);
	silofs_sni_incref(sni_curr);
	err = sbi_do_clone_sub_spnode(sbi, sni_parent, sni_curr, out_sni);
	silofs_sni_decref(sni_curr);
	silofs_sni_decref(sni_parent);
	return err;
}

static int sbi_stage_sub_spnode(struct silofs_sb_info *sbi,
                                struct silofs_spnode_info *sni_parent,
                                loff_t voff, enum silofs_stage_flags stg_flags,
                                struct silofs_spnode_info **out_sni)
{
	int err;
	struct silofs_uaddr uaddr;
	struct silofs_spnode_info *sni = NULL;

	err = silofs_sni_resolve_child(sni_parent, voff, &uaddr);
	if (err) {
		return err;
	}
	silofs_assert_eq(uaddr.stype, SILOFS_STYPE_SPNODE);
	err = sbi_stage_spnode_at(sbi, &uaddr, &sni);
	if (err) {
		return err;
	}
	err = sbi_inspect_cached_sni(sbi, sni, stg_flags);
	if (!err) {
		goto out_ok;
	}
	err = sbi_clone_sub_spnode(sbi, sni_parent, sni, &sni);
	if (err) {
		return err;
	}
out_ok:
	*out_sni = sni;
	return 0;
}

static int sbi_spawn_spleaf_of(struct silofs_sb_info *sbi,
                               struct silofs_spnode_info *sni,
                               loff_t voff, enum silofs_stype stype_sub,
                               struct silofs_spleaf_info **out_sli)
{
	int err;
	struct silofs_uaddr uaddr;
	struct silofs_vrange vrange;
	struct silofs_unode_info *ui = NULL;
	struct silofs_spleaf_info *sli = NULL;

	err = sbi_require_spnode_main_blob(sbi, sni);
	if (err) {
		return err;
	}

	silofs_vrange_of_spleaf(&vrange, voff);
	silofs_sni_main_child_uaddr(sni, voff, &uaddr);

	err = sbi_spawn_spmap(sbi, &uaddr, &ui);
	if (err) {
		return err;
	}
	sli = silofs_sli_from_ui(ui);
	silofs_sli_rebind_view(sli);
	silofs_sli_setup_spawned(sli, &vrange, stype_sub);
	*out_sli = sli;
	return 0;
}

static int sbi_spawn_spleaf_main_blob(struct silofs_sb_info *sbi,
                                      struct silofs_spleaf_info *sli)
{
	int err;
	struct silofs_blobid bid;
	struct silofs_blob_info *bli = NULL;
	const size_t nchilds = ARRAY_SIZE(sli->sl->sl_bkr);

	sbi_make_blobid_for(sbi, SILOFS_STYPE_ANONBK, nchilds, 0, &bid);
	err = sbi_spawn_blob_at(sbi, &bid, &bli);
	if (err) {
		return err;
	}
	silofs_sli_bind_main_blob(sli, &bli->bl_bid);
	return 0;
}

static int sbi_spawn_spleaf(struct silofs_sb_info *sbi,
                            struct silofs_spnode_info *sni,
                            loff_t voff, enum silofs_stype stype_sub,
                            struct silofs_spleaf_info **out_sli)
{
	int err;
	struct silofs_spleaf_info *sli = NULL;

	err = sbi_spawn_spleaf_of(sbi, sni, voff, stype_sub, &sli);
	if (err) {
		return err;
	}
	err = sbi_spawn_spleaf_main_blob(sbi, sli);
	if (err) {
		return err;
	}
	sbi_update_uspace_meta(sbi, ui_stype(&sli->sl_ui));
	*out_sli = sli;
	return 0;
}

static int sbi_do_clone_sub_spleaf(struct silofs_sb_info *sbi,
                                   struct silofs_spnode_info *sni_parent,
                                   struct silofs_spleaf_info *sli_curr,
                                   struct silofs_spleaf_info **out_sli)
{
	int err;
	struct silofs_spleaf_info *sli_next = NULL;
	const loff_t voff = silofs_sli_base_voff(sli_curr);
	const enum silofs_stype stype_sub = silofs_sli_stype_sub(sli_curr);

	err = sbi_spawn_spleaf(sbi, sni_parent, voff, stype_sub, &sli_next);
	if (err) {
		return err;
	}
	silofs_sli_clone_childs(sli_next, sli_curr);
	silofs_sni_bind_child_spleaf(sni_parent, sli_next);
	*out_sli = sli_next;
	return 0;
}

static int sbi_clone_sub_spleaf(struct silofs_sb_info *sbi,
                                struct silofs_spnode_info *sni_parent,
                                struct silofs_spleaf_info *sli_curr,
                                struct silofs_spleaf_info **out_sli)
{
	int err;

	silofs_sni_incref(sni_parent);
	silofs_sli_incref(sli_curr);
	err = sbi_do_clone_sub_spleaf(sbi, sni_parent, sli_curr, out_sli);
	silofs_sli_decref(sli_curr);
	silofs_sni_decref(sni_parent);
	return err;
}

static int sbi_stage_sub_spleaf(struct silofs_sb_info *sbi,
                                struct silofs_spnode_info *sni_parent,
                                loff_t voff, enum silofs_stage_flags stg_flags,
                                struct silofs_spleaf_info **out_sli)
{
	int err;
	struct silofs_uaddr uaddr;
	struct silofs_spleaf_info *sli = NULL;

	err = silofs_sni_resolve_child(sni_parent, voff, &uaddr);
	if (err) {
		return err;
	}
	err = sbi_stage_spleaf_at(sbi, &uaddr, &sli);
	if (err) {
		return err;
	}
	err = sbi_inspect_cached_sli(sbi, sli, stg_flags);
	if (!err) {
		goto out_ok;
	}
	err = sbi_clone_sub_spleaf(sbi, sni_parent, sli, &sli);
	if (err) {
		return err;
	}
out_ok:
	*out_sli = sli;
	return 0;
}

static bool sbi_has_child_at(const struct silofs_sb_info *sbi, loff_t voff)
{
	return sb_has_spnode(sbi->sb, voff);
}

static int
sbi_require_top_spnode(struct silofs_sb_info *sbi, loff_t voff,
                       enum silofs_stage_flags stg_flags,
                       struct silofs_spnode_info **out_sni)
{
	int err;

	if (sbi_has_child_at(sbi, voff)) {
		err = sbi_stage_top_spnode(sbi, voff, stg_flags, out_sni);
	} else {
		err = sbi_spawn_bind_top_spnode(sbi, voff, out_sni);
	}
	return err;
}

static int
sbi_require_sub_spnode(struct silofs_sb_info *sbi,
                       struct silofs_spnode_info *sni_parent,
                       loff_t voff, enum silofs_stage_flags stg_flags,
                       struct silofs_spnode_info **out_sni)
{
	int err;

	if (silofs_sni_has_child_at(sni_parent, voff)) {
		err = sbi_stage_sub_spnode(sbi, sni_parent,
		                           voff, stg_flags, out_sni);
	} else {
		err = sbi_spawn_bind_sub_spnode(sbi, voff,
		                                sni_parent, out_sni);
	}
	return err;
}

static int
sbi_require_child_spnode(struct silofs_sb_info *sbi,
                         struct silofs_spnode_info *sni_parent,
                         loff_t voff, enum silofs_stage_flags stg_flags,
                         struct silofs_spnode_info **out_sni)
{
	int err;

	if (sni_parent == NULL) {
		err = sbi_require_top_spnode(sbi, voff, stg_flags, out_sni);
	} else {
		err = sbi_require_sub_spnode(sbi, sni_parent,
		                             voff, stg_flags, out_sni);
	}
	return err;
}

static int sbi_require_spnodes_to(struct silofs_sb_info *sbi, loff_t voff,
                                  enum silofs_stage_flags stg_flags,
                                  struct silofs_spnode_info **out_sni)
{
	int err;
	size_t height;
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spnode_info *sni_parent = NULL;
	const size_t spleaf_height = SILOFS_SPLEAF_HEIGHT;

	height = sbi_space_tree_height(sbi);
	while (--height > spleaf_height) {
		err = sbi_require_child_spnode(sbi, sni_parent,
		                               voff, stg_flags, &sni);
		if (err) {
			return err;
		}
		sni_parent = sni;
	}
	*out_sni = sni;
	return 0;
}

static int
sbi_stage_child_spnode(struct silofs_sb_info *sbi, loff_t voff,
                       struct silofs_spnode_info *sni_parent,
                       enum silofs_stage_flags stg_flags,
                       struct silofs_spnode_info **out_sni)
{
	int err;

	if (sni_parent == NULL) {
		err = sbi_stage_top_spnode(sbi, voff, stg_flags, out_sni);
	} else {
		err = sbi_stage_sub_spnode(sbi, sni_parent,
		                           voff, stg_flags, out_sni);
	}
	return err;
}

static int sbi_stage_spnodes_to(struct silofs_sb_info *sbi, loff_t voff,
                                enum silofs_stage_flags stg_flags,
                                struct silofs_spnode_info **out_sni)
{
	int err;
	size_t height;
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spnode_info *sni_parent = NULL;
	const size_t spleaf_height = SILOFS_SPLEAF_HEIGHT;

	height = sbi_space_tree_height(sbi);
	while (--height > spleaf_height) {
		err = sbi_stage_child_spnode(sbi, voff, sni_parent,
		                             stg_flags, &sni);
		if (err) {
			return err;
		}
		sni_parent = sni;
	}
	silofs_assert_eq(silofs_sni_height(sni), 2);
	*out_sni = sni;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sbi_do_spawn_bind_spleaf(struct silofs_sb_info *sbi,
                                    struct silofs_spnode_info *sni,
                                    const struct silofs_vaddr *vaddr)
{
	int err;
	struct silofs_spleaf_info *sli = NULL;

	err = sbi_spawn_spleaf(sbi, sni, vaddr->voff, vaddr->stype, &sli);
	if (err) {
		return err;
	}
	silofs_sni_bind_child_spleaf(sni, sli);
	sbi_update_vspace_last_by_spleaf(sbi, sli);
	return 0;
}

static int sbi_spawn_bind_spleaf_at(struct silofs_sb_info *sbi,
                                    struct silofs_spnode_info *sni,
                                    const struct silofs_vaddr *vaddr)
{
	int err;

	silofs_sni_incref(sni);
	err = sbi_do_spawn_bind_spleaf(sbi, sni, vaddr);
	silofs_sni_decref(sni);
	return err;
}

static int sbi_stage_mutable_spleaf(struct silofs_sb_info *sbi, loff_t voff,
                                    struct silofs_spleaf_info **out_sli)
{
	return silofs_stage_spleaf(sbi, voff, SILOFS_STAGE_MUTABLE, out_sli);
}

static int sbi_stage_rdonly_spleaf(struct silofs_sb_info *sbi, loff_t voff,
                                   struct silofs_spleaf_info **out_sli)
{
	return silofs_stage_spleaf(sbi, voff, SILOFS_STAGE_RDONLY, out_sli);
}

static int sbi_require_spleaf_at(struct silofs_sb_info *sbi,
                                 struct silofs_spnode_info *sni,
                                 const struct silofs_vaddr *vaddr)
{
	int err;
	const loff_t voff = vaddr_off(vaddr);
	struct silofs_spleaf_info *sli = NULL;

	if (silofs_sni_has_child_at(sni, voff)) {
		err = sbi_stage_mutable_spleaf(sbi, voff, &sli);
	} else {
		err = sbi_spawn_bind_spleaf_at(sbi, sni, vaddr);
	}
	return err;
}

static int sbi_require_spmaps_at(struct silofs_sb_info *sbi,
                                 const struct silofs_vaddr *vaddr,
                                 enum silofs_stage_flags stg_flags)
{
	int err;
	const loff_t voff = vaddr_off(vaddr);
	struct silofs_spnode_info *sni = NULL;

	err = sbi_require_spnodes_to(sbi, voff, stg_flags, &sni);
	if (err) {
		return err;
	}
	err = sbi_require_spleaf_at(sbi, sni, vaddr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_sbi_expand_vspace(struct silofs_sb_info *sbi,
                             enum silofs_stype stype, loff_t *out_voff)
{
	int err;
	loff_t voff = -1;
	struct silofs_vaddr vaddr;
	const enum silofs_stage_flags stg_flags = SILOFS_STAGE_MUTABLE;

	err = sbi_resolve_unformatted_end(sbi, &voff);
	if (err) {
		return err;
	}
	vaddr_setup(&vaddr, stype, voff);
	err = sbi_require_spmaps_at(sbi, &vaddr, stg_flags);
	if (err) {
		log_dbg("can not expand space: voff=0x%lx err=%d", voff, err);
		return err;
	}
	*out_voff = voff;
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sbi_reload_spnodes_to(struct silofs_sb_info *sbi, loff_t voff,
                                 struct silofs_spnode_info **out_sni)
{
	return sbi_stage_spnodes_to(sbi, voff, SILOFS_STAGE_RDONLY, out_sni);
}

static int sbi_reload_spleaf_at(struct silofs_sb_info *sbi,
                                struct silofs_spnode_info *sni, loff_t voff)
{
	int err;
	struct silofs_spleaf_info *sli = NULL;

	if (!silofs_sni_has_child_at(sni, voff)) {
		return -EFSCORRUPTED;
	}
	err = sbi_stage_rdonly_spleaf(sbi, voff, &sli);
	if (err) {
		return err;
	}
	return 0;
}

static int sbi_reload_first_spleaf_of(struct silofs_sb_info *sbi,
                                      struct silofs_spnode_info *sni)
{
	int err;
	struct silofs_vrange vrange;

	silofs_sni_incref(sni);
	silofs_sni_vspace_range(sni, &vrange);
	err = sbi_reload_spleaf_at(sbi, sni, vrange.beg);
	silofs_sni_decref(sni);
	return err;
}

static void sbi_relax_bringup_cache(struct silofs_sb_info *sbi)
{
	silofs_cache_relax(sbi_cache(sbi), SILOFS_F_BRINGUP);
}

int silofs_sbi_reload_spmaps(struct silofs_sb_info *sbi)
{
	int err;
	size_t cnt = 0;
	loff_t voff = 0;
	loff_t vend = silofs_sb_vspace_last(sbi->sb);
	struct silofs_spnode_info *sni = NULL;
	const size_t limit = SILOFS_SPMAP_NODE_NCHILDS;

	while ((voff < vend) && (cnt++ < limit)) {
		if (!sbi_has_child_at(sbi, voff)) {
			break;
		}
		err = sbi_reload_spnodes_to(sbi, voff, &sni);
		if (err) {
			return err;
		}
		err = sbi_reload_first_spleaf_of(sbi, sni);
		if (err) {
			return err;
		}
		sbi_relax_bringup_cache(sbi);

		voff = silofs_off_to_spnode_next(voff);
		sni = NULL;
	}
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sbi_resolve_itable_root(struct silofs_sb_info *sbi,
                                   struct silofs_vaddr *out_vaddr)
{
	struct silofs_vaddr vaddr;
	enum silofs_stype stype;

	sb_itable_root(sbi->sb, &vaddr);

	stype = vaddr_stype(&vaddr);
	if (vaddr_isnull(&vaddr) || !stype_isitnode(stype)) {
		log_err("non valid itable-root: off=0x%lx stype=%d",
		        vaddr_off(&vaddr), stype);
		return -EFSCORRUPTED;
	}
	vaddr_assign(out_vaddr, &vaddr);
	return 0;
}

int silofs_sbi_reload_itable(struct silofs_sb_info *sbi)
{
	int err;
	struct silofs_vaddr vaddr;

	err = sbi_resolve_itable_root(sbi, &vaddr);
	if (err) {
		return err;
	}
	err = silofs_reload_itable_at(sbi, &vaddr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_sbi_format_itable(struct silofs_sb_info *sbi)
{
	int err;
	struct silofs_vaddr vaddr;

	err = silofs_format_itable_root(sbi, &vaddr);
	if (err) {
		return err;
	}
	sb_set_itable_root(sbi->sb, &vaddr);
	sbi_dirtify(sbi);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_sbi_dirtify(struct silofs_sb_info *sbi)
{
	ui_dirtify(&sbi->s_ui);
}

void silofs_sbi_init_commons(struct silofs_sb_info *sbi)
{
	sbi->s_owner.uid = getuid();
	sbi->s_owner.gid = getgid();
	sbi->s_owner.pid = getpid();
	sbi->s_owner.umask = 0002;
	sbi->s_ctl_flags = 0;
	sbi->s_ms_flags = 0;
	sbi->s_mntime = 0;
}

static void sbi_fini_commons(struct silofs_sb_info *sbi)
{
	sbi->s_ctl_flags = 0;
	sbi->s_ms_flags = 0;
	sbi->sb = NULL;
}

static int sbi_init_iti(struct silofs_sb_info *sbi)
{
	return silofs_itbi_init(&sbi->s_itbi, sbi->s_alif);
}

static void sbi_fini_iti(struct silofs_sb_info *sbi)
{
	silofs_itbi_fini(&sbi->s_itbi);
}

static void sbi_bind_by(struct silofs_sb_info *sbi,
                        struct silofs_fs_apex *apex)
{
	sbi->s_ui.u_ti.t_apex = apex;
	sbi->s_alif = apex->fa_alif;
}

int silofs_sbi_xinit(struct silofs_sb_info *sbi, struct silofs_fs_apex *apex)
{
	sbi_bind_by(sbi, apex);
	return sbi_init_iti(sbi);
}

void silofs_sbi_fini(struct silofs_sb_info *sbi)
{
	sbi_fini_iti(sbi);
	sbi_fini_commons(sbi);
}

bool silofs_sbi_isrofs(const struct silofs_sb_info *sbi)
{
	const unsigned long mask = MS_RDONLY;

	return ((sbi->s_ms_flags & mask) == mask);
}

void silofs_sbi_attach_ubi(struct silofs_sb_info *sbi,
                           struct silofs_ubk_info *ubi)
{
	struct silofs_unode_info *ui = &sbi->s_ui;

	silofs_ui_attach_bk(ui, ubi);
	silofs_ui_bind_view(ui);
	sbi->sb = &ui->u_ti.t_view->sb;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static int sbi_find_cached_spmap(struct silofs_sb_info *sbi,
                                 loff_t voff, size_t height,
                                 struct silofs_unode_info **out_ui)
{
	struct silofs_taddr taddr;
	struct silofs_vrange vrange;
	struct silofs_metaid tree_id;

	sbi_main_treeid(sbi, &tree_id);
	silofs_vrange_setup_by(&vrange, height, voff);
	silofs_taddr_setup(&taddr, &tree_id, vrange.beg, height);

	*out_ui = silofs_cache_find_unode_by(sbi_cache(sbi), &taddr);
	return (*out_ui != NULL) ? 0 : -ENOENT;
}

static int sbi_find_cached_spnode(struct silofs_sb_info *sbi, loff_t voff,
                                  enum silofs_stage_flags stg_flags,
                                  struct silofs_spnode_info **out_sni)
{
	int err;
	struct silofs_unode_info *ui = NULL;
	struct silofs_spnode_info *sni = NULL;

	err = sbi_find_cached_spmap(sbi, voff, SILOFS_SPLEAF_HEIGHT + 1, &ui);
	if (err) {
		return err;
	}
	sni = silofs_sni_from_ui(ui);

	err = sbi_inspect_cached_sni(sbi, sni, stg_flags);
	if (err) {
		return err;
	}
	*out_sni = sni;
	return 0;
}

static int sbi_find_cached_spleaf(struct silofs_sb_info *sbi, loff_t voff,
                                  enum silofs_stage_flags stg_flags,
                                  struct silofs_spleaf_info **out_sli)
{
	int err;
	struct silofs_unode_info *ui = NULL;
	struct silofs_spleaf_info *sli = NULL;

	err = sbi_find_cached_spmap(sbi, voff, SILOFS_SPLEAF_HEIGHT, &ui);
	if (err) {
		return err;
	}
	sli = silofs_sli_from_ui(ui);

	err = sbi_inspect_cached_sli(sbi, sli, stg_flags);
	if (err) {
		return err;
	}
	*out_sli = sli;
	return 0;
}

int silofs_stage_spnode(struct silofs_sb_info *sbi, loff_t voff,
                        enum silofs_stage_flags stg_flags,
                        struct silofs_spnode_info **out_sni)
{
	int err;

	err = sbi_find_cached_spnode(sbi, voff, stg_flags, out_sni);
	if (!err) {
		return 0;
	}
	err = sbi_stage_spnodes_to(sbi, voff, stg_flags, out_sni);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_stage_spleaf(struct silofs_sb_info *sbi, loff_t voff,
                        enum silofs_stage_flags stg_flags,
                        struct silofs_spleaf_info **out_sli)
{
	int err;
	struct silofs_spnode_info *sni = NULL;

	err = sbi_find_cached_spleaf(sbi, voff, stg_flags, out_sli);
	if (!err) {
		return 0;
	}
	err = sbi_stage_spnodes_to(sbi, voff, stg_flags, &sni);
	if (err) {
		return err;
	}
	err = sbi_stage_sub_spleaf(sbi, sni, voff, stg_flags, out_sli);
	if (err) {
		return err;
	}
	return 0;
}

static int sbi_check_stage(const struct silofs_sb_info *sbi,
                           enum silofs_stage_flags stg_flags)
{
	int err = 0;

	if (stg_flags & SILOFS_STAGE_MUTABLE) {
		err = silof_check_writable_fs(sbi);
	}
	return err;
}

static int sbi_stage_vnode_at(struct silofs_sb_info *sbi,
                              const struct silofs_ovaddr *ova,
                              enum silofs_stage_flags stg_flags,
                              struct silofs_vnode_info **out_vi)
{
	int err;
	struct silofs_vnode_info *vi = NULL;

	err = silofs_spawn_bind_vnode_at(sbi, ova, stg_flags, &vi);
	if (err) {
		return err;
	}
	err = silofs_vi_verify_view(vi);
	if (err) {
		sbi_forget_cached_vi(sbi, vi);
		return err;
	}
	*out_vi = vi;
	return 0;
}

static int sbi_check_staged_inode(const struct silofs_inode_info *ii,
                                  enum silofs_stage_flags stg_flags)
{
	if (stg_flags & SILOFS_STAGE_MUTABLE) {
		if (silof_ii_isimmutable(ii)) {
			return -EACCES;
		}
	}
	return 0;
}

static int sbi_stage_inode_at(struct silofs_sb_info *sbi,
                              const struct silofs_iovaddr *iova,
                              enum silofs_stage_flags stg_flags,
                              struct silofs_inode_info **out_ii)
{
	int err;
	struct silofs_vnode_info *vi = NULL;
	struct silofs_inode_info *ii = NULL;

	err = sbi_stage_vnode_at(sbi, &iova->ova, stg_flags, &vi);
	if (err) {
		return err;
	}
	ii = silofs_ii_from_vi(vi);
	silofs_ii_rebind_view(ii, iova->ino);
	silofs_refresh_atime(ii, true);
	*out_ii = ii;
	return 0;
}

static bool cacheonly_mode(enum silofs_stage_flags flags)
{
	return (flags & SILOFS_STAGE_CACHEONLY) > 0;
}

static int sbi_resolve_ova(struct silofs_sb_info *sbi,
                           const struct silofs_vaddr *vaddr,
                           struct silofs_ovaddr *out_ova)
{
	struct silofs_oaddr oaddr;
	int err;

	err = silofs_resolve_oaddr(sbi, vaddr, &oaddr);
	if (err) {
		return err;
	}
	silofs_ovaddr_setup(out_ova, &oaddr, vaddr);
	return 0;
}

static int sbi_rebind_clone_vblock(struct silofs_sb_info *sbi,
                                   struct silofs_spleaf_info *sli,
                                   const struct silofs_ovaddr *ova_src,
                                   struct silofs_ovaddr *out_ova)
{
	struct silofs_ovaddr ova_dst;
	struct silofs_fiovec fiov_src;
	struct silofs_fiovec fiov_dst;
	const struct silofs_blobid *bid;
	struct silofs_blob_info *bli_src = NULL;
	struct silofs_blob_info *bli_dst = NULL;
	const struct silofs_vaddr *vaddr_src = &ova_src->vaddr;
	const size_t len = SILOFS_BK_SIZE;
	int err;

	silofs_sli_bind_to_main_at(sli, vaddr_src);
	silofs_sli_resolve_ova(sli, vaddr_src, &ova_dst);

	bid = &ova_src->oaddr.bid;
	err = silofs_apex_stage_blob(sbi_apex(sbi), bid, &bli_src);
	if (err) {
		return err;
	}
	err = silofs_bli_resolve_bk(bli_src, &ova_src->oaddr, &fiov_src);
	if (err) {
		return err;
	}

	bid = &ova_dst.oaddr.bid;
	err = silofs_apex_stage_blob(sbi_apex(sbi), bid, &bli_dst);
	if (err) {
		return err;
	}
	err = silofs_bli_resolve_bk(bli_dst, &ova_dst.oaddr, &fiov_dst);
	if (err) {
		return err;
	}

	err = silofs_apex_kcopy(sbi_apex(sbi), &fiov_src, &fiov_dst, len);
	if (err) {
		return err;
	}

	silofs_ovaddr_assign(out_ova, &ova_dst);
	return 0;
}

static int sbi_map_vaddr_to_ova(struct silofs_sb_info *sbi,
                                const struct silofs_vaddr *vaddr,
                                enum silofs_stage_flags stg_flags,
                                struct silofs_ovaddr *out_ova)
{
	struct silofs_spnode_info *sni = NULL;
	struct silofs_spleaf_info *sli = NULL;
	const loff_t voff = vaddr_off(vaddr);
	int err;

	err = sbi_resolve_ova(sbi, vaddr, out_ova);
	if (err) {
		return err;
	}
	err = sbi_inspect_ova(sbi, out_ova, stg_flags);
	if (!err) {
		return 0;
	}
	err = sbi_stage_spnode_spleaf(sbi, voff, stg_flags, &sni, &sli);
	if (err) {
		return err;
	}
	err = sbi_rebind_clone_vblock(sbi, sli, out_ova, out_ova);
	if (err) {
		return err;
	}
	return 0;
}

static int sbi_map_iaddr_to_ova(struct silofs_sb_info *sbi,
                                const struct silofs_iaddr *iaddr,
                                enum silofs_stage_flags stg_flags,
                                struct silofs_iovaddr *out_iova)
{
	struct silofs_ovaddr *out_ova = &out_iova->ova;

	out_iova->ino = iaddr->ino;
	return sbi_map_vaddr_to_ova(sbi, &iaddr->vaddr, stg_flags, out_ova);
}

static int sbi_stage_inode_by(struct silofs_sb_info *sbi,
                              const struct silofs_iaddr *iaddr,
                              enum silofs_stage_flags stg_flags,
                              struct silofs_inode_info **out_ii)
{
	int err;
	struct silofs_iovaddr iova = {
		.ino = SILOFS_INO_NULL
	};

	err = sbi_map_iaddr_to_ova(sbi, iaddr, stg_flags, &iova);
	if (err) {
		return err;
	}
	err = sbi_lookup_cached_ii(sbi, &iaddr->vaddr, out_ii);
	if (!err || cacheonly_mode(stg_flags)) {
		return err;
	}
	err = sbi_stage_inode_at(sbi, &iova, stg_flags, out_ii);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_stage_inode(struct silofs_sb_info *sbi, ino_t ino,
                       enum silofs_stage_flags stg_flags,
                       struct silofs_inode_info **out_ii)
{
	struct silofs_iaddr iaddr = {
		.ino = SILOFS_INO_NULL,
	};
	int err;

	err = sbi_check_stage(sbi, stg_flags);
	if (err) {
		return err;
	}
	err = silofs_resolve_iaddr(sbi, ino, &iaddr);
	if (err) {
		return err;
	}
	err = sbi_stage_inode_by(sbi, &iaddr, stg_flags, out_ii);
	if (err) {
		return err;
	}
	err = sbi_check_staged_inode(*out_ii, stg_flags);
	if (err) {
		return err;
	}
	return 0;
}

static int sbi_resolve_stage_vnode(struct silofs_sb_info *sbi,
                                   const struct silofs_vaddr *vaddr,
                                   enum silofs_stage_flags stg_flags,
                                   struct silofs_vnode_info **out_vi)
{
	struct silofs_ovaddr ova;
	int err;

	err = sbi_map_vaddr_to_ova(sbi, vaddr, stg_flags, &ova);
	if (err) {
		return err;
	}
	err = sbi_stage_vnode_at(sbi, &ova, stg_flags, out_vi);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_sbi_require_mutable_vaddr(struct silofs_sb_info *sbi,
                                     const struct silofs_vaddr *vaddr)
{
	struct silofs_ovaddr ova;

	silofs_assert(!vaddr_isnull(vaddr));

	return sbi_map_vaddr_to_ova(sbi, vaddr, SILOFS_STAGE_MUTABLE, &ova);
}

static int sbi_check_stage_at(struct silofs_sb_info *sbi,
                              const struct silofs_vaddr *vaddr,
                              enum silofs_stage_flags stg_flags)
{
	return vaddr_isnull(vaddr) ? -ENOENT : sbi_check_stage(sbi, stg_flags);
}

int silofs_stage_vnode(struct silofs_sb_info *sbi,
                       const struct silofs_vaddr *vaddr,
                       enum silofs_stage_flags stg_flags,
                       struct silofs_vnode_info **out_vi)
{
	int err;

	err = sbi_check_stage_at(sbi, vaddr, stg_flags);
	if (err) {
		return err;
	}
	err = sbi_lookup_cached_vi(sbi, vaddr, out_vi);
	if (!err || cacheonly_mode(stg_flags)) {
		return 0;  /* cache hit or cache-only mode */
	}
	err = sbi_resolve_stage_vnode(sbi, vaddr, stg_flags, out_vi);
	if (err) {
		return err;
	}
	return 0;
}

static int require_supported_itype(mode_t mode)
{
	const mode_t sup = S_IFDIR | S_IFREG | S_IFLNK |
	                   S_IFSOCK | S_IFIFO | S_IFCHR | S_IFBLK;

	return (((mode & S_IFMT) | sup) == sup) ? 0 : -EOPNOTSUPP;
}

int silofs_spawn_vnode(struct silofs_sb_info *sbi, enum silofs_stype stype,
                       struct silofs_vnode_info **out_vi)
{
	int err;

	err = silofs_claim_spawn_vnode(sbi, stype, out_vi);
	if (err) {
		return err;
	}
	vi_stamp_mark_visible(*out_vi);
	return 0;
}

int silofs_spawn_inode(struct silofs_sb_info *sbi,
                       const struct silofs_oper *op, ino_t parent_ino,
                       mode_t parent_mode, mode_t mode, dev_t rdev,
                       struct silofs_inode_info **out_ii)
{
	int err;

	err = require_supported_itype(mode);
	if (err) {
		return err;
	}
	err = silofs_claim_spawn_inode(sbi, out_ii);
	if (err) {
		return err;
	}
	ii_setup_inode_by(*out_ii, op, parent_ino, parent_mode, mode, rdev);
	return 0;
}

static int sbi_discard_inode_at(struct silofs_sb_info *sbi,
                                const struct silofs_iaddr *iaddr)
{
	int err;

	err = silofs_discard_ino(sbi, iaddr->ino);
	if (err) {
		return err;
	}
	err = silofs_reclaim_vspace(sbi, &iaddr->vaddr);
	if (err) {
		return err;
	}
	return 0;
}

int silofs_remove_inode(struct silofs_sb_info *sbi,
                        struct silofs_inode_info *ii)
{
	int err;
	struct silofs_iaddr iaddr;

	ii_iaddr(ii, &iaddr);
	err = sbi_discard_inode_at(sbi, &iaddr);
	if (err) {
		return err;
	}
	sbi_forget_cached_ii(sbi, ii);
	return 0;
}

static int reclaim_vspace_at(struct silofs_sb_info *sbi,
                             const struct silofs_vaddr *vaddr)
{
	int err;
	struct silofs_oaddr oaddr;

	err = silofs_resolve_oaddr(sbi, vaddr, &oaddr);
	if (err) {
		return err;
	}
	err = silofs_reclaim_vspace(sbi, vaddr);
	if (err) {
		return err;
	}
	return 0;
}

static int sbi_remove_vnode_of(struct silofs_sb_info *sbi,
                               struct silofs_vnode_info *vi)
{
	int err;

	vi_incref(vi);
	err = reclaim_vspace_at(sbi, vi_vaddr(vi));
	vi_decref(vi);
	return err;
}

int silofs_remove_vnode(struct silofs_sb_info *sbi,
                        struct silofs_vnode_info *vi)
{
	int err;

	err = sbi_remove_vnode_of(sbi, vi);
	if (err) {
		return err;
	}
	sbi_forget_cached_vi(sbi, vi);
	return 0;
}

int silofs_remove_vnode_at(struct silofs_sb_info *sbi,
                           const struct silofs_vaddr *vaddr)
{
	int err;
	struct silofs_vnode_info *vi = NULL;

	err = sbi_lookup_cached_vi(sbi, vaddr, &vi);
	if (!err) {
		err = silofs_remove_vnode(sbi, vi);
	} else {
		err = reclaim_vspace_at(sbi, vaddr);
	}
	return err;
}

int silofs_probe_unwritten(struct silofs_sb_info *sbi,
                           const struct silofs_vaddr *vaddr, bool *out_res)
{
	int err;
	struct silofs_spleaf_info *sli = NULL;
	const loff_t voff = vaddr_off(vaddr);

	err = sbi_stage_rdonly_spleaf(sbi, voff, &sli);
	if (err) {
		return err;
	}
	*out_res = silofs_sli_has_unwritten_at(sli, vaddr);
	return 0;
}

int silofs_clear_unwritten(struct silofs_sb_info *sbi,
                           const struct silofs_vaddr *vaddr)
{
	int err;
	struct silofs_spleaf_info *sli = NULL;
	const loff_t voff = vaddr_off(vaddr);

	err = sbi_stage_mutable_spleaf(sbi, voff, &sli);
	if (err) {
		return err;
	}
	silofs_sli_clear_unwritten_at(sli, vaddr);
	return 0;
}

int silofs_mark_unwritten(struct silofs_sb_info *sbi,
                          const struct silofs_vaddr *vaddr)
{
	int err;
	struct silofs_spleaf_info *sli = NULL;
	const loff_t voff = vaddr_off(vaddr);

	err = sbi_stage_mutable_spleaf(sbi, voff, &sli);
	if (err) {
		return err;
	}
	silofs_sli_mark_unwritten_at(sli, vaddr);
	return 0;
}

int silofs_refcnt_islast_at(struct silofs_sb_info *sbi,
                            const struct silofs_vaddr *vaddr, bool *out_res)
{
	int err;
	struct silofs_spleaf_info *sli = NULL;
	const loff_t voff = vaddr_off(vaddr);

	err = sbi_stage_rdonly_spleaf(sbi, voff, &sli);
	if (err) {
		return err;
	}
	*out_res = silofs_sli_has_last_refcnt(sli, vaddr);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_resolve_oaddr(struct silofs_sb_info *sbi,
                         const struct silofs_vaddr *vaddr,
                         struct silofs_oaddr *out_oaddr)
{
	int err;
	struct silofs_spleaf_info *sli = NULL;
	const loff_t voff = vaddr_off(vaddr);

	err = sbi_stage_rdonly_spleaf(sbi, voff, &sli);
	if (err) {
		return err;
	}
	silofs_sli_resolve_oaddr(sli, vaddr, out_oaddr);
	return 0;
}

int silofs_resolve_oaddr_of(struct silofs_sb_info *sbi,
                            const struct silofs_vnode_info *vi,
                            struct silofs_oaddr *out_oaddr)
{
	int err = 0;
	const enum silofs_stype stype = vi_stype(vi);

	switch (stype) {
	case SILOFS_STYPE_ANONBK:
	case SILOFS_STYPE_DATA1K:
	case SILOFS_STYPE_DATA4K:
	case SILOFS_STYPE_ITNODE:
	case SILOFS_STYPE_INODE:
	case SILOFS_STYPE_XANODE:
	case SILOFS_STYPE_DTNODE:
	case SILOFS_STYPE_FTNODE:
	case SILOFS_STYPE_SYMVAL:
	case SILOFS_STYPE_DATABK:
		err = silofs_resolve_oaddr(sbi, vi_vaddr(vi), out_oaddr);
		break;
	case SILOFS_STYPE_SUPER:
	case SILOFS_STYPE_SPNODE:
	case SILOFS_STYPE_SPLEAF:
	case SILOFS_STYPE_NONE:
	case SILOFS_STYPE_MAX:
	default:
		err = -EINVAL;
		silofs_assert_eq(err, 0);
		break;
	}
	return err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_kivam_of(const struct silofs_vnode_info *vi,
                    struct silofs_kivam *out_kivam)
{
	const struct silofs_vaddr *vaddr = vi_vaddr(vi);
	const struct silofs_fs_apex *apex = vi_apex(vi);
	const struct silofs_super_block *sb = apex->fa_sbi->sb;

	sb_kivam_of(sb, vaddr, out_kivam);
	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static void sbi_update_owner(struct silofs_sb_info *sbi,
                             const struct silofs_fs_args *args)
{
	sbi->s_owner.uid = args->uid;
	sbi->s_owner.gid = args->gid;
	sbi->s_owner.pid = args->pid;
	sbi->s_owner.umask = args->umask;
}

static void sbi_update_mntflags(struct silofs_sb_info *sbi,
                                const struct silofs_fs_args *args)
{
	unsigned long ms_flag_with = 0;
	unsigned long ms_flag_dont = 0;

	if (args->lazytime) {
		ms_flag_with |= MS_LAZYTIME;
	} else {
		ms_flag_dont |= MS_LAZYTIME;
	}
	if (args->noexec) {
		ms_flag_with |= MS_NOEXEC;
	} else {
		ms_flag_dont |= MS_NOEXEC;
	}
	if (args->nosuid) {
		ms_flag_with |= MS_NOSUID;
	} else {
		ms_flag_dont |= MS_NOSUID;
	}
	if (args->nodev) {
		ms_flag_with |= MS_NODEV;
	} else {
		ms_flag_dont |= MS_NODEV;
	}
	if (args->rdonly) {
		ms_flag_with |= MS_RDONLY;
	} else {
		ms_flag_dont |= MS_RDONLY;
	}
	sbi->s_ms_flags |= ms_flag_with;
	sbi->s_ms_flags &= ~ms_flag_dont;
}

static void sbi_update_ctlflags(struct silofs_sb_info *sbi,
                                const struct silofs_fs_args *args)
{
	if (args->kcopy_mode) {
		sbi->s_ctl_flags |= SILOFS_F_KCOPY;
	}
	if (args->allowother) {
		sbi->s_ctl_flags |= SILOFS_F_ALLOWOTHER;
	}
}

void silofs_sbi_update_by_args(struct silofs_sb_info *sbi,
                               const struct silofs_fs_args *args)
{
	sbi_update_owner(sbi, args);
	sbi_update_mntflags(sbi, args);
	sbi_update_ctlflags(sbi, args);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static const struct silofs_mdigest *
sbi_mdigest(const struct silofs_sb_info *sbi)
{
	return &sbi->s_ui.u_ti.t_apex->fa_crypto->md;
}

static void sbi_zero_stamp_sb_view(struct silofs_sb_info *sbi)
{
	union silofs_view *view = sbi->s_ui.u_ti.t_view;

	silofs_zero_stamp_view(view, SILOFS_STYPE_SUPER);
}

static void sbi_assign_vspace_span(struct silofs_sb_info *sbi)
{
	struct silofs_vrange vrange;
	const size_t height = SILOFS_SUPER_HEIGHT;

	silofs_vrange_setup_by(&vrange, height, 0);
	sb_set_vspace_span(sbi->sb, height, &vrange);
}

void silofs_sbi_setup_sb(struct silofs_sb_info *sbi, size_t capacity)
{
	struct silofs_super_block *sb = sbi->sb;

	sbi_zero_stamp_sb_view(sbi);
	sb_init(sb);
	sb_setup_fresh(sb, silofs_time_now(), capacity);
	sb_setup_rand(sb, sbi_mdigest(sbi));
	sbi_assign_vspace_span(sbi);

	silofs_assert(!sbi_has_main_blob(sbi));
}

void silofs_sbi_update_birth_time(struct silofs_sb_info *sbi, time_t btime)
{
	sb_set_birth_time(sbi->sb, btime);
	sbi_dirtify(sbi);
}

static void ucred_copyto(const struct silofs_ucred *ucred,
                         struct silofs_ucred *other)
{
	memcpy(other, ucred, sizeof(*other));
}

static void sbi_update_by(struct silofs_sb_info *sbi,
                          const struct silofs_sb_info *sbi_other)
{
	ucred_copyto(&sbi_other->s_owner, &sbi->s_owner);
	silofs_itbi_update_by(&sbi->s_itbi, &sbi_other->s_itbi);
	sbi->s_ctl_flags = sbi_other->s_ctl_flags;
	sbi->s_ms_flags = sbi_other->s_ms_flags;
	sbi->s_mntime = sbi_other->s_mntime;
}

static void sbi_regenerate_post_dup(const struct silofs_sb_info *sbi)
{
	struct silofs_super_block *sb = sbi->sb;

	sb_regenerate_main_treeid(sb);
	sb_reset_main_blobid(sb);
}

void silofs_sbi_clone_from(struct silofs_sb_info *sbi,
                           const struct silofs_sb_info *sbi_other)
{
	silofs_assert(!sbi_has_main_blob(sbi));

	silofs_ui_clone_into(&sbi_other->s_ui, &sbi->s_ui);
	sbi_update_by(sbi, sbi_other);
	sbi_regenerate_post_dup(sbi);
	sbi_dirtify(sbi);

	silofs_assert(!sbi_has_main_blob(sbi));
}
