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
#ifndef SILOFS_BOOT_H_
#define SILOFS_BOOT_H_

struct silofs_mbootrec_info {
	struct silofs_list_head   mbr_lh;
	struct silofs_uuid        mbr_uuid;
	struct silofs_uaddr       mbr_sb_uaddr;
	struct silofs_namebuf     mbr_name;
	struct silofs_cipher_args mbr_cip_args;
	loff_t mbr_index;
	time_t mbr_btime;
};

struct silofs_mboot_info {
	struct silofs_alloc_if *mbt_alif;
	struct silofs_mdigest  *mbt_md;
	struct silofs_listq     mbt_lsq;
	loff_t mbt_next_index;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_mbi_init(struct silofs_mboot_info *mbi,
                    struct silofs_alloc_if *alif, struct silofs_mdigest *md);

int silofs_mbi_init_by(struct silofs_mboot_info *mbi,
                       const struct silofs_fs_apex *apex);

void silofs_mbi_fini(struct silofs_mboot_info *mbi);

int silofs_mbi_decode(struct silofs_mboot_info *mbi,
                      const void *buf, size_t bsz);

int silofs_mbi_encode(const struct silofs_mboot_info *mbi,
                      void *buf, size_t bsz, size_t *out_esz);

int silofs_mbi_encsize(const struct silofs_mboot_info *mbi, size_t *out_esz);

int silofs_mbi_lookup(const struct silofs_mboot_info *mbi,
                      const struct silofs_namestr *name,
                      struct silofs_mbootrec_info **out_mbri);

int silofs_mbi_insert(struct silofs_mboot_info *mbi,
                      const struct silofs_namestr *name,
                      const struct silofs_uaddr *sb_uaddr);

int silofs_mbi_nextof(const struct silofs_mboot_info *mbi, loff_t idx,
                      struct silofs_mbootrec_info **out_mbri);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_default_cip_args(struct silofs_cipher_args *cip_args);

void silofs_calc_pass_hash(const struct silofs_passphrase *pp,
                           const struct silofs_mdigest *md,
                           struct silofs_hash512 *out_hash);

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

int silofs_boot_lib(void);

void silofs_boot_cons(void);

int silofs_boot_mem(size_t mem_want, size_t *out_mem_size);


#endif /* SILOFS_BOOT_H_ */
