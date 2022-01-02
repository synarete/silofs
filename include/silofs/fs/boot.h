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

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_bsec4k_init(struct silofs_bootsec4k *bor);

void silofs_bsec4k_fini(struct silofs_bootsec4k *bor);

void silofs_bsec4k_stamp(struct silofs_bootsec4k *bor,
                         const struct silofs_mdigest *md);

int silofs_bsec4k_verify(const struct silofs_bootsec4k *mbr,
                         const struct silofs_mdigest *md);

void silofs_bsec4k_parse(const struct silofs_bootsec4k *bor,
                         struct silofs_bootsec *bsec);

void silofs_bsec4k_set(struct silofs_bootsec4k *bor,
                       const struct silofs_bootsec *bsec);

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_bootsec_init(struct silofs_bootsec *bsec);

void silofs_bootsec_fini(struct silofs_bootsec *bsec);

void silofs_bootsec_name(const struct silofs_bootsec *bsec,
                         struct silofs_namestr *out_name);

void silofs_bootsec_set_name(struct silofs_bootsec *bsec,
                             const struct silofs_namestr *name);

bool silofs_bootsec_has_name(const struct silofs_bootsec *bsec,
                             const struct silofs_namestr *name);

void silofs_bootsec_set_uaddr(struct silofs_bootsec *bsec,
                              const struct silofs_uaddr *sb_uaddr);

void silofs_bootsec_set_packid(struct silofs_bootsec *bsec,
                               const struct silofs_packid *sb_packid);

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
