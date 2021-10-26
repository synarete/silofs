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
#ifndef SILOFS_BOOT_H_
#define SILOFS_BOOT_H_

int silofs_boot_lib(void);

int silofs_boot_memsize(size_t mem_want, size_t *out_mem_size);

void silofs_guarantee_consistency(void);


/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_mbr_init(struct silofs_main_bootrec *mbr);

void silofs_mbr_fini(struct silofs_main_bootrec *mbr);

void silofs_mbr_copyto(const struct silofs_main_bootrec *mbr,
                       struct silofs_main_bootrec *other);

struct silofs_main_bootrec *silofs_mbr_new(struct silofs_alloc_if *alif);

void silofs_mbr_del(struct silofs_main_bootrec *mbr,
                    struct silofs_alloc_if *alif);

void silofs_mbr_sb_ref(const struct silofs_main_bootrec *mbr,
                       struct silofs_uaddr *out_uaddr);

void silofs_mbr_set_sb_ref(struct silofs_main_bootrec *mbr,
                           const struct silofs_uaddr *uaddr);

int silofs_mbr_cipher_args(const struct silofs_main_bootrec *mbr,
                           struct silofs_cipher_args *cip_args);

int silofs_mbr_check(const struct silofs_main_bootrec *mbr);


void silofs_calc_pass_hash(const struct silofs_passphrase *pp,
                           const struct silofs_mdigest *md,
                           struct silofs_hash512 *out_hash);

#endif /* SILOFS_BOOT_H_ */
