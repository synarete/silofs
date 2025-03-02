/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2025 Shachar Sharon
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
#ifndef SILOFS_ALIAS_H_
#define SILOFS_ALIAS_H_

#ifndef SILOFS_USE_PRIVATE
#error "internal library header -- do not include!"
#endif

#include <silofs/defs.h>
#include <silofs/infra.h>

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

#define uni_incref(uni)        silofs_uni_incref(uni)
#define uni_decref(uni)        silofs_uni_decref(uni)
#define uni_dirtify(uni)       silofs_uni_dirtify(uni)
#define uni_ulink(uni)         silofs_uni_ulink(uni)
#define uni_uaddr(uni)         silofs_uni_uaddr(uni)
#define uni_laddr(uni)         silofs_uni_laddr(uni)
#define uni_ltype(uni)         silofs_uni_ltype(uni)
#define uni_riv(uni)           silofs_uni_riv(uni)

#define sbi_env(sbi)           silofs_sbi_env(sbi)
#define sbi_cache(sbi)         silofs_sbi_cache(sbi)
#define sbi_ulink(sbi)         silofs_sbi_ulink(sbi)
#define sbi_uaddr(sbi)         silofs_sbi_uaddr(sbi)
#define sbi_laddr(sbi)         silofs_sbi_laddr(sbi)
#define sbi_incref(sbi)        silofs_sbi_incref(sbi)
#define sbi_decref(sbi)        silofs_sbi_decref(sbi)
#define sbi_dirtify(sbi)       silofs_sbi_dirtify(sbi)

#define sni_ulink(sni)         silofs_sni_ulink(sni)
#define sni_uaddr(sni)         silofs_sni_uaddr(sni)
#define sni_laddr(sni)         silofs_sni_laddr(sni)
#define sni_incref(sni)        silofs_sni_incref(sni)
#define sni_decref(sni)        silofs_sni_decref(sni)
#define sni_vrange(sni, vrng)  silofs_sni_vspace_range(sni, vrng)
#define sni_slot_of(sni, o)    silofs_sni_slot_of(sni, o)
#define sni_base_voff(sni)     silofs_sni_base_voff(sni)

#define sli_ulink(sli)         silofs_sli_ulink(sli)
#define sli_uaddr(sli)         silofs_sli_uaddr(sli)
#define sli_laddr(sli)         silofs_sli_laddr(sli)
#define sli_incref(sli)        silofs_sli_incref(sli)
#define sli_decref(sli)        silofs_sli_decref(sli)
#define sli_vrange(sli, vrng)  silofs_sli_vspace_range(sli, vrng)
#define sli_base_voff(sli)     silofs_sli_base_voff(sli)

#define vni_ltype(vni)         silofs_vni_ltype(vni)
#define vni_vaddr(vni)         silofs_vni_vaddr(vni)
#define vni_env(vni)           silofs_vni_env(vni)
#define vni_sbi(vni)           silofs_vni_sbi(vni)
#define vni_refcnt(vni)        silofs_vni_refcnt(vni)
#define vni_incref(vni)        silofs_vni_incref(vni)
#define vni_decref(vni)        silofs_vni_decref(vni)
#define vni_dirtify(vni, ii)   silofs_vni_dirtify(vni, ii)
#define vni_need_recheck(vni)  silofs_vni_need_recheck(vni)
#define vni_set_rechecked(vni) silofs_vni_set_rechecked(vni)

#define ii_unconst(ii)         silofs_ii_unconst(ii)
#define ii_to_vni(ii)          silofs_ii_to_vni(ii)
#define ii_ino(ii)             silofs_ii_ino(ii)
#define ii_vaddr(ii)           silofs_ii_vaddr(ii)
#define ii_sbi(ii)             silofs_ii_sbi(ii)
#define ii_env(ii)             silofs_ii_env(ii)
#define ii_cache(ii)           silofs_ii_cache(ii)
#define ii_refcnt(ii)          silofs_ii_refcnt(ii)
#define ii_incref(ii)          silofs_ii_incref(ii)
#define ii_decref(ii)          silofs_ii_decref(ii)
#define ii_dirtify(ii)         silofs_ii_dirtify(ii)
#define ii_xino(ii)            silofs_ii_xino_of(ii)
#define ii_parent(ii)          silofs_ii_parent(ii)
#define ii_uid(ii)             silofs_ii_uid(ii)
#define ii_gid(ii)             silofs_ii_gid(ii)
#define ii_mode(ii)            silofs_ii_mode(ii)
#define ii_nlink(ii)           silofs_ii_nlink(ii)
#define ii_size(ii)            silofs_ii_size(ii)
#define ii_flags(ii)           silofs_ii_flags(ii)
#define ii_span(ii)            silofs_ii_span(ii)
#define ii_blocks(ii)          silofs_ii_blocks(ii)
#define ii_generation(ii)      silofs_ii_generation(ii)
#define ii_isrootd(ii)         silofs_ii_isrootd(ii)
#define ii_isdir(ii)           silofs_ii_isdir(ii)
#define ii_isreg(ii)           silofs_ii_isreg(ii)
#define ii_islnk(ii)           silofs_ii_islnk(ii)
#define ii_isfifo(ii)          silofs_ii_isfifo(ii)
#define ii_issock(ii)          silofs_ii_issock(ii)

#define uid_eq(uid1, uid2)     silofs_uid_eq(uid1, uid2)
#define uid_isroot(uid)        silofs_uid_isroot(uid)
#define gid_eq(gid1, gid2)     silofs_gid_eq(gid1, gid2)
#define ino_isnull(ino)        silofs_ino_isnull(ino)

#define task_sbi(t)            silofs_task_sbi(t)
#define task_lcache(t)         silofs_task_lcache(t)

#endif /* SILOFS_ALIAS_H_ */
