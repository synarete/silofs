/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2026 Shachar Sharon
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

#include <silofs/exec.h>

int silofs_sanitize_status_code(int status)
{
	int err;

	if (!status) {
		return 0;
	}
	err = abs(status);
	if (err >= SILOFS_ERRBASE2) {
		return -EUCLEAN;
	}
	if (err >= SILOFS_ERRBASE) {
		return -abs(err - SILOFS_ERRBASE);
	}
	return -err;
}

void silofs_relax_caches(const struct silofs_core_refs *corefs, int flags)
{
	silofs_pcache_relax(corefs->pcache, flags);
	silofs_lcache_relax(corefs->lcache, flags);
	if (flags & SILOFS_CTLF_IDLE) {
		silofs_dstor_relax(corefs->dstor);
	}
}

void silofs_drop_caches(const struct silofs_core_refs *corefs)
{
	silofs_pspools_drop(corefs->pspools);
	silofs_lspools_drop(corefs->lspools);
	silofs_pcache_drop(corefs->pcache);
	silofs_lcache_drop(corefs->lcache);
	silofs_dstor_drop(corefs->dstor);
}

int silofs_reinit_ciphers(const struct silofs_core_refs *corefs)
{
	const struct silofs_mbr_meta *mbr_meta = &corefs->fsroot->mbr_meta;
	const struct silofs_ciargs *ciargs     = &mbr_meta->nmeta.ciargs;
	int err;

	err = silofs_cipher_reinit(corefs->enc_ci_hd, ciargs);
	return_if_err(err);

	err = silofs_cipher_reinit(corefs->dec_ci_hd, ciargs);
	return_if_err(err);

	return 0;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static size_t page_size(void)
{
	return (size_t)silofs_sc_page_size();
}

static size_t aliged_size_of(size_t objsz)
{
	const size_t pgsz  = page_size();
	const size_t npgs  = silofs_div_round_up(objsz, pgsz);
	const size_t memsz = npgs * pgsz;

	silofs_assert_le(memsz, 65536);

	return memsz;
}

int silofs_new_core_obj(size_t objsz, void **out_obj)
{
	void *mem = nullptr;
	size_t msz;
	int err;

	msz = aliged_size_of(objsz);
	err = posix_memalign(&mem, page_size(), msz);
	if (err) {
		log_err("posix_memalign failed: msz=%zu err=%d", msz, err);
		return -abs(err);
	}
	err = silofs_sys_mlock(mem, msz);
	if (err) {
		free(mem);
		log_err("mlock failed: msz=%zu err=%d", msz, err);
		return err;
	}
	explicit_bzero(mem, msz);
	*out_obj = mem;
	return 0;
}

void silofs_del_core_obj(void *obj, size_t objsz)
{
	void *mem = obj;

	if (mem != nullptr) {
		const size_t msz = aliged_size_of(objsz);
		explicit_bzero(mem, msz);

		silofs_sys_munlock(mem, msz);
		free(mem);
	}
}
