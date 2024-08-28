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
#include <silofs/errors.h>
#include <silofs/crypt.h>
#include <gcrypt.h>


#define SILOFS_SECMEM_SIZE      (64L * SILOFS_KILO)

int silofs_init_gcrypt(void)
{
	gcry_error_t err;
	enum gcry_ctl_cmds cmd;
	const char *version;
	const char *expected_version = GCRYPT_VERSION;

	version = gcry_check_version(expected_version);
	if (!version) {
		silofs_log_warn("libgcrypt version != %s", expected_version);
		return -1;
	}
	cmd = GCRYCTL_SUSPEND_SECMEM_WARN;
	err = gcry_control(cmd);
	if (err) {
		goto out_control_err;
	}
	cmd = GCRYCTL_INIT_SECMEM;
	err = gcry_control(cmd, SILOFS_SECMEM_SIZE, 0);
	if (err) {
		goto out_control_err;
	}
	cmd = GCRYCTL_RESUME_SECMEM_WARN;
	err = gcry_control(cmd);
	if (err) {
		goto out_control_err;
	}
	cmd = GCRYCTL_INITIALIZATION_FINISHED;
	gcry_control(cmd, 0);
	if (err) {
		goto out_control_err;
	}
	return 0;

out_control_err:
	return silofs_gcrypt_err(err, "gcry_control");
}

const char *silofs_gcrypt_version(void)
{
	return GCRYPT_VERSION;
}

int silofs_gcrypt_err(gcry_error_t gcry_err, const char *fn)
{
	const int err = (int)gcry_err;

	if (fn != NULL) {
		silofs_log_error("%s: %s", fn, gcry_strerror(gcry_err));
	}

	return (err > 0) ? -err : err;
}
