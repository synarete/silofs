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
#include <silofs/errors.h>
#include <silofs/crypto.h>

enum {
	SILOFS_SECMEM_SIZE = 64L * SILOFS_KILO,
};

int silofs_init_gcrypt(bool with_fips)
{
	const char *version          = nullptr;
	const char *expected_version = GCRYPT_VERSION;
	enum gcry_ctl_cmds cmd;
	gcry_error_t err;

	if (with_fips) {
		/* FIPS force-mode _must_ come first */
		cmd = GCRYCTL_FORCE_FIPS_MODE;
		err = gcry_control(cmd);
		if (err) {
			goto out_control_err;
		}
	}
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
	silofs_log_warn("gcry_control failure: cmd=%d err=%d", cmd, err);
	return silofs_gcrypt_status(err, "gcry_control");
}

const char *silofs_gcrypt_version(void)
{
	return GCRYPT_VERSION;
}

int silofs_gcrypt_status_(gcry_error_t gcry_err, const char *fn,
                          const char *file, int line)
{
	const int err = (int)gcry_err;

	if (gcry_err && (fn != nullptr)) {
		silofs_logf(SILOFS_LOG_ERROR, file, line, "%s: %s", fn,
		            gcry_strerror(gcry_err));
	}

	return (err > 0) ? -err : err;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_gcrypt_random(void *ptr, size_t len)
{
	gcry_randomize(ptr, len, GCRY_STRONG_RANDOM);
}
