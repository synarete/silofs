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
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <config.h>

#include <silofs/api.h>
#include "mountd.h"

static void *zalloc(size_t n)
{
	void *p = nullptr;
	int err;

	err = silofs_zmalloc(n, &p);
	if (err) {
		silofs_die(err, "malloc failure: nbytes=%lu", n);
	}
	return p;
}

static void zfree(void *p, size_t n)
{
	silofs_zfree(p, n);
}

static void zfreestr(char *s)
{
	if (s != nullptr) {
		zfree(s, strlen(s) + 1);
	}
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static char *read_mntconf_file(const char *path)
{
	struct stat st = { .st_size = -1 };
	size_t size    = 0;
	char *conf     = nullptr;
	int fd         = -1;
	int err;

	err = silofs_sys_stat(path, &st);
	if (err) {
		silofs_die(err, "stat failure: %s", path);
	}
	if (!S_ISREG(st.st_mode)) {
		silofs_die(0, "not a regular file: %s", path);
	}
	if (st.st_size > SILOFS_MEGA) {
		silofs_die(-EFBIG, "illegal mntconf file: %s", path);
	}
	err = silofs_sys_open(path, O_RDONLY, 0, &fd);
	if (err) {
		silofs_die(err, "can not open mntconf file %s", path);
	}
	size = (size_t)st.st_size;
	conf = zalloc(size + 1);
	err  = silofs_sys_readn(fd, conf, size);
	if (err) {
		silofs_die(err, "failed to read mntconf file %s", path);
	}
	silofs_sys_close(fd);

	return conf;
}

static struct silofs_mntrules *new_mntrules(void)
{
	struct silofs_mntrules *mrules;

	mrules         = zalloc(sizeof(*mrules));
	mrules->nrules = 0;

	return mrules;
}

struct silofs_mntrules *mountd_parse_mntrules(const char *path)
{
	struct silofs_alloc *alloc       = silofs_default_alloc;
	struct silofs_mntrules *mntrules = new_mntrules();
	char *conf                       = nullptr;
	int err;

	conf = read_mntconf_file(path);
	err  = silofs_parse_mntrules(mntrules, alloc, conf);
	zfreestr(conf);
	if (err) {
		silofs_die(err, "not a valid mount rules file: %s", path);
	}
	return mntrules;
}

void mountd_free_mntrules(struct silofs_mntrules *mntrules)
{
	struct silofs_alloc *alloc = silofs_default_alloc;

	if (mntrules != nullptr) {
		silofs_release_mntrules(mntrules, alloc);
		zfree(mntrules, sizeof(*mntrules));
	}
}
