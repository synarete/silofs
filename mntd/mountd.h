/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2023 Shachar Sharon
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
#ifndef SILOFS_MOUNTD_H_
#define SILOFS_MOUNTD_H_

#include <silofs/configs.h>
#include <silofs/fs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <error.h>
#include <locale.h>
#include <getopt.h>
#include <signal.h>
#include <limits.h>


/* default logging mask */
#define MOUNTD_LOG_MASK \
	(SILOFS_LOG_INFO | SILOFS_LOG_WARN | \
	 SILOFS_LOG_ERROR | SILOFS_LOG_CRIT | SILOFS_LOG_STDOUT)

/* global context */
struct mountd_args {
	int     argc;
	char  **argv;
	char   *mntpoint;
	char   *mntpoint_real;
	char   *confpath;
	bool    long_listing;
	bool    allow_coredump;
	bool    dumpable;
};

struct mountd_ctx {
	struct mountd_args      args;
	struct silofs_ms_env   *mse;
	struct silofs_mntrules *mntrules;
	char   *progname;
	int     log_mask;
	int     sig_halt;
	int     sig_fatal;
};

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct silofs_mntrules *mountd_parse_mntrules(const char *pathname);

void mountd_free_mntrules(struct silofs_mntrules *mnt_conf);

#endif /* SILOFS_MOUNTD_H_ */
