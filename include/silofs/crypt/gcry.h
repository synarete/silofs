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
#ifndef SILOFS_GCRY_H_
#define SILOFS_GCRY_H_

#include <silofs/infra.h>
#include <gcrypt.h>

const char *silofs_gcrypt_version(void);

int silofs_init_gcrypt(void);

int silofs_gcrypt_status(gcry_error_t gcry_err, const char *fn);

#endif /* SILOFS_GCRY_H_ */
