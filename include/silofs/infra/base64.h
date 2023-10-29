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
#ifndef SILOFS_BASE64_H_
#define SILOFS_BASE64_H_

#include <stdlib.h>

size_t silofs_base64_encode_len(size_t inlen);

int silofs_base64_encode(const void *in, size_t inlen,
                         char *out, size_t outlen_max, size_t *out_len);

int silofs_base64_decode(const char *in, size_t inlen,
                         void *out, size_t outlen_max,
                         size_t *out_len, size_t *out_inrd);

#endif /* SILOFS_BASE64_H_ */
