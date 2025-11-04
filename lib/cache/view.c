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
#include "configs.h"
#include <stdlib.h>
#include <silofs/ondisk.h>
#include "addr.h"
#include "crypt.h"
#include "view.h"

static size_t view_len(enum silofs_mtype mtype)
{
	return silofs_mtype_size(mtype);
}

int silofs_encrypt_view(const struct silofs_cipher *cipher,
                        const struct silofs_ivkey *ivkey,
                        const struct silofs_view *view,
                        enum silofs_mtype mtype, void *ptr)
{
	return silofs_encrypt_buf(cipher, ivkey, view, ptr, view_len(mtype));
}

int silofs_decrypt_view(const struct silofs_cipher *cipher,
                        const struct silofs_ivkey *ivkey,
                        const struct silofs_view *view,
                        enum silofs_mtype mtype, void *ptr)
{
	return silofs_decrypt_buf(cipher, ivkey, view, ptr, view_len(mtype));
}

int silofs_decrypt_view_inplace(const struct silofs_cipher *cipher,
                                const struct silofs_ivkey *ivkey,
                                struct silofs_view *view,
                                enum silofs_mtype mtype)
{
	return silofs_decrypt_buf(cipher, ivkey, view, view, view_len(mtype));
}
