/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * This file is part of silofs.
 *
 * Copyright (C) 2020-2022 Shachar Sharon
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
#include <silofs/macros.h>
#include <silofs/utility.h>
#include <silofs/panic.h>
#include <silofs/random.h>
#include <silofs/time.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

static void do_getentropy(void *buf, size_t len)
{
	int err;

	err = getentropy(buf, len);
	if (err) {
		silofs_panic("getentropy: err=%d", errno);
	}
}

void silofs_getentropy(void *buf, size_t len)
{
	size_t cnt;
	uint8_t *ptr = buf;
	const uint8_t *end = ptr + len;
	const size_t getentropy_max = 256;

	while (ptr < end) {
		cnt = silofs_min((size_t)(end - ptr), getentropy_max);
		do_getentropy(ptr, cnt);
		ptr += cnt;
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static void prandgen_refill(struct silofs_prandgen *prng)
{
	silofs_getentropy(prng->rands, sizeof(prng->rands));
}

void silofs_prandgen_init(struct silofs_prandgen *prng)
{
	prng->used_slots = 0;
	prng->take_cycle = 0;
	prandgen_refill(prng);
}

static size_t prandgen_avail_bytes(const struct silofs_prandgen *prng)
{
	const size_t nslots_max = SILOFS_ARRAY_SIZE(prng->rands);

	return (nslots_max - prng->used_slots) * sizeof(prng->rands[0]);
}

static const uint64_t *prandgen_tip(const struct silofs_prandgen *prng)
{
	return &prng->rands[prng->used_slots];
}

static size_t
prandgen_nslots_of(const struct silofs_prandgen *prng, size_t nbytes)
{
	const size_t slot_size = sizeof(prng->rands[0]);

	return (nbytes + slot_size - 1) / slot_size;
}

static void prandgen_rotate_some(struct silofs_prandgen *prng, size_t nslots)
{
	struct timespec ts;
	uint32_t rot;
	uint64_t val;
	uint64_t rnd;
	uint64_t *tip;

	silofs_ts_gettime(&ts, 1);
	tip = &prng->rands[prng->used_slots];
	rnd = (tip > prng->rands) ? tip[-1] : tip[nslots - 1];
	for (size_t i = 0; i < nslots; ++i) {
		val = *tip ^ (uint64_t)(ts.tv_nsec);
		rnd ^= val;
		rot = (uint32_t)(rnd + i) % 59;
		*tip++ = silofs_rotate64(val, rot);
	}
}

static size_t prandgen_take_some(struct silofs_prandgen *prng,
                                 void *buf, size_t len)
{
	const size_t nbytes = silofs_min(prandgen_avail_bytes(prng), len);
	const size_t nslots = prandgen_nslots_of(prng, nbytes);

	memcpy(buf, prandgen_tip(prng), nbytes);
	prandgen_rotate_some(prng, nslots);
	prng->used_slots += (uint32_t)nslots;
	prng->take_cycle++;
	return nbytes;
}

static uint64_t prandgen_take_uint64(struct silofs_prandgen *prng)
{
	uint64_t ret;

	ret = *prandgen_tip(prng);
	prandgen_rotate_some(prng, 1);
	prng->used_slots += 1;
	prng->take_cycle++;
	return ret;
}


static void prandgen_prepare(struct silofs_prandgen *prng)
{
	const size_t nslots_max = SILOFS_ARRAY_SIZE(prng->rands);

	if (prng->used_slots == nslots_max) {
		if (prng->take_cycle >= (64 * nslots_max)) {
			prandgen_refill(prng);
			prng->take_cycle = 0;
		}
		prng->used_slots = 0;
	}
}

void silofs_prandgen_take(struct silofs_prandgen *prng, void *buf, size_t bsz)
{
	size_t cnt;
	uint8_t *cur = buf;
	const uint8_t *end = cur + bsz;

	while (cur < end) {
		prandgen_prepare(prng);
		cnt = prandgen_take_some(prng, cur, (size_t)(end - cur));
		silofs_expect_gt(cnt, 0);
		cur += cnt;
	}
}

void silofs_prandgen_take_u64(struct silofs_prandgen *prng, uint64_t *out)
{
	prandgen_prepare(prng);
	*out = prandgen_take_uint64(prng);
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

void silofs_prandgen_ascii(struct silofs_prandgen *prng, char *str, size_t n)
{
	int print_ch;
	uint64_t rnd;
	const int base = 33;
	const int last = 126;

	for (size_t i = 0; i < n; ++i) {
		if ((i % 31) == 0) {
			silofs_prandgen_take_u64(prng, &rnd);
		} else {
			rnd = rnd >> 1;
		}
		print_ch = abs(((int)rnd % (last - base)) + base);
		str[i] = (char)print_ch;
	}
}
