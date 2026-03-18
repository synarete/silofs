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
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <silofs/ondisk.h>
#include <silofs/infra.h>
#include <silofs/crypto/gcry.h>
#include <silofs/crypto/prand.h>

static void do_gcry_random(void *buf, size_t len)
{
	silofs_gcrypt_random(buf, len);
}

static size_t do_getentropy(void *buf, size_t len)
{
	const size_t nr = silofs_min(len, 256);
	int ret;

	ret = getentropy(buf, nr);
	return (ret == 0) ? nr : 0;
}

static void get_sys_entropy(void *buf, size_t len)
{
	void *p = buf;
	size_t n;

	n = do_getentropy(p, len);
	p = silofs_nextof(p, n);
	while (n < len) {
		const size_t k = do_getentropy(p, len - n);

		if (k == 0) {
			break;
		}
		n += k;
		p = silofs_nextof(p, k);
	}
	if (n < len) {
		/* system entropy is exhausted, fall to libgcrypt */
		do_gcry_random(p, len - n);
	}
}

/*: : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : : :*/

static struct silofs_prndstate *
prandgen_get_state(struct silofs_prandgen *prng, size_t idx)
{
	const size_t slot = idx % ARRAY_SIZE(prng->state);

	return &prng->state[slot];
}

static const struct silofs_prndstate *
prandgen_pick_state(const struct silofs_prandgen *prng)
{
	const size_t slot = prng->icount % ARRAY_SIZE(prng->state);

	return &prng->state[slot];
}

static void prandgen_mkhash(const struct silofs_prandgen *prng,
                            struct silofs_hash256 *out_hash)
{
	const struct silofs_prndstate *ps = prandgen_pick_state(prng);

	silofs_sha3_256_of(&prng->md_hd, ps, sizeof(*ps), out_hash);
}

static void
prandgen_update_state_by(struct silofs_prandgen *prng, uint64_t count,
                         const struct silofs_hash256 *hash)
{
	struct {
		struct silofs_prndstate ps;
		struct silofs_hash256 h;
		uint64_t count;
		struct timespec ts;
	} s;
	struct silofs_hash256 ph;
	struct silofs_prndstate *ps = prandgen_get_state(prng, count);

	STATICASSERT_EQ(sizeof(ph), sizeof(*ps));

	silofs_clock_gettime_mono(&s.ts);
	memcpy(&s.ps, ps, sizeof(s.ps));
	memcpy(&s.h, hash, sizeof(s.h));
	s.count = count + prng->slot;

	silofs_sha3_256_of(&prng->md_hd, &s, sizeof(s), &ph);
	memcpy(ps, &ph, sizeof(*ps));
}

static void prandgen_init_state(struct silofs_prandgen *prng)
{
	get_sys_entropy(prng->state, sizeof(prng->state));
}

static void prandgen_refill_prandom(struct silofs_prandgen *prng)
{
	size_t psz = sizeof(prng->prandom);
	void *p    = prng->prandom;
	size_t n   = 0;

	while (n < psz) {
		struct silofs_hash256 hash;
		size_t k;

		prandgen_mkhash(prng, &hash);
		prandgen_update_state_by(prng, prng->icount++, &hash);

		k = silofs_min(sizeof(hash), psz - n);
		memcpy(p, &hash, k);
		p = silofs_nextof(p, k);
		n += k;
	}
}

static void prandgen_reset_prandom(struct silofs_prandgen *prng)
{
	memset(prng->prandom, 0, sizeof(prng->prandom));
}

static void prandgen_renew_prandom(struct silofs_prandgen *prng)
{
	prandgen_reset_prandom(prng);
	prandgen_refill_prandom(prng);
	prng->slot = 0;
	prng->cycle++;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

int silofs_prandgen_init(struct silofs_prandgen *prng)
{
	int err;

	silofs_memzero(prng, sizeof(*prng));
	prng->icount = 0;
	prng->xcount = 0;
	prng->cycle  = 0;
	prng->slot   = 0;

	prandgen_init_state(prng);
	err = silofs_mdigest_init(&prng->md_hd);
	if (err) {
		return err;
	}
	prandgen_renew_prandom(prng);
	return 0;
}

void silofs_prandgen_fini(struct silofs_prandgen *prng)
{
	silofs_mdigest_fini(&prng->md_hd);
	silofs_memzero(prng, sizeof(*prng));
}

static uint64_t prandgen_consume_slot(struct silofs_prandgen *prng)
{
	uint64_t pr;

	/* take full u64 */
	pr = prng->prandom[prng->slot];
	/* clear used slot */
	prng->prandom[prng->slot] = 0;
	/* move to next */
	prng->slot++;

	return pr;
}

static bool prandgen_has_more(const struct silofs_prandgen *prng)
{
	return (prng->slot < ARRAY_SIZE(prng->prandom));
}

static void prandgen_prepare(struct silofs_prandgen *prng)
{
	if (!prandgen_has_more(prng)) {
		prandgen_renew_prandom(prng);
	}
}

static void prandgen_consume(struct silofs_prandgen *prng, void *p, size_t n)
{
	uint8_t *q = p;
	size_t k   = 0;

	while (k < n) {
		uint64_t u;
		const size_t nb = silofs_min(n - k, sizeof(u));

		prandgen_prepare(prng);
		u = prandgen_consume_slot(prng);

		memcpy(&q[k], &u, nb);
		k += nb;
	}
}

static void prandgen_reseed(struct silofs_prandgen *prng)
{
	uint32_t r[ARRAY_SIZE(prng->state)];
	size_t sj = prng->icount + prng->slot;

	get_sys_entropy(r, sizeof(r));
	for (size_t i = 0; i < ARRAY_SIZE(r); ++i) {
		struct silofs_prndstate *ps = &prng->state[i];
		const size_t j              = sj++ % ARRAY_SIZE(ps->s);

		ps->s[j] ^= r[i];
	}
}

void silofs_prandgen_take(struct silofs_prandgen *prng, void *p, size_t n)
{
	const uint32_t cycle = prng->cycle;

	prandgen_consume(prng, p, n);
	if (cycle != prng->cycle) {
		prandgen_reseed(prng);
	}
}

void silofs_prandgen_feed(struct silofs_prandgen *prng, const void *p,
                          size_t n)
{
	struct silofs_hash256 hash;

	silofs_sha3_256_of(&prng->md_hd, p, n, &hash);
	prandgen_update_state_by(prng, prng->xcount++, &hash);
}
