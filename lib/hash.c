/*
 * Copyright (c) 2008, 2009, 2010, 2012, 2013, 2014 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <config.h>
#include "hash.h"
#include <string.h>
#include "unaligned.h"

/* Returns the hash of 'a', 'b', and 'c'. */
uint32_t
hash_3words(uint32_t a, uint32_t b, uint32_t c)
{
    return hash_finish(hash_add(hash_add(hash_add(a, 0), b), c), 12);
}

/* Returns the hash of the 'n' bytes at 'p', starting from 'basis'. */
uint32_t
hash_bytes(const void *p_, size_t n, uint32_t basis)
{
    const uint32_t *p = p_;
    size_t orig_n = n;
    uint32_t hash;

    hash = basis;
    while (n >= 4) {
        hash = hash_add(hash, get_unaligned_u32(p));
        n -= 4;
        p += 1;
    }

    if (n) {
        uint32_t tmp = 0;

        memcpy(&tmp, p, n);
        hash = hash_add(hash, tmp);
    }

    return hash_finish(hash, orig_n);
}

static void mhash128_add(ovs_u128 *hashp, const uint32_t *data)
{
    const uint32_t c1 = 0x239b961b;
    const uint32_t c2 = 0xab0e9789;
    const uint32_t c3 = 0x38b34ae5;
    const uint32_t c4 = 0xa1e38b93;
    uint32_t k1 = data[0];
    uint32_t k2 = data[1];
    uint32_t k3 = data[2];
    uint32_t k4 = data[3];

    ovs_u128 hash = *hashp;

    k1 *= c1;
    k1  = hash_rot(k1,15);
    k1 *= c2;
    hash.h[0] ^= k1;

    hash.h[0] = hash_rot(hash.h[0],19);
    hash.h[0] += hash.h[1];
    hash.h[0] = hash.h[0]*5+0x561ccd1b;

    k2 *= c2;
    k2  = hash_rot(k2,16);
    k2 *= c3;
    hash.h[1] ^= k2;

    hash.h[1] = hash_rot(hash.h[1],17);
    hash.h[1] += hash.h[2];
    hash.h[1] = hash.h[1]*5+0x0bcaa747;

    k3 *= c3;
    k3  = hash_rot(k3,17);
    k3 *= c4;
    hash.h[2] ^= k3;

    hash.h[2] = hash_rot(hash.h[2],15);
    hash.h[2] += hash.h[3];
    hash.h[2] = hash.h[2]*5+0x96cd1c35;

    k4 *= c4;
    k4  = hash_rot(k4,18);
    k4 *= c1;
    hash.h[3] ^= k4;

    hash.h[3] = hash_rot(hash.h[3],13);
    hash.h[3] += hash.h[0];
    hash.h[3] = hash.h[3]*5+0x32ac3b17;

    *hashp = hash;
}

static void mhash128_add_tail(ovs_u128 *hashp, const uint8_t *data, size_t len)
{
    const uint32_t c1 = 0x239b961b;
    const uint32_t c2 = 0xab0e9789;
    const uint32_t c3 = 0x38b34ae5;
    const uint32_t c4 = 0xa1e38b93;
    uint32_t k1 = 0;
    uint32_t k2 = 0;
    uint32_t k3 = 0;
    uint32_t k4 = 0;
    ovs_u128 hash = *hashp;

    switch(len & 15) {
    case 15:
        k4 ^= data[14] << 16;
    case 14:
        k4 ^= data[13] << 8;
    case 13:
        k4 ^= data[12] << 0;
        k4 *= c4;
        k4  = hash_rot(k4,18);
        k4 *= c1; hash.h[3] ^= k4;

    case 12:
        k3 ^= data[11] << 24;
    case 11:
        k3 ^= data[10] << 16;
    case 10:
        k3 ^= data[ 9] << 8;
    case  9:
        k3 ^= data[ 8] << 0;
        k3 *= c3;
        k3  = hash_rot(k3,17);
        k3 *= c4;
        hash.h[2] ^= k3;

    case  8:
        k2 ^= data[ 7] << 24;
    case  7:
        k2 ^= data[ 6] << 16;
    case  6:
        k2 ^= data[ 5] << 8;
    case  5:
        k2 ^= data[ 4] << 0;
        k2 *= c2;
        k2  = hash_rot(k2,16);
        k2 *= c3;
        hash.h[1] ^= k2;

    case  4:
        k1 ^= data[ 3] << 24;
    case  3:
        k1 ^= data[ 2] << 16;
    case  2:
        k1 ^= data[ 1] << 8;
    case  1:
        k1 ^= data[ 0] << 0;
        k1 *= c1;
        k1  = hash_rot(k1,15);
        k1 *= c2;
        hash.h[0] ^= k1;
    };

    *hashp = hash;
}

static void
fmix32(ovs_u128 *in, ovs_u128 *out)
{
    int i, h;

    for (i = 0; i < 4; i++) {
        h = in->h[i];

        h ^= h >> 16;
        h *= 0x85ebca6b;
        h ^= h >> 13;
        h *= 0xc2b2ae35;
        h ^= h >> 16;

        out->h[i] = h;
    }
}

static void
mhash128_finish(ovs_u128 *hashp, size_t len)
{
    ovs_u128 hash = *hashp;

    hash.h[0] ^= len;
    hash.h[1] ^= len;
    hash.h[2] ^= len;
    hash.h[3] ^= len;

    hash.h[0] += hash.h[1];
    hash.h[0] += hash.h[2];
    hash.h[0] += hash.h[3];
    hash.h[1] += hash.h[0];
    hash.h[2] += hash.h[0];
    hash.h[3] += hash.h[0];

    fmix32(&hash, &hash);

    hash.h[0] += hash.h[1];
    hash.h[0] += hash.h[2];
    hash.h[0] += hash.h[3];
    hash.h[1] += hash.h[0];
    hash.h[2] += hash.h[0];
    hash.h[3] += hash.h[0];

    *hashp = hash;
}

/* Calculates the 128-bit hash of the 'len' bytes at 'p_', starting from
 * 'basis' and places it into 'out'. */
void
hash_words128(const void *p_, size_t len, uint32_t basis, ovs_u128 *out)
{
    const uint32_t *p = p_;
    const int nblocks = len / (128 / 8); /* 1 block = 128 bits */
    const uint32_t *blocks = (const uint32_t *)(p + nblocks*4);
    const uint8_t *tail = (const uint8_t*)(p + nblocks*4);

    ovs_u128 hash = {
        .h[0] = basis,
        .h[1] = basis,
        .h[2] = basis,
        .h[3] = basis,
    };

    for(int i = -nblocks; i; i++) {
        mhash128_add(&hash, &blocks[i*4]);
    }

    mhash128_add_tail(&hash, tail, len);
    mhash128_finish(&hash, len);

    *out = hash;
}

uint32_t
hash_double(double x, uint32_t basis)
{
    uint32_t value[2];
    BUILD_ASSERT_DECL(sizeof x == sizeof value);

    memcpy(value, &x, sizeof value);
    return hash_3words(value[0], value[1], basis);
}

uint32_t
hash_words__(const uint32_t p[], size_t n_words, uint32_t basis)
{
    return hash_words_inline(p, n_words, basis);
}

uint32_t
hash_words64__(const uint64_t p[], size_t n_words, uint64_t basis)
{
    return hash_words64_inline(p, n_words, basis);
}
