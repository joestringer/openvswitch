/*
 * Copyright (c) 2011 Google, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * CityHash, by Geoff Pike and Jyrki Alakuijala
 *
 * This file provides chash128() and related functions.
 *
 * It's probably possible to create even faster hash functions by
 * writing a program that systematically explores some of the space of
 * possible hash functions, by using SIMD instructions, or by
 * compromising on hash quality.
 */

#include <config.h>
#include "chash.h"

#include <string.h>
#include "byte-order.h"
#include "compiler.h"

#ifdef WORDS_BIGENDIAN
#define uint32_t_in_expected_order(x) (uint32_byteswap(x))
#define uint64_t_in_expected_order(x) (uint64_byteswap(x))
#else
#define uint32_in_expected_order(x) (x)
#define uint64_in_expected_order(x) (x)
#endif

static uint64_t
fetch64(const void *p)
{
    uint64_t result;

    memcpy(&result, p, sizeof (result));
    return uint64_in_expected_order(result);
}

static uint32_t
fetch32(const void *p)
{
    uint64_t result;

    memcpy(&result, p, sizeof (result));
    return uint32_in_expected_order(result);
}

static void
swap_uint64(uint64_t *a, uint64_t *b)
{
    uint64_t x = *a;
    *a = *b;
    *b = x;
}

/* Some primes between 2^63 and 2^64 for various uses. */
static const uint64_t k0 = 0xc3a5c85c97cb3127ULL;
static const uint64_t k1 = 0xb492b66fbe98f273ULL;
static const uint64_t k2 = 0x9ae16a3b2f90404fULL;

#undef PERMUTE3
#define PERMUTE3(TYPE, a, b, c) \
    do {                        \
        TYPE tmp = c;           \
        c = b;                  \
        b = a;                  \
        a = tmp;                \
    } while (0)

/* Bitwise right rotate.  Normally this will compile to a single
 * instruction, especially if the shift is a manifest constant. */
static uint64_t
rotate(uint64_t val, int shift)
{
    /* Avoid shifting by 64: doing so yields an undefined result. */
    return shift == 0 ? val : ((val >> shift) | (val << (64 - shift)));
}

static uint64_t
shift_mix(uint64_t val)
{
    return val ^ (val >> 47);
}

static uint64_t
hash_len16__(uint64_t u, uint64_t v, uint64_t mul)
{
    /* Murmur-inspired hashing. */
    uint64_t a = (u ^ v) * mul;

    a ^= (a >> 47);
    uint64_t b = (v ^ a) * mul;

    b ^= (b >> 47);
    b *= mul;
    return b;
}

static uint64_t
hash_len16(uint64_t u, uint64_t v)
{
    const uint64_t kMul = 0x9ddfea08eb382d69ULL;

    return hash_len16__(u, v, kMul);
}

static uint64_t
hash_len0to16(const void *s_, size_t len)
{
    const char *s = s_;

    if (len >= 8) {
        uint64_t mul = k2 + len * 2;
        uint64_t a = fetch64(s) + k2;
        uint64_t b = fetch64(s + len - 8);
        uint64_t c = rotate(b, 37) * mul + a;
        uint64_t d = (rotate(a, 25) + b) * mul;

        return hash_len16__(c, d, mul);
    }
    if (len >= 4) {
        uint64_t mul = k2 + len * 2;
        uint64_t a = fetch32(s);

        return hash_len16__(len + (a << 3), fetch32(s + len - 4), mul);
    }
    if (len > 0) {
        uint8_t a = s[0];
        uint8_t b = s[len >> 1];
        uint8_t c = s[len - 1];
        uint32_t y = a + (b << 8);
        uint32_t z = len + (c << 2);

        return shift_mix(y * k2 ^ z * k0) * k2;
    }
    return k2;
}

/* Return a 16-byte hash for 48 bytes.  Quick and dirty.
 * Callers do best to use "random-looking" values for a and b. */
static uint128_t
weak_hash_len32_seeds__(uint64_t w, uint64_t x, uint64_t y, uint64_t z,
                         uint64_t a, uint64_t b)
{
    uint128_t result;
    uint64_t c;

    a += w;
    b = rotate(b + a + z, 21);
    c = a;

    a += x;
    a += y;
    b += rotate(a, 44);

    result.lo = a + z;
    result.hi = b + c;
    return result;
}

/* Return a 16-byte hash for s[0] ... s[31], a, and b.  Quick and dirty. */
static uint128_t
weak_hash_len32_seeds(const void *s_, uint64_t a, uint64_t b)
{
    const char *s = s_;

    return weak_hash_len32_seeds__(fetch64(s),
                                    fetch64(s + 8),
                                    fetch64(s + 16), fetch64(s + 24), a, b);
}

#if !(defined(__SSE4_2__) && defined(__x86_64))

/* A subroutine for chash128().  Returns a decent 128-bit hash for strings
 * of any length representable in signed long.  Based on City and Murmur. */
static uint128_t
city_murmur(const void *s_, size_t len, uint128_t seed)
{
    const char *s = s_;
    uint128_t result;
    uint64_t a = seed.lo;
    uint64_t b = seed.hi;
    uint64_t c = 0;
    uint64_t d = 0;
    signed long l = len - 16;

    if (l <= 0) {               /* len <= 16 */
        a = shift_mix(a * k1) * k1;
        c = b * k1 + hash_len0to16(s, len);
        d = shift_mix(a + (len >= 8 ? fetch64(s) : c));
    } else {                    /* len > 16 */
        c = hash_len16(fetch64(s + len - 8) + k1, a);
        d = hash_len16(b + len, c + fetch64(s + len - 16));
        a += d;
        do {
            a ^= shift_mix(fetch64(s) * k1) * k1;
            a *= k1;
            b ^= a;
            c ^= shift_mix(fetch64(s + 8) * k1) * k1;
            c *= k1;
            d ^= c;
            s += 16;
            l -= 16;
        } while (l > 0);
    }
    a = hash_len16(a, c);
    b = hash_len16(d, b);

    result.lo = a ^ b;
    result.hi = hash_len16(b, a);
    return result;
}

uint128_t
chash128_seed(const void *s_, size_t len, uint128_t seed)
{
    const char *s = s_;
    uint128_t v, w, result;
    uint64_t x, y, z;
    size_t tail_done;

    if (len < 128) {
        return city_murmur(s, len, seed);
    }
    /* We expect len >= 128 to be the common case.  Keep 56 bytes of state:
     * v, w, x, y, and z. */
    x = seed.lo;
    y = seed.hi;
    z = len * k1;

    v.lo = rotate(y ^ k1, 49) * k1 + fetch64(s);
    v.hi = rotate(v.lo, 42) * k1 + fetch64(s + 8);
    w.lo = rotate(y + z, 35) * k1 + x;
    w.hi = rotate(x + fetch64(s + 88), 53) * k1;

    /* This is the same inner loop as chash64(), manually unrolled. */
    do {
        x = rotate(x + y + v.lo + fetch64(s + 8), 37) * k1;
        y = rotate(y + v.hi + fetch64(s + 48), 42) * k1;
        x ^= w.hi;
        y += v.lo + fetch64(s + 40);
        z = rotate(z + w.lo, 33) * k1;
        v = weak_hash_len32_seeds(s, v.hi * k1, x + w.lo);
        w = weak_hash_len32_seeds(s + 32, z + w.hi, y + fetch64(s + 16));
        swap_uint64(&z, &x);
        s += 64;
        x = rotate(x + y + v.lo + fetch64(s + 8), 37) * k1;
        y = rotate(y + v.hi + fetch64(s + 48), 42) * k1;
        x ^= w.hi;
        y += v.lo + fetch64(s + 40);
        z = rotate(z + w.lo, 33) * k1;
        v = weak_hash_len32_seeds(s, v.hi * k1, x + w.lo);
        w = weak_hash_len32_seeds(s + 32, z + w.hi, y + fetch64(s + 16));
        swap_uint64(&z, &x);
        s += 64;
        len -= 128;
    } while (OVS_LIKELY(len >= 128));
    x += rotate(v.lo + z, 49) * k0;
    y = y * k0 + rotate(w.hi, 37);
    z = z * k0 + rotate(w.lo, 27);
    w.lo *= 9;
    v.lo *= k0;

    /* If 0 < len < 128, hash up to 4 chunks of 32 bytes each from the end of
     * s. */
    tail_done = 0;
    while (tail_done < len) {
        tail_done += 32;
        y = rotate(x + y, 42) * k0 + v.hi;
        w.lo += fetch64(s + len - tail_done + 16);
        x = x * k0 + w.lo;
        z += w.hi + fetch64(s + len - tail_done);
        w.hi += v.lo;
        v = weak_hash_len32_seeds(s + len - tail_done, v.lo + z, v.hi);
        v.lo *= k0;
    }

    /* At this point our 56 bytes of state should contain more than
     * enough information for a strong 128-bit hash.  We use two
     * different 56-byte-to-8-byte hashes to get a 16-byte final result. */
    x = hash_len16(x, v.lo);
    y = hash_len16(y + z, w.lo);

    result.lo = hash_len16(x + v.hi, w.hi) + y;
    result.hi = hash_len16(x + w.hi, y + v.hi);
    return result;
}

uint128_t
chash128(const void *s_, size_t len)
{
    const char *s = s_;
    uint128_t seed;

    if (len < 16) {
        seed.lo = k0;
        seed.hi = k1;
    } else {
        seed.lo = fetch64(s);
        seed.hi = fetch64(s + 8) + k0;
    }
    return (len >= 16 ? chash128_seed(s + 16, len - 16, seed)
                      : chash128_seed(s, len, seed));
}

#else /* __SSE4_2__ && __x86_64 */
#include <nmmintrin.h>

/* Requires len >= 240. */
static void
chash256_long(const void *s_, size_t len, uint32_t seed, uint64_t * result)
{
    const char *s = s_;
    uint64_t a = fetch64(s + 56) + k0;
    uint64_t b = fetch64(s + 96) + k0;
    uint64_t c = result[0] = hash_len16(b, len);
    uint64_t d = result[1] = fetch64(s + 120) * k0 + len;
    uint64_t e = fetch64(s + 184) + seed;
    uint64_t f = 0;
    uint64_t g = 0;
    uint64_t h = c + d;
    uint64_t x = seed;
    uint64_t y = 0;
    uint64_t z = 0;

    /* 240 bytes of input per iter. */
    size_t iters = len / 240;

    len -= iters * 240;
    do {
#undef CHUNK
#define CHUNK(r)                                \
    PERMUTE3(uint64_t x, z, y);                 \
    b += fetch64(s);                            \
    c += fetch64(s + 8);                        \
    d += fetch64(s + 16);                       \
    e += fetch64(s + 24);                       \
    f += fetch64(s + 32);                       \
    a += b;                                     \
    h += f;                                     \
    b += c;                                     \
    f += d;                                     \
    g += e;                                     \
    e += z;                                     \
    g += x;                                     \
    z = _mm_crc32_u64(z, b + g);                \
    y = _mm_crc32_u64(y, e + h);                \
    x = _mm_crc32_u64(x, f + a);                \
    e = rotate(e, r);                           \
    c += e;                                     \
    s += 40

        CHUNK(0);
        PERMUTE3(uint64_t, a, h, c);
        CHUNK(33);
        PERMUTE3(uint64_t, a, h, f);
        CHUNK(0);
        PERMUTE3(uint64_t, b, h, f);
        CHUNK(42);
        PERMUTE3(uint64_t, b, h, d);
        CHUNK(0);
        PERMUTE3(uint64_t, b, h, e);
        CHUNK(33);
        PERMUTE3(uint64_t, a, h, e);
    } while (--iters > 0);

    while (len >= 40) {
        CHUNK(29);
        e ^= rotate(a, 20);
        h += rotate(b, 30);
        g ^= rotate(c, 40);
        f += rotate(d, 34);
        PERMUTE3(uint64_t, c, h, g);
        len -= 40;
    }
    if (len > 0) {
        s = s + len - 40;
        CHUNK(33);
        e ^= rotate(a, 43);
        h += rotate(b, 42);
        g ^= rotate(c, 41);
        f += rotate(d, 40);
    }
    result[0] ^= h;
    result[1] ^= g;
    g += h;
    a = hash_len16(a, g + z);
    x += y << 32;
    b += x;
    c = hash_len16(c, z) + h;
    d = hash_len16(d, e + result[0]);
    g += e;
    h += hash_len16(x, f);
    e = hash_len16(a, d) + g;
    z = hash_len16(b, c) + a;
    y = hash_len16(g, h) + c;
    result[0] = e + z + y + x;
    a = shift_mix((a + y) * k0) * k0 + b;
    result[1] += a + result[0];
    a = shift_mix(a * k0) * k0 + c;
    result[2] = a + result[1];
    a = shift_mix((a + e) * k0) * k0;
    result[3] = a + result[2];
}

/* Requires len < 240. */
static void
chash256_short(const void *s, size_t len, uint64_t * result)
{
    char buf[240];

    memcpy(buf, s, len);
    memset(buf + len, 0, 240 - len);
    chash256_long(buf, 240, ~(len), result);
}

static void
chash256(const void *s, size_t len, uint64_t * result)
{
    if (OVS_LIKELY(len >= 240)) {
        chash256_long(s, len, 0, result);
    } else {
        chash256_short(s, len, result);
    }
}

uint128_t
chash128_seed(const void *s, size_t len, uint128_t seed)
{
    if (len <= 900) {
        return chash128_seed(s, len, seed);
    } else {
        uint128_t hash;
        uint64_t u, v;
        uint64_t result[4];

        chash256(s, len, result);
        u = seed.hi + result[0];
        v = seed.lo + result[1];

        hash.lo = hash_len16(u, v + result[2]);
        hash.hi = hash_len16(rotate(v, 32), u * k0 + result[3]);
        return hash;
    }
}

uint128_t
chash128(const void *s, size_t len)
{
    if (len <= 900) {
        return chash128(s, len);
    } else {
        uint64_t result[4];

        chash256(s, len, result);
        return {result[2], result[3]};
    }
}

#endif
