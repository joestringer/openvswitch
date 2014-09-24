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
 * This file provides chash64() and related functions.
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

/* Magic numbers for 32-bit hashing.  Copied from Murmur3. */
static const uint32_t c1 = 0xcc9e2d51;
static const uint32_t c2 = 0x1b873593;

/* A 32-bit to 32-bit integer hash copied from Murmur3. */
static uint32_t
fmix(uint32_t h)
{
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;
    return h;
}

static uint32_t
rotate32(uint32_t val, int shift)
{
    /* Avoid shifting by 32: doing so yields an undefined result. */
    return shift == 0 ? val : ((val >> shift) | (val << (32 - shift)));
}

#undef PERMUTE3
#define PERMUTE3(TYPE, a, b, c) \
    do {                        \
        TYPE tmp = c;           \
        c = b;                  \
        b = a;                  \
        a = tmp;                \
    } while (0)

static uint32_t
mur(uint32_t a, uint32_t h)
{
    /* Helper from Murmur3 for combining two 32-bit values. */
    a *= c1;
    a = rotate32(a, 17);
    a *= c2;
    h ^= a;
    h = rotate32(h, 19);
    return h * 5 + 0xe6546b64;
}

static uint32_t
hash32_len13to24(const void *s_, size_t len)
{
    const char *s = s_;
    uint32_t a = fetch32(s - 4 + (len >> 1));
    uint32_t b = fetch32(s + 4);
    uint32_t c = fetch32(s + len - 8);
    uint32_t d = fetch32(s + (len >> 1));
    uint32_t e = fetch32(s);
    uint32_t f = fetch32(s + len - 4);
    uint32_t h = len;

    return fmix(mur(f, mur(e, mur(d, mur(c, mur(b, mur(a, h)))))));
}

static uint32_t
hash32_len0to4(const void *s_, size_t len)
{
    const char *s = s_;
    uint32_t b = 0;
    uint32_t c = 9;

    for (size_t i = 0; i < len; i++) {
        signed char v = s[i];

        b = b * c1 + v;
        c ^= b;
    }
    return fmix(mur(b, mur(len, c)));
}

static uint32_t
hash32_len5to12(const void *s_, size_t len)
{
    const char *s = s_;
    uint32_t a = len, b = len * 5, c = 9, d = b;

    a += fetch32(s);
    b += fetch32(s + len - 4);
    c += fetch32(s + ((len >> 1) & 4));
    return fmix(mur(c, mur(b, mur(a, d))));
}

uint32_t
chash32(const void *s_, size_t len)
{
    const char *s = s_;
    uint32_t h, g, f;
    uint32_t a0, a1, a2, a3, a4;
    size_t iters;

    if (len <= 24) {
        return len <= 12 ?
            (len <= 4 ? hash32_len0to4(s, len) : hash32_len5to12(s, len)) :
            hash32_len13to24(s, len);
    }
    /* len > 24 */
    h = len;
    g = c1 * len;
    f = g;
    a0 = rotate32(fetch32(s + len - 4) * c1, 17) * c2;
    a1 = rotate32(fetch32(s + len - 8) * c1, 17) * c2;
    a2 = rotate32(fetch32(s + len - 16) * c1, 17) * c2;
    a3 = rotate32(fetch32(s + len - 12) * c1, 17) * c2;
    a4 = rotate32(fetch32(s + len - 20) * c1, 17) * c2;

    h ^= a0;
    h = rotate32(h, 19);
    h = h * 5 + 0xe6546b64;
    h ^= a2;
    h = rotate32(h, 19);
    h = h * 5 + 0xe6546b64;
    g ^= a1;
    g = rotate32(g, 19);
    g = g * 5 + 0xe6546b64;
    g ^= a3;
    g = rotate32(g, 19);
    g = g * 5 + 0xe6546b64;
    f += a4;
    f = rotate32(f, 19);
    f = f * 5 + 0xe6546b64;
    iters = (len - 1) / 20;

    do {
        a0 = rotate32(fetch32(s) * c1, 17) * c2;
        a1 = fetch32(s + 4);
        a2 = rotate32(fetch32(s + 8) * c1, 17) * c2;
        a3 = rotate32(fetch32(s + 12) * c1, 17) * c2;
        a4 = fetch32(s + 16);

        h ^= a0;
        h = rotate32(h, 18);
        h = h * 5 + 0xe6546b64;
        f += a1;
        f = rotate32(f, 19);
        f = f * c1;
        g += a2;
        g = rotate32(g, 18);
        g = g * 5 + 0xe6546b64;
        h ^= a3 + a1;
        h = rotate32(h, 19);
        h = h * 5 + 0xe6546b64;
        g ^= a4;
        g = uint32_byteswap(g) * 5;
        h += a4 * 5;
        h = uint32_byteswap(h);
        f += a0;
        PERMUTE3(uint32_t, f, h, g);
        s += 20;
    } while (--iters != 0);

    g = rotate32(g, 11) * c1;
    g = rotate32(g, 17) * c1;
    f = rotate32(f, 11) * c1;
    f = rotate32(f, 17) * c1;
    h = rotate32(h + g, 19);
    h = h * 5 + 0xe6546b64;
    h = rotate32(h, 17) * c1;
    h = rotate32(h + f, 19);
    h = h * 5 + 0xe6546b64;
    h = rotate32(h, 17) * c1;

    return h;
}

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

/* This probably works well for 16-byte strings as well, but it may be overkill
 * in that case. */
static uint64_t
hash_len17to32(const void *s_, size_t len)
{
    const char *s = s_;
    uint64_t mul = k2 + len * 2;
    uint64_t a = fetch64(s) * k1;
    uint64_t b = fetch64(s + 8);
    uint64_t c = fetch64(s + len - 8) * mul;
    uint64_t d = fetch64(s + len - 16) * k2;

    return hash_len16__(rotate(a + b, 43) + rotate(c, 30) + d,
                       a + rotate(b + k2, 18) + c, mul);
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

/* Return an 8-byte hash for 33 to 64 bytes. */
static uint64_t
hash_len33to64(const void *s_, size_t len)
{
    const char *s = s_;
    uint64_t mul = k2 + len * 2;
    uint64_t a = fetch64(s) * k2;
    uint64_t b = fetch64(s + 8);
    uint64_t c = fetch64(s + len - 24);
    uint64_t d = fetch64(s + len - 32);
    uint64_t e = fetch64(s + 16) * k2;
    uint64_t f = fetch64(s + 24) * 9;
    uint64_t g = fetch64(s + len - 8);
    uint64_t h = fetch64(s + len - 16) * mul;
    uint64_t u = rotate(a + g, 43) + (rotate(b, 30) + c) * 9;
    uint64_t v = ((a + g) ^ d) + f + 1;
    uint64_t w = uint64_byteswap((u + v) * mul) + h;
    uint64_t x = rotate(e + f, 42) + c;
    uint64_t y = (uint64_byteswap((v + w) * mul) + g) * mul;
    uint64_t z = e + f + c;

    a = uint64_byteswap((x + z) * mul + y) + b;
    b = shift_mix((z + a) * mul + d + h) * mul;
    return b + x;
}

uint64_t
chash64(const void *s_, size_t len)
{
    const char *s = s_;
    uint128_t v, w;
    uint64_t x, y, z;

    if (len <= 32) {
        if (len <= 16) {
            return hash_len0to16(s, len);
        } else {
            return hash_len17to32(s, len);
        }
    } else if (len <= 64) {
        return hash_len33to64(s, len);
    }
    /* For strings over 64 bytes we hash the end first, and then as we
     * loop we keep 56 bytes of state: v, w, x, y, and z. */
    x = fetch64(s + len - 40);
    y = fetch64(s + len - 16) + fetch64(s + len - 56);
    z = hash_len16(fetch64(s + len - 48) + len, fetch64(s + len - 24));

    v = weak_hash_len32_seeds(s + len - 64, len, z);
    w = weak_hash_len32_seeds(s + len - 32, y + k1, x);
    x = x * k1 + fetch64(s);

    /* Decrease len to the nearest multiple of 64, and operate on 64-byte
     * chunks. */
    len = (len - 1) & ~(63);
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
        len -= 64;
    } while (len != 0);

    return hash_len16(hash_len16(v.lo, w.lo) + shift_mix(y) * k1 + z,
                     hash_len16(v.hi, w.hi) + x);
}

uint64_t
chash64_seed(const void *s, size_t len, uint64_t seed)
{
    return chash64_seeds(s, len, k2, seed);
}

uint64_t
chash64_seeds(const void *s, size_t len, uint64_t seed0, uint64_t seed1)
{
    return hash_len16(chash64(s, len) - seed0, seed1);
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

void
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
