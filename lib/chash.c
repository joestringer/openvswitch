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
 * This file provides CityHash64() and related functions.
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

static uint64_t
UNALIGNED_LOAD64(const char *p)
{
    uint64_t result;

    memcpy(&result, p, sizeof (result));
    return result;
}

static uint32_t
UNALIGNED_LOAD32(const char *p)
{
    uint32_t result;

    memcpy(&result, p, sizeof (result));
    return result;
}

#ifdef WORDS_BIGENDIAN
#define uint32_t_in_expected_order(x) (uint32_byteswap(x))
#define uint64_t_in_expected_order(x) (uint64_byteswap(x))
#else
#define uint32_in_expected_order(x) (x)
#define uint64_in_expected_order(x) (x)
#endif

static uint64_t
Fetch64(const char *p)
{
    return uint64_in_expected_order(UNALIGNED_LOAD64(p));
}

static uint32_t
Fetch32(const char *p)
{
    return uint32_in_expected_order(UNALIGNED_LOAD32(p));
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
Rotate32(uint32_t val, int shift)
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
Mur(uint32_t a, uint32_t h)
{
    /* Helper from Murmur3 for combining two 32-bit values. */
    a *= c1;
    a = Rotate32(a, 17);
    a *= c2;
    h ^= a;
    h = Rotate32(h, 19);
    return h * 5 + 0xe6546b64;
}

static uint32_t
Hash32Len13to24(const char *s, size_t len)
{
    uint32_t a = Fetch32(s - 4 + (len >> 1));
    uint32_t b = Fetch32(s + 4);
    uint32_t c = Fetch32(s + len - 8);
    uint32_t d = Fetch32(s + (len >> 1));
    uint32_t e = Fetch32(s);
    uint32_t f = Fetch32(s + len - 4);
    uint32_t h = len;

    return fmix(Mur(f, Mur(e, Mur(d, Mur(c, Mur(b, Mur(a, h)))))));
}

static uint32_t
Hash32Len0to4(const char *s, size_t len)
{
    uint32_t b = 0;
    uint32_t c = 9;

    for (size_t i = 0; i < len; i++) {
        signed char v = s[i];

        b = b * c1 + v;
        c ^= b;
    }
    return fmix(Mur(b, Mur(len, c)));
}

static uint32_t
Hash32Len5to12(const char *s, size_t len)
{
    uint32_t a = len, b = len * 5, c = 9, d = b;

    a += Fetch32(s);
    b += Fetch32(s + len - 4);
    c += Fetch32(s + ((len >> 1) & 4));
    return fmix(Mur(c, Mur(b, Mur(a, d))));
}

uint32_t
CityHash32(const char *s, size_t len)
{
    if (len <= 24) {
        return len <= 12 ?
            (len <= 4 ? Hash32Len0to4(s, len) : Hash32Len5to12(s, len)) :
            Hash32Len13to24(s, len);
    }
    /* len > 24 */
    uint32_t h = len, g = c1 * len, f = g;
    uint32_t a0 = Rotate32(Fetch32(s + len - 4) * c1, 17) * c2;
    uint32_t a1 = Rotate32(Fetch32(s + len - 8) * c1, 17) * c2;
    uint32_t a2 = Rotate32(Fetch32(s + len - 16) * c1, 17) * c2;
    uint32_t a3 = Rotate32(Fetch32(s + len - 12) * c1, 17) * c2;
    uint32_t a4 = Rotate32(Fetch32(s + len - 20) * c1, 17) * c2;

    h ^= a0;
    h = Rotate32(h, 19);
    h = h * 5 + 0xe6546b64;
    h ^= a2;
    h = Rotate32(h, 19);
    h = h * 5 + 0xe6546b64;
    g ^= a1;
    g = Rotate32(g, 19);
    g = g * 5 + 0xe6546b64;
    g ^= a3;
    g = Rotate32(g, 19);
    g = g * 5 + 0xe6546b64;
    f += a4;
    f = Rotate32(f, 19);
    f = f * 5 + 0xe6546b64;
    size_t iters = (len - 1) / 20;

    do {
        uint32_t a0 = Rotate32(Fetch32(s) * c1, 17) * c2;
        uint32_t a1 = Fetch32(s + 4);
        uint32_t a2 = Rotate32(Fetch32(s + 8) * c1, 17) * c2;
        uint32_t a3 = Rotate32(Fetch32(s + 12) * c1, 17) * c2;
        uint32_t a4 = Fetch32(s + 16);

        h ^= a0;
        h = Rotate32(h, 18);
        h = h * 5 + 0xe6546b64;
        f += a1;
        f = Rotate32(f, 19);
        f = f * c1;
        g += a2;
        g = Rotate32(g, 18);
        g = g * 5 + 0xe6546b64;
        h ^= a3 + a1;
        h = Rotate32(h, 19);
        h = h * 5 + 0xe6546b64;
        g ^= a4;
        g = uint32_byteswap(g) * 5;
        h += a4 * 5;
        h = uint32_byteswap(h);
        f += a0;
        PERMUTE3(uint32_t, f, h, g);
        s += 20;
    } while (--iters != 0);
    g = Rotate32(g, 11) * c1;
    g = Rotate32(g, 17) * c1;
    f = Rotate32(f, 11) * c1;
    f = Rotate32(f, 17) * c1;
    h = Rotate32(h + g, 19);
    h = h * 5 + 0xe6546b64;
    h = Rotate32(h, 17) * c1;
    h = Rotate32(h + f, 19);
    h = h * 5 + 0xe6546b64;
    h = Rotate32(h, 17) * c1;
    return h;
}

/* Bitwise right rotate.  Normally this will compile to a single
 * instruction, especially if the shift is a manifest constant. */
static uint64_t
Rotate(uint64_t val, int shift)
{
    /* Avoid shifting by 64: doing so yields an undefined result. */
    return shift == 0 ? val : ((val >> shift) | (val << (64 - shift)));
}

static uint64_t
ShiftMix(uint64_t val)
{
    return val ^ (val >> 47);
}

static uint64_t
HashLen16(uint64_t u, uint64_t v)
{
    uint128_t result = { u, v };
    return Hash128to64(&result);
}

static uint64_t
HashLen16__(uint64_t u, uint64_t v, uint64_t mul)
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
HashLen0to16(const char *s, size_t len)
{
    if (len >= 8) {
        uint64_t mul = k2 + len * 2;
        uint64_t a = Fetch64(s) + k2;
        uint64_t b = Fetch64(s + len - 8);
        uint64_t c = Rotate(b, 37) * mul + a;
        uint64_t d = (Rotate(a, 25) + b) * mul;

        return HashLen16__(c, d, mul);
    }
    if (len >= 4) {
        uint64_t mul = k2 + len * 2;
        uint64_t a = Fetch32(s);

        return HashLen16__(len + (a << 3), Fetch32(s + len - 4), mul);
    }
    if (len > 0) {
        uint8_t a = s[0];
        uint8_t b = s[len >> 1];
        uint8_t c = s[len - 1];
        uint32_t y = a + (b << 8);
        uint32_t z = len + (c << 2);

        return ShiftMix(y * k2 ^ z * k0) * k2;
    }
    return k2;
}

/* This probably works well for 16-byte strings as well, but it may be overkill
 * in that case. */
static uint64_t
HashLen17to32(const char *s, size_t len)
{
    uint64_t mul = k2 + len * 2;
    uint64_t a = Fetch64(s) * k1;
    uint64_t b = Fetch64(s + 8);
    uint64_t c = Fetch64(s + len - 8) * mul;
    uint64_t d = Fetch64(s + len - 16) * k2;

    return HashLen16__(Rotate(a + b, 43) + Rotate(c, 30) + d,
                       a + Rotate(b + k2, 18) + c, mul);
}

/* Return a 16-byte hash for 48 bytes.  Quick and dirty.
 * Callers do best to use "random-looking" values for a and b. */
static uint128_t
WeakHashLen32WithSeeds__(uint64_t w, uint64_t x, uint64_t y, uint64_t z,
                         uint64_t a, uint64_t b)
{
    uint128_t result;
    uint64_t c;

    a += w;
    b = Rotate(b + a + z, 21);
    c = a;

    a += x;
    a += y;
    b += Rotate(a, 44);

    result.lo = a + z;
    result.hi = b + c;
    return result;
}

/* Return a 16-byte hash for s[0] ... s[31], a, and b.  Quick and dirty. */
static uint128_t
WeakHashLen32WithSeeds(const char *s, uint64_t a, uint64_t b)
{
    return WeakHashLen32WithSeeds__(Fetch64(s),
                                    Fetch64(s + 8),
                                    Fetch64(s + 16), Fetch64(s + 24), a, b);
}

/* Return an 8-byte hash for 33 to 64 bytes. */
static uint64_t
HashLen33to64(const char *s, size_t len)
{
    uint64_t mul = k2 + len * 2;
    uint64_t a = Fetch64(s) * k2;
    uint64_t b = Fetch64(s + 8);
    uint64_t c = Fetch64(s + len - 24);
    uint64_t d = Fetch64(s + len - 32);
    uint64_t e = Fetch64(s + 16) * k2;
    uint64_t f = Fetch64(s + 24) * 9;
    uint64_t g = Fetch64(s + len - 8);
    uint64_t h = Fetch64(s + len - 16) * mul;
    uint64_t u = Rotate(a + g, 43) + (Rotate(b, 30) + c) * 9;
    uint64_t v = ((a + g) ^ d) + f + 1;
    uint64_t w = uint64_byteswap((u + v) * mul) + h;
    uint64_t x = Rotate(e + f, 42) + c;
    uint64_t y = (uint64_byteswap((v + w) * mul) + g) * mul;
    uint64_t z = e + f + c;

    a = uint64_byteswap((x + z) * mul + y) + b;
    b = ShiftMix((z + a) * mul + d + h) * mul;
    return b + x;
}

uint64_t
CityHash64(const char *s, size_t len)
{
    if (len <= 32) {
        if (len <= 16) {
            return HashLen0to16(s, len);
        } else {
            return HashLen17to32(s, len);
        }
    } else if (len <= 64) {
        return HashLen33to64(s, len);
    }
    /* For strings over 64 bytes we hash the end first, and then as we
     * loop we keep 56 bytes of state: v, w, x, y, and z. */
    uint64_t x = Fetch64(s + len - 40);
    uint64_t y = Fetch64(s + len - 16) + Fetch64(s + len - 56);
    uint64_t z = HashLen16(Fetch64(s + len - 48) + len, Fetch64(s + len - 24));

    uint128_t v = WeakHashLen32WithSeeds(s + len - 64, len, z);
    uint128_t w = WeakHashLen32WithSeeds(s + len - 32, y + k1, x);
    x = x * k1 + Fetch64(s);

    /* Decrease len to the nearest multiple of 64, and operate on 64-byte
     * chunks. */
    len = (len - 1) & ~(63);
    do {
        x = Rotate(x + y + v.lo + Fetch64(s + 8), 37) * k1;
        y = Rotate(y + v.hi + Fetch64(s + 48), 42) * k1;
        x ^= w.hi;
        y += v.lo + Fetch64(s + 40);
        z = Rotate(z + w.lo, 33) * k1;
        v = WeakHashLen32WithSeeds(s, v.hi * k1, x + w.lo);
        w = WeakHashLen32WithSeeds(s + 32, z + w.hi, y + Fetch64(s + 16));
        swap_uint64(&z, &x);
        s += 64;
        len -= 64;
    } while (len != 0);
    return HashLen16(HashLen16(v.lo, w.lo) + ShiftMix(y) * k1 + z,
                     HashLen16(v.hi, w.hi) + x);
}

uint64_t
CityHash64WithSeed(const char *s, size_t len, uint64_t seed)
{
    return CityHash64WithSeeds(s, len, k2, seed);
}

uint64_t
CityHash64WithSeeds(const char *s, size_t len, uint64_t seed0, uint64_t seed1)
{
    return HashLen16(CityHash64(s, len) - seed0, seed1);
}

#if !(defined(__SSE4_2__) && defined(__x86_64))

/* A subroutine for CityHash128().  Returns a decent 128-bit hash for strings
 * of any length representable in signed long.  Based on City and Murmur. */
static uint128_t
CityMurmur(const char *s, size_t len, uint128_t seed)
{
    uint128_t result;
    uint64_t a = seed.lo;
    uint64_t b = seed.hi;
    uint64_t c = 0;
    uint64_t d = 0;
    signed long l = len - 16;

    if (l <= 0) {               /* len <= 16 */
        a = ShiftMix(a * k1) * k1;
        c = b * k1 + HashLen0to16(s, len);
        d = ShiftMix(a + (len >= 8 ? Fetch64(s) : c));
    } else {                    /* len > 16 */
        c = HashLen16(Fetch64(s + len - 8) + k1, a);
        d = HashLen16(b + len, c + Fetch64(s + len - 16));
        a += d;
        do {
            a ^= ShiftMix(Fetch64(s) * k1) * k1;
            a *= k1;
            b ^= a;
            c ^= ShiftMix(Fetch64(s + 8) * k1) * k1;
            c *= k1;
            d ^= c;
            s += 16;
            l -= 16;
        } while (l > 0);
    }
    a = HashLen16(a, c);
    b = HashLen16(d, b);

    result.lo = a ^ b;
    result.hi = HashLen16(b, a);
    return result;
}

uint128_t
CityHash128WithSeed(const char *s, size_t len, uint128_t seed)
{
    uint128_t v, w, result;
    uint64_t x, y, z;
    size_t tail_done;

    if (len < 128) {
        return CityMurmur(s, len, seed);
    }
    /* We expect len >= 128 to be the common case.  Keep 56 bytes of state:
     * v, w, x, y, and z. */
    x = seed.lo;
    y = seed.hi;
    z = len * k1;

    v.lo = Rotate(y ^ k1, 49) * k1 + Fetch64(s);
    v.hi = Rotate(v.lo, 42) * k1 + Fetch64(s + 8);
    w.lo = Rotate(y + z, 35) * k1 + x;
    w.hi = Rotate(x + Fetch64(s + 88), 53) * k1;

    /* This is the same inner loop as CityHash64(), manually unrolled. */
    do {
        x = Rotate(x + y + v.lo + Fetch64(s + 8), 37) * k1;
        y = Rotate(y + v.hi + Fetch64(s + 48), 42) * k1;
        x ^= w.hi;
        y += v.lo + Fetch64(s + 40);
        z = Rotate(z + w.lo, 33) * k1;
        v = WeakHashLen32WithSeeds(s, v.hi * k1, x + w.lo);
        w = WeakHashLen32WithSeeds(s + 32, z + w.hi, y + Fetch64(s + 16));
        swap_uint64(&z, &x);
        s += 64;
        x = Rotate(x + y + v.lo + Fetch64(s + 8), 37) * k1;
        y = Rotate(y + v.hi + Fetch64(s + 48), 42) * k1;
        x ^= w.hi;
        y += v.lo + Fetch64(s + 40);
        z = Rotate(z + w.lo, 33) * k1;
        v = WeakHashLen32WithSeeds(s, v.hi * k1, x + w.lo);
        w = WeakHashLen32WithSeeds(s + 32, z + w.hi, y + Fetch64(s + 16));
        swap_uint64(&z, &x);
        s += 64;
        len -= 128;
    } while (OVS_LIKELY(len >= 128));
    x += Rotate(v.lo + z, 49) * k0;
    y = y * k0 + Rotate(w.hi, 37);
    z = z * k0 + Rotate(w.lo, 27);
    w.lo *= 9;
    v.lo *= k0;
    /* If 0 < len < 128, hash up to 4 chunks of 32 bytes each from the end of
     * s. */
    tail_done = 0;
    while (tail_done < len) {
        tail_done += 32;
        y = Rotate(x + y, 42) * k0 + v.hi;
        w.lo += Fetch64(s + len - tail_done + 16);
        x = x * k0 + w.lo;
        z += w.hi + Fetch64(s + len - tail_done);
        w.hi += v.lo;
        v = WeakHashLen32WithSeeds(s + len - tail_done, v.lo + z, v.hi);
        v.lo *= k0;
    }

    /* At this point our 56 bytes of state should contain more than
     * enough information for a strong 128-bit hash.  We use two
     * different 56-byte-to-8-byte hashes to get a 16-byte final result. */
    x = HashLen16(x, v.lo);
    y = HashLen16(y + z, w.lo);

    result.lo = HashLen16(x + v.hi, w.hi) + y;
    result.hi = HashLen16(x + w.hi, y + v.hi);
    return result;
}

uint128_t
CityHash128(const char *s, size_t len)
{
    uint128_t seed;

    if (len < 16) {
        seed.lo = k0;
        seed.hi = k1;
    } else {
        seed.lo = Fetch64(s);
        seed.hi = Fetch64(s + 8) + k0;
    }
    return (len >= 16 ? CityHash128WithSeed(s + 16, len - 16, seed)
                      : CityHash128WithSeed(s, len, seed));
}

#else /* __SSE4_2__ && __x86_64 */
#include <nmmintrin.h>

/* Requires len >= 240. */
static void
CityHashCrc256Long(const char *s, size_t len, uint32_t seed, uint64_t * result)
{
    uint64_t a = Fetch64(s + 56) + k0;
    uint64_t b = Fetch64(s + 96) + k0;
    uint64_t c = result[0] = HashLen16(b, len);
    uint64_t d = result[1] = Fetch64(s + 120) * k0 + len;
    uint64_t e = Fetch64(s + 184) + seed;
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
    b += Fetch64(s);                            \
    c += Fetch64(s + 8);                        \
    d += Fetch64(s + 16);                       \
    e += Fetch64(s + 24);                       \
    f += Fetch64(s + 32);                       \
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
    e = Rotate(e, r);                           \
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
        e ^= Rotate(a, 20);
        h += Rotate(b, 30);
        g ^= Rotate(c, 40);
        f += Rotate(d, 34);
        PERMUTE3(uint64_t, c, h, g);
        len -= 40;
    }
    if (len > 0) {
        s = s + len - 40;
        CHUNK(33);
        e ^= Rotate(a, 43);
        h += Rotate(b, 42);
        g ^= Rotate(c, 41);
        f += Rotate(d, 40);
    }
    result[0] ^= h;
    result[1] ^= g;
    g += h;
    a = HashLen16(a, g + z);
    x += y << 32;
    b += x;
    c = HashLen16(c, z) + h;
    d = HashLen16(d, e + result[0]);
    g += e;
    h += HashLen16(x, f);
    e = HashLen16(a, d) + g;
    z = HashLen16(b, c) + a;
    y = HashLen16(g, h) + c;
    result[0] = e + z + y + x;
    a = ShiftMix((a + y) * k0) * k0 + b;
    result[1] += a + result[0];
    a = ShiftMix(a * k0) * k0 + c;
    result[2] = a + result[1];
    a = ShiftMix((a + e) * k0) * k0;
    result[3] = a + result[2];
}

/* Requires len < 240. */
static void
CityHashCrc256Short(const char *s, size_t len, uint64_t * result)
{
    char buf[240];

    memcpy(buf, s, len);
    memset(buf + len, 0, 240 - len);
    CityHashCrc256Long(buf, 240, ~(len), result);
}

void
CityHashCrc256(const char *s, size_t len, uint64_t * result)
{
    if (OVS_LIKELY(len >= 240)) {
        CityHashCrc256Long(s, len, 0, result);
    } else {
        CityHashCrc256Short(s, len, result);
    }
}

uint128_t
CityHash128WithSeed(const char *s, size_t len, uint128_t seed)
{
    if (len <= 900) {
        return CityHash128WithSeed(s, len, seed);
    } else {
        uint128_t hash;
        uint64_t u, v;
        uint64_t result[4];

        CityHashCrc256(s, len, result);
        u = seed.hi + result[0];
        v = seed.lo + result[1];

        hash.lo = HashLen16(u, v + result[2]);
        hash.hi = HashLen16(Rotate(v, 32), u * k0 + result[3]);
        return hash;
    }
}

uint128_t
CityHash128(const char *s, size_t len)
{
    if (len <= 900) {
        return CityHash128(s, len);
    } else {
        uint64_t result[4];

        CityHashCrc256(s, len, result);
        return {result[2], result[3]};
    }
}

#endif
