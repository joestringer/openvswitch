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

static void
swap64(uint64_t *a, uint64_t *b)
{
    uint64_t c;

    c = *a;
    *a = *b;
    *b = c;
}

static uint64_t UNALIGNED_LOAD64(const char *p) {
  return *ALIGNED_CAST(uint64_t *, p);
}

static uint32_t UNALIGNED_LOAD32(const char *p) {
  return *ALIGNED_CAST(uint32_t *, p);
}

#ifdef _MSC_VER

#include <stdlib.h>
#define bswap_32(x) _byteswap_ulong(x)
#define bswap_64(x) _byteswap_uint64_t(x)

#elif defined(__APPLE__)

// Mac OS X / Darwin features
#include <libkern/OSByteOrder.h>
#define bswap_32(x) OSSwapInt32(x)
#define bswap_64(x) OSSwapInt64(x)

#elif defined(__sun) || defined(sun)

#include <sys/byteorder.h>
#define bswap_32(x) BSWAP_32(x)
#define bswap_64(x) BSWAP_64(x)

#elif defined(__FreeBSD__)

#include <sys/endian.h>
#define bswap_32(x) bswap32(x)
#define bswap_64(x) bswap64(x)

#elif defined(__OpenBSD__)

#include <sys/types.h>
#define bswap_32(x) swap32(x)
#define bswap_64(x) swap64(x)

#elif defined(__NetBSD__)

#include <sys/types.h>
#include <machine/bswap.h>
#if defined(__BSWAP_RENAME) && !defined(__bswap_32)
#define bswap_32(x) bswap32(x)
#define bswap_64(x) bswap64(x)
#endif

#else

#include <byteswap.h>

#endif

#ifdef WORDS_BIGENDIAN
#define uint32_t_in_expected_order(x) (bswap_32(x))
#define uint64_t_in_expected_order(x) (bswap_64(x))
#else
#define uint32_t_in_expected_order(x) (x)
#define uint64_t_in_expected_order(x) (x)
#endif

#if !defined(LIKELY)
#if HAVE_BUILTIN_EXPECT
#define LIKELY(x) (__builtin_expect(!!(x), 1))
#else
#define LIKELY(x) (x)
#endif
#endif

static uint64_t Fetch64(const char *p) {
  return uint64_t_in_expected_order(UNALIGNED_LOAD64(p));
}

static uint32_t Fetch32(const char *p) {
  return uint32_t_in_expected_order(UNALIGNED_LOAD32(p));
}

// Some primes between 2^63 and 2^64 for various uses.
static const uint64_t k0 = 0xc3a5c85c97cb3127ULL;
static const uint64_t k1 = 0xb492b66fbe98f273ULL;
static const uint64_t k2 = 0x9ae16a3b2f90404fULL;

#undef PERMUTE3
#define PERMUTE3(a, b, c) do { swap64(a, b); swap64(a, c); } while (0)

// Bitwise right rotate.  Normally this will compile to a single
// instruction, especially if the shift is a manifest constant.
static uint64_t Rotate(uint64_t val, int shift) {
  // Avoid shifting by 64: doing so yields an undefined result.
  return shift == 0 ? val : ((val >> shift) | (val << (64 - shift)));
}

static uint64_t ShiftMix(uint64_t val) {
  return val ^ (val >> 47);
}

static uint64_t HashLen16__(uint64_t u, uint64_t v, uint64_t mul) {
  // Murmur-inspired hashing.
  uint64_t a = (u ^ v) * mul;
  a ^= (a >> 47);
  uint64_t b = (v ^ a) * mul;
  b ^= (b >> 47);
  b *= mul;
  return b;
}

static uint64_t HashLen16(uint64_t u, uint64_t v) {
    return HashLen16__(u, v, 0xc6a4a7935bd1e995ULL);
}

static uint64_t HashLen0to16(const char *s, size_t len) {
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
    uint32_t y = ((uint32_t)a) + (((uint32_t)b) << 8);
    uint32_t z = len + (((uint32_t)c) << 2);
    return ShiftMix(y * k2 ^ z * k0) * k2;
  }
  return k2;
}

// This probably works well for 16-byte strings as well, but it may be overkill
// in that case.
static uint64_t HashLen17to32(const char *s, size_t len) {
  uint64_t mul = k2 + len * 2;
  uint64_t a = Fetch64(s) * k1;
  uint64_t b = Fetch64(s + 8);
  uint64_t c = Fetch64(s + len - 8) * mul;
  uint64_t d = Fetch64(s + len - 16) * k2;
  return HashLen16__(Rotate(a + b, 43) + Rotate(c, 30) + d,
                     a + Rotate(b + k2, 18) + c, mul);
}

// Return a 16-byte hash for 48 bytes.  Quick and dirty.
// Callers do best to use "random-looking" values for a and b.
static void
WeakHashLen32WithSeeds__(uint64_t w, uint64_t x, uint64_t y, uint64_t z,
                         uint64_t a, uint64_t b,
                         uint64_t *dstA, uint64_t*dstB) {
  a += w;
  b = Rotate(b + a + z, 21);
  uint64_t c = a;
  a += x;
  a += y;
  b += Rotate(a, 44);
  *dstA = a + z;
  *dstB = b + c;
}

// Return a 16-byte hash for s[0] ... s[31], a, and b.  Quick and dirty.
static void WeakHashLen32WithSeeds(const char* s, uint64_t a, uint64_t b,
                                   uint64_t *dstA, uint64_t *dstB) {
  return WeakHashLen32WithSeeds__(Fetch64(s),
                                  Fetch64(s + 8),
                                  Fetch64(s + 16),
                                  Fetch64(s + 24),
                                  a,
                                  b,
                                  dstA,
                                  dstB);
}

// Return an 8-byte hash for 33 to 64 bytes.
static uint64_t HashLen33to64(const char *s, size_t len) {
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
  uint64_t w = bswap_64((u + v) * mul) + h;
  uint64_t x = Rotate(e + f, 42) + c;
  uint64_t y = (bswap_64((v + w) * mul) + g) * mul;
  uint64_t z = e + f + c;
  a = bswap_64((x + z) * mul + y) + b;
  b = ShiftMix((z + a) * mul + d + h) * mul;
  return b + x;
}

static uint64_t CityHash64WithoutSeed(const char *s, size_t len) {
  if (len <= 32) {
    if (len <= 16) {
      return HashLen0to16(s, len);
    } else {
      return HashLen17to32(s, len);
    }
  } else if (len <= 64) {
    return HashLen33to64(s, len);
  }

  // For strings over 64 bytes we hash the end first, and then as we
  // loop we keep 56 bytes of state: v, w, x, y, and z.
  uint64_t x = Fetch64(s + len - 40);
  uint64_t y = Fetch64(s + len - 16) + Fetch64(s + len - 56);
  uint64_t z = HashLen16(Fetch64(s + len - 48) + len, Fetch64(s + len - 24));
  uint64_t v_first, v_second, w_first, w_second;
  WeakHashLen32WithSeeds(s + len - 64, len, z, &v_first, &v_second);
  WeakHashLen32WithSeeds(s + len - 32, y + k1, x, &w_first, &w_second);
  x = x * k1 + Fetch64(s);

  // Decrease len to the nearest multiple of 64, and operate on 64-byte chunks.
  len = (len - 1) & ~((size_t)63);
  do {
    x = Rotate(x + y + v_first + Fetch64(s + 8), 37) * k1;
    y = Rotate(y + v_second + Fetch64(s + 48), 42) * k1;
    x ^= w_second;
    y += v_first + Fetch64(s + 40);
    z = Rotate(z + w_first, 33) * k1;
    WeakHashLen32WithSeeds(s, v_second * k1, x + w_first,
                           &v_first, &v_second);
    WeakHashLen32WithSeeds(s + 32, z + w_second, y + Fetch64(s + 16),
                           &w_first, &w_second);
    swap64(&z, &x);
    s += 64;
    len -= 64;
  } while (len != 0);
  return HashLen16(HashLen16(v_first, w_first) + ShiftMix(y) * k1 + z,
                   HashLen16(v_second, w_second) + x);
}

static uint64_t CityHash64WithSeeds(const char *s, size_t len,
                           uint64_t seed0, uint64_t seed1) {
  return HashLen16(CityHash64WithoutSeed(s, len) - seed0, seed1);
}

uint64_t chash64(const void *s, size_t len, uint64_t seed) {
  return CityHash64WithSeeds(s, len, k2, seed);
}

#ifdef __SSE4_2__
#include <nmmintrin.h>

// Requires len >= 240.
static void CityHashCrc256Long(const char *s, size_t len,
                               uint32_t seed, uint64_t *result) {
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

  // 240 bytes of input per iter.
  size_t iters = len / 240;
  len -= iters * 240;
  do {
#undef CHUNK
#define CHUNK(r)                                \
    PERMUTE3(x, z, y);                          \
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

    CHUNK(0); PERMUTE3(a, h, c);
    CHUNK(33); PERMUTE3(a, h, f);
    CHUNK(0); PERMUTE3(b, h, f);
    CHUNK(42); PERMUTE3(b, h, d);
    CHUNK(0); PERMUTE3(b, h, e);
    CHUNK(33); PERMUTE3(a, h, e);
  } while (--iters > 0);

  while (len >= 40) {
    CHUNK(29);
    e ^= Rotate(a, 20);
    h += Rotate(b, 30);
    g ^= Rotate(c, 40);
    f += Rotate(d, 34);
    PERMUTE3(c, h, g);
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

// Requires len < 240.
static void CityHashCrc256Short(const char *s, size_t len, uint64_t *result) {
  char buf[240];
  memcpy(buf, s, len);
  memset(buf + len, 0, 240 - len);
  CityHashCrc256Long(buf, 240, ~static_cast<uint32_t>(len), result);
}

void CityHashCrc256(const char *s, size_t len, uint64_t *result) {
  if (LIKELY(len >= 240)) {
    CityHashCrc256Long(s, len, 0, result);
  } else {
    CityHashCrc256Short(s, len, result);
  }
}
#endif

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
