// AES.cpp
// Copyright (c) 2025 金煜力
// AES-256 (CBC) 加密

#include "ui.h"
#include "AES.h"
#include <vector>
#include <string>
#include <cwchar>
#include <stdexcept>
#include <fstream>
#include <cstdio>
#include <windows.h>
#include <functional>
#include <wincrypt.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <intrin.h>
#include <wmmintrin.h>
#include <emmintrin.h>
#include <atomic>
#include <mutex>
#include <condition_variable>

// CBC模式
#ifndef CBC
#define CBC 1
#endif

// ECB模式
#ifndef ECB
#define ECB 1
#endif

// CTR模式
#ifndef CTR
#define CTR 1
#endif

#define AES256 1

#define AES_BLOCKLEN 16 // AES块长度为16字节

#if defined(AES256) && (AES256 == 1)
#define AES_KEYLEN 32
#define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
#define AES_KEYLEN 24
#define AES_keyExpSize 208
#else
#define AES_KEYLEN 16
#define AES_keyExpSize 176
#endif

// Pause control
static std::atomic<bool> g_request_pause(false);
static std::atomic<bool> g_processing_paused(false);
static std::mutex g_pause_mutex;
static std::condition_variable g_pause_cv;

void request_pause() {
    g_request_pause.store(true);
}

void resume_processing() {
    g_request_pause.store(false);
    {
        std::lock_guard<std::mutex> lk(g_pause_mutex);
    }
    g_pause_cv.notify_all();
}

bool is_processing_paused() {
    return g_processing_paused.load();
}

struct AES_ctx
{
    uint8_t RoundKey[AES_keyExpSize];
#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
    uint8_t Iv[AES_BLOCKLEN];
#endif
    // AES-NI accelerated round keys (if supported)
    bool aesni_available;
    // allocate maximum round keys for AES-256 (Nr=14 -> 15 round keys)
    __m128i enc_round_keys[15];
    __m128i dec_round_keys[15];
};

// The number of columns comprising a state in AES. This is a constant in AES. Value=4
#define Nb 4

#if defined(AES256) && (AES256 == 1)
#define Nk 8
#define Nr 14
#elif defined(AES192) && (AES192 == 1)
#define Nk 6
#define Nr 12
#else
#define Nk 4
#define Nr 10
#endif

#ifndef MULTIPLY_AS_A_FUNCTION
#define MULTIPLY_AS_A_FUNCTION 0
#endif

typedef uint8_t state_t[4][4];

// S盒
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// 逆S盒
#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
static const uint8_t rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};
#endif

// 轮常数
static const uint8_t Rcon[11] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

#define getSBoxValue(num) (sbox[(num)])
#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
#define getSBoxInvert(num) (rsbox[(num)])
#endif

// CPU AES-NI 检测
static bool cpu_supports_aesni()
{
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 25)) != 0; // ECX bit 25 = AESNI
}

// 密钥扩展
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
    unsigned i, j, k;
    uint8_t tempa[4];

    for (i = 0; i < Nk; ++i)
    {
        RoundKey[(i * 4) + 0] = Key[(i * 4) + 0];
        RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
        RoundKey[(i * 4) + 2] = Key[(i * 4) + 2];
        RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
    }

    for (i = Nk; i < Nb * (Nr + 1); ++i)
    {
        {
            k = (i - 1) * 4;
            tempa[0] = RoundKey[k + 0];
            tempa[1] = RoundKey[k + 1];
            tempa[2] = RoundKey[k + 2];
            tempa[3] = RoundKey[k + 3];
        }

        if (i % Nk == 0)
        {
            {
                const uint8_t u8tmp = tempa[0];
                tempa[0] = tempa[1];
                tempa[1] = tempa[2];
                tempa[2] = tempa[3];
                tempa[3] = u8tmp;
            }

            {
                tempa[0] = getSBoxValue(tempa[0]);
                tempa[1] = getSBoxValue(tempa[1]);
                tempa[2] = getSBoxValue(tempa[2]);
                tempa[3] = getSBoxValue(tempa[3]);
            }

            tempa[0] = tempa[0] ^ Rcon[i / Nk];
        }
#if defined(AES256) && (AES256 == 1)
        if (i % Nk == 4)
        {
            tempa[0] = getSBoxValue(tempa[0]);
            tempa[1] = getSBoxValue(tempa[1]);
            tempa[2] = getSBoxValue(tempa[2]);
            tempa[3] = getSBoxValue(tempa[3]);
        }
#endif
        j = i * 4; k = (i - Nk) * 4;
        RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
        RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
        RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
        RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
    }
}

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)
{
    KeyExpansion(ctx->RoundKey, key);
    // prepare AES-NI round keys if available
    ctx->aesni_available = cpu_supports_aesni();
    if (ctx->aesni_available) {
        // load encryption round keys
        for (int i = 0; i <= Nr; ++i) {
            ctx->enc_round_keys[i] = _mm_loadu_si128((const __m128i*)(ctx->RoundKey + i * AES_BLOCKLEN));
        }
        // prepare decryption round keys
        ctx->dec_round_keys[0] = ctx->enc_round_keys[Nr];
        for (int i = 1; i < Nr; ++i) {
            ctx->dec_round_keys[i] = _mm_aesimc_si128(ctx->enc_round_keys[Nr - i]);
        }
        ctx->dec_round_keys[Nr] = ctx->enc_round_keys[0];
    }
}

#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv)
{
    KeyExpansion(ctx->RoundKey, key);
    memcpy(ctx->Iv, iv, AES_BLOCKLEN);
    // prepare AES-NI round keys if available
    ctx->aesni_available = cpu_supports_aesni();
    if (ctx->aesni_available) {
        for (int i = 0; i <= Nr; ++i) {
            ctx->enc_round_keys[i] = _mm_loadu_si128((const __m128i*)(ctx->RoundKey + i * AES_BLOCKLEN));
        }
        ctx->dec_round_keys[0] = ctx->enc_round_keys[Nr];
        for (int i = 1; i < Nr; ++i) {
            ctx->dec_round_keys[i] = _mm_aesimc_si128(ctx->enc_round_keys[Nr - i]);
        }
        ctx->dec_round_keys[Nr] = ctx->enc_round_keys[0];
    }
}

void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv)
{
    memcpy(ctx->Iv, iv, AES_BLOCKLEN);
}
#endif

// 轮密钥加
static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
{
    uint8_t i, j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];
        }
    }
}

// 字节替换
static void SubBytes(state_t* state)
{
    uint8_t i, j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            (*state)[j][i] = getSBoxValue((*state)[j][i]);
        }
    }
}

// 行移位
static void ShiftRows(state_t* state)
{
    uint8_t temp;

    temp = (*state)[0][1];
    (*state)[0][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[3][1];
    (*state)[3][1] = temp;

    temp = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    temp = (*state)[0][3];
    (*state)[0][3] = (*state)[3][3];
    (*state)[3][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[1][3];
    (*state)[1][3] = temp;
}

static uint8_t xtime(uint8_t x)
{
    return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

// 列混合
static void MixColumns(state_t* state)
{
    uint8_t i;
    uint8_t Tmp, Tm, t;
    for (i = 0; i < 4; ++i)
    {
        t = (*state)[i][0];
        Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
        Tm = (*state)[i][0] ^ (*state)[i][1]; Tm = xtime(Tm); (*state)[i][0] ^= Tm ^ Tmp;
        Tm = (*state)[i][1] ^ (*state)[i][2]; Tm = xtime(Tm); (*state)[i][1] ^= Tm ^ Tmp;
        Tm = (*state)[i][2] ^ (*state)[i][3]; Tm = xtime(Tm); (*state)[i][2] ^= Tm ^ Tmp;
        Tm = (*state)[i][3] ^ t; Tm = xtime(Tm); (*state)[i][3] ^= Tm ^ Tmp;
    }
}

#if MULTIPLY_AS_A_FUNCTION
static uint8_t Multiply(uint8_t x, uint8_t y)
{
    return (((y & 1) * x) ^
        ((y >> 1 & 1) * xtime(x)) ^
        ((y >> 2 & 1) * xtime(xtime(x))) ^
        ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
        ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
}
#else
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))
#endif

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
// 逆列混合
static void InvMixColumns(state_t* state)
{
    int i;
    uint8_t a, b, c, d;
    for (i = 0; i < 4; ++i)
    {
        a = (*state)[i][0];
        b = (*state)[i][1];
        c = (*state)[i][2];
        d = (*state)[i][3];

        (*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
        (*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
        (*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
        (*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
    }
}

// 逆字节替换
static void InvSubBytes(state_t* state)
{
    uint8_t i, j;
    for (i = 0; i < 4; ++i)
    {
        for (j = 0; j < 4; ++j)
        {
            (*state)[j][i] = getSBoxInvert((*state)[j][i]);
        }
    }
}

// 逆行移位
static void InvShiftRows(state_t* state)
{
    uint8_t temp;

    temp = (*state)[3][1];
    (*state)[3][1] = (*state)[2][1];
    (*state)[2][1] = (*state)[1][1];
    (*state)[1][1] = (*state)[0][1];
    (*state)[0][1] = temp;

    temp = (*state)[0][2];
    (*state)[0][2] = (*state)[2][2];
    (*state)[2][2] = temp;

    temp = (*state)[1][2];
    (*state)[1][2] = (*state)[3][2];
    (*state)[3][2] = temp;

    temp = (*state)[0][3];
    (*state)[0][3] = (*state)[1][3];
    (*state)[1][3] = (*state)[2][3];
    (*state)[2][3] = (*state)[3][3];
    (*state)[3][3] = temp;
}
#endif

// 加密函数（软件实现，作为回退）
static void Cipher(state_t* state, const uint8_t* RoundKey)
{
    uint8_t round = 0;

    AddRoundKey(0, state, RoundKey);

    for (round = 1; ; ++round)
    {
        SubBytes(state);
        ShiftRows(state);
        if (round == Nr) {
            break;
        }
        MixColumns(state);
        AddRoundKey(round, state, RoundKey);
    }
    AddRoundKey(Nr, state, RoundKey);
}

#if (defined(CBC) && CBC == 1) || (defined(ECB) && ECB == 1)
// 解密函数（软件实现，作为回退）
static void InvCipher(state_t* state, const uint8_t* RoundKey)
{
    uint8_t round = 0;

    AddRoundKey(Nr, state, RoundKey);

    for (round = (Nr - 1); ; --round)
    {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(round, state, RoundKey);
        if (round == 0) {
            break;
        }
        InvMixColumns(state);
    }
}
#endif

// AES-NI 单块加解密器（使用已经展开成 __m128i 的轮密钥）
static inline void AESNI_encrypt_block(const struct AES_ctx* ctx, uint8_t* buf)
{
    if (!ctx->aesni_available) {
        Cipher((state_t*)buf, ctx->RoundKey);
        return;
    }
    __m128i m = _mm_loadu_si128((const __m128i*)buf);
    m = _mm_xor_si128(m, ctx->enc_round_keys[0]);
    for (int i = 1; i < Nr; ++i) {
        m = _mm_aesenc_si128(m, ctx->enc_round_keys[i]);
    }
    m = _mm_aesenclast_si128(m, ctx->enc_round_keys[Nr]);
    _mm_storeu_si128((__m128i*)buf, m);
}

static inline void AESNI_decrypt_block(const struct AES_ctx* ctx, uint8_t* buf)
{
    if (!ctx->aesni_available) {
        InvCipher((state_t*)buf, ctx->RoundKey);
        return;
    }
    __m128i m = _mm_loadu_si128((const __m128i*)buf);
    m = _mm_xor_si128(m, ctx->dec_round_keys[0]);
    for (int i = 1; i < Nr; ++i) {
        m = _mm_aesdec_si128(m, ctx->dec_round_keys[i]);
    }
    m = _mm_aesdeclast_si128(m, ctx->dec_round_keys[Nr]);
    _mm_storeu_si128((__m128i*)buf, m);
}

#if defined(ECB) && (ECB == 1)
void AES_ECB_encrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
    AESNI_encrypt_block(ctx, buf);
}

void AES_ECB_decrypt(const struct AES_ctx* ctx, uint8_t* buf)
{
    AESNI_decrypt_block(ctx, buf);
}
#endif

#if defined(CBC) && (CBC == 1)
static void XorWithIv(uint8_t* buf, const uint8_t* Iv)
{
    uint8_t i;
    for (i = 0; i < AES_BLOCKLEN; ++i)
    {
        buf[i] ^= Iv[i];
    }
}

void AES_CBC_encrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
    size_t i;
    uint8_t* Iv = ctx->Iv;
    for (i = 0; i < length; i += AES_BLOCKLEN)
    {
        XorWithIv(buf, Iv);
        AES_ECB_encrypt(ctx, buf);
        Iv = buf;
        buf += AES_BLOCKLEN;
    }
    memcpy(ctx->Iv, Iv, AES_BLOCKLEN);
}

void AES_CBC_decrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
    size_t i;
    uint8_t storeNextIv[AES_BLOCKLEN];
    for (i = 0; i < length; i += AES_BLOCKLEN)
    {
        memcpy(storeNextIv, buf, AES_BLOCKLEN);
        AES_ECB_decrypt(ctx, buf);
        XorWithIv(buf, ctx->Iv);
        memcpy(ctx->Iv, storeNextIv, AES_BLOCKLEN);
        buf += AES_BLOCKLEN;
    }
}
#endif

#if defined(CTR) && (CTR == 1)
void AES_CTR_xcrypt_buffer(struct AES_ctx* ctx, uint8_t* buf, size_t length)
{
    uint8_t buffer[AES_BLOCKLEN];

    size_t i;
    int bi;
    for (i = 0, bi = AES_BLOCKLEN; i < length; ++i, ++bi)
    {
        if (bi == AES_BLOCKLEN)
        {
            memcpy(buffer, ctx->Iv, AES_BLOCKLEN);
            // encrypt the counter block
            AES_ECB_encrypt(ctx, buffer);

            for (bi = (AES_BLOCKLEN - 1); bi >= 0; --bi)
            {
                if (ctx->Iv[bi] == 255)
                {
                    ctx->Iv[bi] = 0;
                    continue;
                }
                ctx->Iv[bi] += 1;
                break;
            }
            bi = 0;
        }

        buf[i] = (buf[i] ^ buffer[bi]);
    }
}
#endif

// 生成安全的随机数
static void generate_secure_random(uint8_t* buffer, size_t size) {
    HCRYPTPROV hProv;
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        throw std::runtime_error("无法获取加密上下文");
    }
    if (!CryptGenRandom(hProv, (DWORD)size, buffer)) {
        CryptReleaseContext(hProv, 0);
        throw std::runtime_error("生成随机数失败");
    }
    CryptReleaseContext(hProv, 0);
}

// PKCS7填充
static void pkcs7_pad(std::vector<uint8_t>& data) {
    size_t pad_len = AES_BLOCKLEN - (data.size() % AES_BLOCKLEN);
    if (pad_len == 0) pad_len = AES_BLOCKLEN;
    data.insert(data.end(), pad_len, static_cast<uint8_t>(pad_len));
}

// PKCS7去除填充
static bool pkcs7_unpad(std::vector<uint8_t>& data) {
    if (data.empty()) return false;

    uint8_t pad_len = data.back();
    if (pad_len == 0 || pad_len > AES_BLOCKLEN || pad_len > data.size()) {
        return false;
    }

    // 验证填充字节是否正确
    for (size_t i = data.size() - pad_len; i < data.size(); i++) {
        if (data[i] != pad_len) {
            return false;
        }
    }

    data.resize(data.size() - pad_len);
    return true;
}

// 新的同步实现，基于写入的字节数报告进度
void aes256_cbc_file(const std::wstring& input_file,
    const std::wstring& output_file,
    const std::vector<uint8_t>& key,
    const std::wstring& mode,
    ProgressCallback progressCallback) {

    // 获取输入文件大小
    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    if (!GetFileAttributesExW(input_file.c_str(), GetFileExInfoStandard, &fileInfo)) {
        throw std::runtime_error("无法获取输入文件大小");
    }

    ULONGLONG inputFileSize = ((ULONGLONG)fileInfo.nFileSizeHigh << 32) + fileInfo.nFileSizeLow;
    ULONGLONG expectedOutputSize = 0;

    if (mode == L"enc") {
        // 计算精确的PKCS#7填充长度
        size_t pad_len = AES_BLOCKLEN - (inputFileSize % AES_BLOCKLEN);
        if (pad_len == 0) pad_len = AES_BLOCKLEN;
        expectedOutputSize = inputFileSize + AES_BLOCKLEN /* IV */ + pad_len;
    }
    else {
        // 对于解密，预估输出大小为输入大小减去IV
        expectedOutputSize = inputFileSize - AES_BLOCKLEN;
    }

    // 验证密钥长度
    if (key.size() != 32) {
        throw std::invalid_argument("密钥长度必须为32字节(AES-256)");
    }

    if (mode == L"enc") {
        FILE* fin = nullptr;
        if (_wfopen_s(&fin, input_file.c_str(), L"rb") != 0 || !fin) {
            throw std::runtime_error("无法打开输入文件");
        }

        FILE* fout = nullptr;
        if (_wfopen_s(&fout, output_file.c_str(), L"wb") != 0 || !fout) {
            if (fin) fclose(fin);
            throw std::runtime_error("无法创建输出文件");
        }

        // 生成随机IV
        uint8_t iv[AES_BLOCKLEN];
        generate_secure_random(iv, sizeof(iv));

        // 写入IV
        ULONGLONG written = 0;
        if (fwrite(iv, 1, sizeof(iv), fout) != sizeof(iv)) {
            fclose(fin); fclose(fout);
            throw std::runtime_error("写入IV失败");
        }
        written += sizeof(iv);
        // 当进度增加1%时才更新进度
        int last_reported_percent = -1;
        if (progressCallback && expectedOutputSize > 0) {
            // Use 64-bit math to avoid overflow on 32-bit builds (written is size_t which may be 32-bit)
            int p = static_cast<int>(((static_cast<ULONGLONG>(written) * 100ULL) / expectedOutputSize));
            if (p > last_reported_percent && p < 100) {
                progressCallback(p);
                last_reported_percent = p;
            }
        }

        // 初始化AES上下文
        struct AES_ctx ctx;
        AES_init_ctx_iv(&ctx, key.data(), iv);

        // 获取输入文件大小以处理空文件情况
        _fseeki64(fin, 0, SEEK_END);
        __int64 input_size = _ftelli64(fin);
        _fseeki64(fin, 0, SEEK_SET);

        const size_t BUFFER_SIZE = 64 * 1024;
        std::vector<uint8_t> buffer;
        buffer.resize(BUFFER_SIZE);

        if (input_size == 0) {
            // 空文件：写入一个完整的填充块
            buffer.assign(AES_BLOCKLEN, AES_BLOCKLEN);
            AES_CBC_encrypt_buffer(&ctx, buffer.data(), buffer.size());
            if (fwrite(buffer.data(), 1, buffer.size(), fout) != buffer.size()) {
                fclose(fin); fclose(fout);
                throw std::runtime_error("写入加密数据失败");
            }
            written += buffer.size();
            if (progressCallback && expectedOutputSize > 0) {
                progressCallback(100);
            }
        }
        else {
            while (true) {
                // pause handling
                if (g_request_pause.load()) {
                    g_processing_paused.store(true);
                    std::unique_lock<std::mutex> ul(g_pause_mutex);
                    g_pause_cv.wait(ul, []() { return !g_request_pause.load(); });
                    g_processing_paused.store(false);
                }

                size_t bytes_read = fread(buffer.data(), 1, BUFFER_SIZE, fin);
                if (bytes_read == 0) break;
                buffer.resize(bytes_read);

                bool last = feof(fin) != 0;
                if (last) {
                    pkcs7_pad(buffer);
                }

                // 加密数据
                AES_CBC_encrypt_buffer(&ctx, buffer.data(), buffer.size());

                if (fwrite(buffer.data(), 1, buffer.size(), fout) != buffer.size()) {
                    fclose(fin); fclose(fout);
                    throw std::runtime_error("写入加密数据失败");
                }

                written += buffer.size();
                if (progressCallback && expectedOutputSize > 0) {
                    int p = static_cast<int>(((static_cast<ULONGLONG>(written) * 100ULL) / expectedOutputSize));
                    if (p > last_reported_percent && p < 100) {
                        progressCallback(p);
                        last_reported_percent = p;
                    }
                }

                if (last) break;

                buffer.resize(BUFFER_SIZE);
            }
            // 最终设置进度为100%
            if (progressCallback) progressCallback(100);
        }

        fclose(fin);
        fclose(fout);
    }
    else if (mode == L"dec") {
        FILE* fin = nullptr;
        if (_wfopen_s(&fin, input_file.c_str(), L"rb") != 0 || !fin) {
            throw std::runtime_error("无法打开输入文件");
        }

        FILE* fout = nullptr;
        if (_wfopen_s(&fout, output_file.c_str(), L"wb") != 0 || !fout) {
            if (fin) fclose(fin);
            throw std::runtime_error("无法创建输出文件");
        }

        // 读取IV
        uint8_t iv[AES_BLOCKLEN];
        size_t iv_read = fread(iv, 1, sizeof(iv), fin);
        if (iv_read != sizeof(iv)) {
            fclose(fin); fclose(fout);
            throw std::runtime_error("文件太小，无法读取IV");
        }

        ULONGLONG written = 0;

        // 初始化AES上下文
        struct AES_ctx ctx;
        AES_init_ctx_iv(&ctx, key.data(), iv);

        // 获取文件大小
        _fseeki64(fin, 0, SEEK_END);
        __int64 file_size = _ftelli64(fin);
        __int64 encrypted_size = file_size - static_cast<__int64>(sizeof(iv));
        if (encrypted_size < 0 || (encrypted_size % AES_BLOCKLEN) != 0) {
            fclose(fin); fclose(fout);
            throw std::runtime_error("加密数据大小不是块大小的倍数，文件可能已损坏");
        }
        _fseeki64(fin, static_cast<__int64>(sizeof(iv)), SEEK_SET);

        const size_t BUFFER_SIZE = 64 * 1024;
        std::vector<uint8_t> buffer;
        buffer.resize(BUFFER_SIZE);

        int last_reported_percent = -1;

        while (true) {
            // pause handling
            if (g_request_pause.load()) {
                g_processing_paused.store(true);
                std::unique_lock<std::mutex> ul(g_pause_mutex);
                g_pause_cv.wait(ul, []() { return !g_request_pause.load(); });
                g_processing_paused.store(false);
            }

            size_t bytes_read = fread(buffer.data(), 1, BUFFER_SIZE, fin);
            if (bytes_read == 0) break;
            buffer.resize(bytes_read);

            // 解密数据
            AES_CBC_decrypt_buffer(&ctx, buffer.data(), buffer.size());

            bool last = feof(fin) != 0;
            if (last) {
                if (!pkcs7_unpad(buffer)) {
                    fclose(fin); fclose(fout);
                    throw std::runtime_error("填充验证失败，文件可能已损坏");
                }
            }

            if (!buffer.empty()) {
                if (fwrite(buffer.data(), 1, buffer.size(), fout) != buffer.size()) {
                    fclose(fin); fclose(fout);
                    throw std::runtime_error("写入解密数据失败");
                }
                written += buffer.size();
                if (progressCallback && expectedOutputSize > 0) {
                    int p = static_cast<int>(((static_cast<ULONGLONG>(written) * 100ULL) / expectedOutputSize));
                    if (p > last_reported_percent && p < 100) {
                        progressCallback(p);
                        last_reported_percent = p;
                    }
                }
            }

            if (last) break;

            buffer.resize(BUFFER_SIZE);
        }

        // 最终设置进度为100%
        if (progressCallback) progressCallback(100);

        fclose(fin);
        fclose(fout);
    }
    else {
        throw std::invalid_argument("模式参数必须是'enc'或'dec'");
    }
}

// 密钥生成 (AES-256, 32字节长度)
std::vector<uint8_t> generate_aes256_key() {
    // 创建32字节的密钥缓冲区
    std::vector<uint8_t> key(32);
    // 生成随机密钥
    generate_secure_random(key.data(), key.size());
    return key;
}

// 读取密钥文件
std::vector<uint8_t> read_key(const std::wstring& file_path) {
    std::ifstream file(file_path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        fwprintf(stderr, L"无法打开文件: %ls\n", file_path.c_str());
        return {};
    }
    const auto file_size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> buffer(file_size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), file_size)) {
        fwprintf(stderr, L"读取文件失败: %ls\n", file_path.c_str());
        return {};
    }
    return buffer;
}

// 写入密钥文件
bool write_key(const std::wstring& file_path, const std::vector<uint8_t>& data) {
    std::ofstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        fwprintf(stderr, L"无法创建文件: %ls\n", file_path.c_str());
        return false;
    }
    if (!file.write(reinterpret_cast<const char*>(data.data()), data.size())) {
        fwprintf(stderr, L"写入文件失败: %ls\n", file_path.c_str());
        return false;
    }
    if (!file.good()) {
        fwprintf(stderr, L"写入过程中发生错误: %ls\n", file_path.c_str());
        return false;
    }
    return true;
}
