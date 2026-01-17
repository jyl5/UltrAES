// hash.cpp
// Copyright (c) 2025 金煜力
// CRC32 & MD5 & SHA 哈希校验和计算

#include "hash.h"
#include <string>
#include <vector>
#include <cstdint>
#include <array>
#include <stdexcept>
#include <algorithm>
#include <iomanip>
#include <sstream>
#include <cstring>

// ================= CRC32 =================
// CRC32查找表
const uint32_t crc32_table[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

void Crc32Init(CRC32_CTX* ctx) {
    ctx->crc = 0xFFFFFFFF;
}

void Crc32Update(CRC32_CTX* ctx, const void* data, size_t length) {
    const uint8_t* buffer = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < length; ++i) {
        ctx->crc = (ctx->crc >> 8) ^ crc32_table[(ctx->crc ^ buffer[i]) & 0xFF];
    }
}

void Crc32Update(CRC32_CTX* ctx, const std::string& str) {
    Crc32Update(ctx, str.data(), str.size());
}

void Crc32Update(CRC32_CTX* ctx, const std::vector<uint8_t>& data) {
    Crc32Update(ctx, data.data(), data.size());
}

std::string Crc32HexDigest(CRC32_CTX* ctx) {
    uint32_t final_crc = ctx->crc ^ 0xFFFFFFFF;
    char hex_digest[9];
    snprintf(hex_digest, sizeof(hex_digest), "%08x", final_crc);
    return std::string(hex_digest);
}

std::wstring Crc32HexDigestW(CRC32_CTX* ctx) {
    uint32_t final_crc = ctx->crc ^ 0xFFFFFFFF;
    wchar_t hex_digest[9];
    swprintf(hex_digest, 9, L"%08x", final_crc);
    return std::wstring(hex_digest);
}

uint32_t Crc32Digest(CRC32_CTX* ctx) {
    return ctx->crc ^ 0xFFFFFFFF;
}

void Crc32Reset(CRC32_CTX* ctx) {
    ctx->crc = 0xFFFFFFFF;
}

// ================= MD5 =================
constexpr uint32_t MD5_S[64] = {
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
};

constexpr uint32_t MD5_K[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

inline uint32_t md5_left_rotate(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

inline uint32_t md5_to_little_endian(const uint8_t* bytes) {
    return static_cast<uint32_t>(bytes[0])
        | (static_cast<uint32_t>(bytes[1]) << 8)
        | (static_cast<uint32_t>(bytes[2]) << 16)
        | (static_cast<uint32_t>(bytes[3]) << 24);
}

void Md5Transform(MD5_CTX* ctx, const uint8_t* block) {
    uint32_t a = ctx->A, b = ctx->B, c = ctx->C, d = ctx->D;
    uint32_t X[16];
    for (int i = 0; i < 16; ++i) {
        X[i] = md5_to_little_endian(block + i * 4);
    }
    for (int i = 0; i < 64; ++i) {
        uint32_t F, g;
        if (i < 16) {
            F = (b & c) | ((~b) & d);
            g = i;
        }
        else if (i < 32) {
            F = (d & b) | ((~d) & c);
            g = (5 * i + 1) % 16;
        }
        else if (i < 48) {
            F = b ^ c ^ d;
            g = (3 * i + 5) % 16;
        }
        else {
            F = c ^ (b | (~d));
            g = (7 * i) % 16;
        }
        F = F + a + MD5_K[i] + X[g];
        a = d;
        d = c;
        c = b;
        b = b + md5_left_rotate(F, MD5_S[i]);
    }
    ctx->A += a;
    ctx->B += b;
    ctx->C += c;
    ctx->D += d;
}

void Md5DoFinalize(MD5_CTX* ctx) {
    if (ctx->finished) return;
    uint64_t bit_length = ctx->total_bytes * 8;
    ctx->buffer.push_back(0x80);
    size_t orig_size = ctx->buffer.size();
    size_t pad_size = (orig_size % 64 < 56) ? (56 - orig_size % 64) : (120 - orig_size % 64);
    ctx->buffer.insert(ctx->buffer.end(), pad_size, 0);
    for (int i = 0; i < 8; i++) {
        ctx->buffer.push_back(static_cast<uint8_t>(bit_length >> (i * 8)));
    }
    for (size_t i = 0; i < ctx->buffer.size(); i += 64) {
        Md5Transform(ctx, ctx->buffer.data() + i);
    }
    auto to_le_bytes = [](uint32_t n) -> std::array<uint8_t, 4> {
        return {
            static_cast<uint8_t>(n),
            static_cast<uint8_t>(n >> 8),
            static_cast<uint8_t>(n >> 16),
            static_cast<uint8_t>(n >> 24)
        };
        };
    std::array<uint8_t, 4> a_bytes = to_le_bytes(ctx->A);
    std::array<uint8_t, 4> b_bytes = to_le_bytes(ctx->B);
    std::array<uint8_t, 4> c_bytes = to_le_bytes(ctx->C);
    std::array<uint8_t, 4> d_bytes = to_le_bytes(ctx->D);
    std::copy(a_bytes.begin(), a_bytes.end(), ctx->digest_result.begin());
    std::copy(b_bytes.begin(), b_bytes.end(), ctx->digest_result.begin() + 4);
    std::copy(c_bytes.begin(), c_bytes.end(), ctx->digest_result.begin() + 8);
    std::copy(d_bytes.begin(), d_bytes.end(), ctx->digest_result.begin() + 12);
    ctx->finished = true;
}

void Md5Init(MD5_CTX* ctx) {
    ctx->A = 0x67452301;
    ctx->B = 0xefcdab89;
    ctx->C = 0x98badcfe;
    ctx->D = 0x10325476;
    ctx->total_bytes = 0;
    ctx->finished = false;
    ctx->buffer.reserve(64);
    ctx->digest_result.fill(0);
}

void Md5Update(MD5_CTX* ctx, const void* data, size_t length) {
    if (ctx->finished) return;
    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    ctx->total_bytes += length;
    if (!ctx->buffer.empty()) {
        size_t to_copy = std::min<size_t>(64 - ctx->buffer.size(), length);
        ctx->buffer.insert(ctx->buffer.end(), ptr, ptr + to_copy);
        ptr += to_copy;
        length -= to_copy;
        if (ctx->buffer.size() == 64) {
            Md5Transform(ctx, ctx->buffer.data());
            ctx->buffer.clear();
        }
    }
    while (length >= 64) {
        Md5Transform(ctx, ptr);
        ptr += 64;
        length -= 64;
    }
    if (length > 0) {
        ctx->buffer.insert(ctx->buffer.end(), ptr, ptr + length);
    }
}

void Md5Update(MD5_CTX* ctx, const std::string& data) {
    Md5Update(ctx, data.data(), data.size());
}

void Md5Update(MD5_CTX* ctx, const std::vector<uint8_t>& data) {
    Md5Update(ctx, data.data(), data.size());
}

void Md5Finalize(MD5_CTX* ctx) {
    if (!ctx->finished) Md5DoFinalize(ctx);
}

std::string Md5Digest(MD5_CTX* ctx) {
    if (!ctx->finished) Md5DoFinalize(ctx);
    return std::string(ctx->digest_result.begin(), ctx->digest_result.end());
}

std::string Md5HexDigest(MD5_CTX* ctx) {
    if (!ctx->finished) Md5DoFinalize(ctx);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t c : ctx->digest_result) {
        oss << std::setw(2) << static_cast<unsigned>(c);
    }
    return oss.str();
}

std::wstring Md5HexDigestW(MD5_CTX* ctx) {
    if (!ctx->finished) Md5DoFinalize(ctx);
    std::wostringstream oss;
    oss << std::hex << std::setfill(L'0');
    for (uint8_t c : ctx->digest_result) {
        oss << std::setw(2) << static_cast<unsigned>(c);
    }
    return oss.str();
}

void Md5Reset(MD5_CTX* ctx) {
    ctx->A = 0x67452301;
    ctx->B = 0xefcdab89;
    ctx->C = 0x98badcfe;
    ctx->D = 0x10325476;
    ctx->total_bytes = 0;
    ctx->finished = false;
    ctx->buffer.clear();
    ctx->digest_result.fill(0);
}

// ================= SHA1 =================
inline uint32_t sha1_left_rotate(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32 - n));
}

void Sha1Transform(SHA1_CTX* ctx, const uint8_t* block) {
    uint32_t w[80];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
            (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
            (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
            static_cast<uint32_t>(block[i * 4 + 3]);
    }
    for (int i = 16; i < 80; ++i) {
        w[i] = sha1_left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }
    uint32_t a = ctx->h0, b = ctx->h1, c = ctx->h2, d = ctx->h3, e = ctx->h4;
    for (int i = 0; i < 20; ++i) {
        uint32_t f = (b & c) | ((~b) & d);
        uint32_t temp = sha1_left_rotate(a, 5) + f + e + 0x5A827999 + w[i];
        e = d; d = c; c = sha1_left_rotate(b, 30); b = a; a = temp;
    }
    for (int i = 20; i < 40; ++i) {
        uint32_t f = b ^ c ^ d;
        uint32_t temp = sha1_left_rotate(a, 5) + f + e + 0x6ED9EBA1 + w[i];
        e = d; d = c; c = sha1_left_rotate(b, 30); b = a; a = temp;
    }
    for (int i = 40; i < 60; ++i) {
        uint32_t f = (b & c) | (b & d) | (c & d);
        uint32_t temp = sha1_left_rotate(a, 5) + f + e + 0x8F1BBCDC + w[i];
        e = d; d = c; c = sha1_left_rotate(b, 30); b = a; a = temp;
    }
    for (int i = 60; i < 80; ++i) {
        uint32_t f = b ^ c ^ d;
        uint32_t temp = sha1_left_rotate(a, 5) + f + e + 0xCA62C1D6 + w[i];
        e = d; d = c; c = sha1_left_rotate(b, 30); b = a; a = temp;
    }
    ctx->h0 += a; ctx->h1 += b; ctx->h2 += c; ctx->h3 += d; ctx->h4 += e;
}

void Sha1DoFinalize(SHA1_CTX* ctx) {
    if (ctx->finished) return;
    size_t n = ctx->buffer.size();
    size_t k = (55 - n + 64) % 64;
    std::vector<uint8_t> padding;
    padding.reserve(n + 1 + k + 8);
    padding = ctx->buffer;
    padding.push_back(0x80);
    padding.insert(padding.end(), k, 0);
    uint64_t bit_length = ctx->total_bytes * 8;
    for (int i = 0; i < 8; i++) {
        padding.push_back(static_cast<uint8_t>((bit_length >> (56 - i * 8)) & 0xFF));
    }
    for (size_t i = 0; i < padding.size(); i += 64) {
        Sha1Transform(ctx, padding.data() + i);
    }
    auto to_be_bytes = [](uint32_t n, uint8_t* bytes) {
        bytes[0] = static_cast<uint8_t>((n >> 24) & 0xFF);
        bytes[1] = static_cast<uint8_t>((n >> 16) & 0xFF);
        bytes[2] = static_cast<uint8_t>((n >> 8) & 0xFF);
        bytes[3] = static_cast<uint8_t>(n & 0xFF);
        };
    to_be_bytes(ctx->h0, ctx->digest_result.data());
    to_be_bytes(ctx->h1, ctx->digest_result.data() + 4);
    to_be_bytes(ctx->h2, ctx->digest_result.data() + 8);
    to_be_bytes(ctx->h3, ctx->digest_result.data() + 12);
    to_be_bytes(ctx->h4, ctx->digest_result.data() + 16);
    ctx->finished = true;
}

void Sha1Init(SHA1_CTX* ctx) {
    ctx->h0 = 0x67452301;
    ctx->h1 = 0xEFCDAB89;
    ctx->h2 = 0x98BADCFE;
    ctx->h3 = 0x10325476;
    ctx->h4 = 0xC3D2E1F0;
    ctx->total_bytes = 0;
    ctx->finished = false;
    ctx->digest_result.fill(0);
}

void Sha1Update(SHA1_CTX* ctx, const void* data, size_t length) {
    if (ctx->finished) return;
    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    ctx->total_bytes += length;
    if (!ctx->buffer.empty()) {
        size_t to_copy = std::min<size_t>(64 - ctx->buffer.size(), length);
        ctx->buffer.insert(ctx->buffer.end(), ptr, ptr + to_copy);
        ptr += to_copy;
        length -= to_copy;
        if (ctx->buffer.size() == 64) {
            Sha1Transform(ctx, ctx->buffer.data());
            ctx->buffer.clear();
        }
    }
    while (length >= 64) {
        Sha1Transform(ctx, ptr);
        ptr += 64;
        length -= 64;
    }
    if (length > 0) {
        ctx->buffer.insert(ctx->buffer.end(), ptr, ptr + length);
    }
}

void Sha1Update(SHA1_CTX* ctx, const std::string& data) {
    Sha1Update(ctx, data.data(), data.size());
}

void Sha1Update(SHA1_CTX* ctx, const std::vector<uint8_t>& data) {
    Sha1Update(ctx, data.data(), data.size());
}

void Sha1Finalize(SHA1_CTX* ctx) {
    if (!ctx->finished) Sha1DoFinalize(ctx);
}

std::string Sha1Digest(SHA1_CTX* ctx) {
    if (!ctx->finished) Sha1DoFinalize(ctx);
    return std::string(ctx->digest_result.begin(), ctx->digest_result.end());
}

std::string Sha1HexDigest(SHA1_CTX* ctx) {
    if (!ctx->finished) Sha1DoFinalize(ctx);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t c : ctx->digest_result) {
        oss << std::setw(2) << static_cast<unsigned>(c);
    }
    return oss.str();
}

std::wstring Sha1HexDigestW(SHA1_CTX* ctx) {
    if (!ctx->finished) Sha1DoFinalize(ctx);
    std::wostringstream oss;
    oss << std::hex << std::setfill(L'0');
    for (uint8_t c : ctx->digest_result) {
        oss << std::setw(2) << static_cast<unsigned>(c);
    }
    return oss.str();
}

void Sha1Reset(SHA1_CTX* ctx) {
    ctx->h0 = 0x67452301;
    ctx->h1 = 0xEFCDAB89;
    ctx->h2 = 0x98BADCFE;
    ctx->h3 = 0x10325476;
    ctx->h4 = 0xC3D2E1F0;
    ctx->total_bytes = 0;
    ctx->finished = false;
    ctx->buffer.clear();
    ctx->digest_result.fill(0);
}

// ================= SHA256 =================
inline uint32_t sha256_rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

inline uint32_t sha256_ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

inline uint32_t sha256_maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32_t sha256_sigma0(uint32_t x) {
    return sha256_rotr(x, 2) ^ sha256_rotr(x, 13) ^ sha256_rotr(x, 22);
}

inline uint32_t sha256_sigma1(uint32_t x) {
    return sha256_rotr(x, 6) ^ sha256_rotr(x, 11) ^ sha256_rotr(x, 25);
}

inline uint32_t sha256_gamma0(uint32_t x) {
    return sha256_rotr(x, 7) ^ sha256_rotr(x, 18) ^ (x >> 3);
}

inline uint32_t sha256_gamma1(uint32_t x) {
    return sha256_rotr(x, 17) ^ sha256_rotr(x, 19) ^ (x >> 10);
}

const std::array<uint32_t, 64> sha256_k = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void Sha256ProcessBlock(SHA256_CTX* ctx, const uint8_t* block) {
    std::array<uint32_t, 64> w;
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
            (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
            (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
            (static_cast<uint32_t>(block[i * 4 + 3]));
    }
    for (int i = 16; i < 64; ++i) {
        w[i] = sha256_gamma1(w[i - 2]) + w[i - 7] + sha256_gamma0(w[i - 15]) + w[i - 16];
    }
    uint32_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3], e = ctx->h[4], f = ctx->h[5], g = ctx->h[6], h_val = ctx->h[7];
    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = h_val + sha256_sigma1(e) + sha256_ch(e, f, g) + sha256_k[i] + w[i];
        uint32_t t2 = sha256_sigma0(a) + sha256_maj(a, b, c);
        h_val = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d; ctx->h[4] += e; ctx->h[5] += f; ctx->h[6] += g; ctx->h[7] += h_val;
}

void Sha256Init(SHA256_CTX* ctx) {
    ctx->total_bytes = 0;
    ctx->buffer.clear();
    ctx->buffer.reserve(64);
    ctx->h[0] = 0x6a09e667;
    ctx->h[1] = 0xbb67ae85;
    ctx->h[2] = 0x3c6ef372;
    ctx->h[3] = 0xa54ff53a;
    ctx->h[4] = 0x510e527f;
    ctx->h[5] = 0x9b05688c;
    ctx->h[6] = 0x1f83d9ab;
    ctx->h[7] = 0x5be0cd19;
    ctx->finalized = false;
}

void Sha256Update(SHA256_CTX* ctx, const void* data, size_t len) {
    if (ctx->finalized) {
        throw std::runtime_error("SHA256: cannot update after finalization");
    }
    const uint8_t* d = static_cast<const uint8_t*>(data);
    size_t index = 0;
    size_t remaining = len;
    if (!ctx->buffer.empty()) {
        size_t buffer_remaining = 64 - ctx->buffer.size();
        if (remaining < buffer_remaining) {
            ctx->buffer.insert(ctx->buffer.end(), d, d + remaining);
            return;
        }
        ctx->buffer.insert(ctx->buffer.end(), d, d + buffer_remaining);
        Sha256ProcessBlock(ctx, ctx->buffer.data());
        ctx->total_bytes += 64;
        index += buffer_remaining;
        remaining -= buffer_remaining;
        ctx->buffer.clear();
    }
    while (remaining >= 64) {
        Sha256ProcessBlock(ctx, d + index);
        ctx->total_bytes += 64;
        index += 64;
        remaining -= 64;
    }
    if (remaining > 0) {
        ctx->buffer.insert(ctx->buffer.end(), d + index, d + index + remaining);
    }
}

void Sha256Update(SHA256_CTX* ctx, const std::string& data) {
    Sha256Update(ctx, data.data(), data.size());
}

void Sha256Update(SHA256_CTX* ctx, const std::vector<uint8_t>& data) {
    Sha256Update(ctx, data.data(), data.size());
}

void Sha256DoFinalize(SHA256_CTX* ctx) {
    if (ctx->finalized) return;
    uint64_t total_bits = (ctx->total_bytes + ctx->buffer.size()) * 8;
    ctx->buffer.push_back(0x80);
    size_t orig_size = ctx->buffer.size();
    size_t padding_len = (orig_size % 64 < 56) ? (56 - orig_size % 64) : (120 - orig_size % 64);
    ctx->buffer.resize(orig_size + padding_len, 0);
    for (int i = 0; i < 8; ++i) {
        ctx->buffer.push_back(static_cast<uint8_t>((total_bits >> (56 - i * 8)) & 0xFF));
    }
    for (size_t i = 0; i < ctx->buffer.size(); i += 64) {
        Sha256ProcessBlock(ctx, &ctx->buffer[i]);
    }
    ctx->finalized = true;
    ctx->buffer.clear();
}

void Sha256Finalize(SHA256_CTX* ctx) {
    if (!ctx->finalized) Sha256DoFinalize(ctx);
}

std::vector<uint8_t> Sha256Digest(SHA256_CTX* ctx) {
    if (!ctx->finalized) Sha256DoFinalize(ctx);
    std::vector<uint8_t> result(32);
    for (int i = 0; i < 8; ++i) {
        result[i * 4] = static_cast<uint8_t>(ctx->h[i] >> 24);
        result[i * 4 + 1] = static_cast<uint8_t>(ctx->h[i] >> 16);
        result[i * 4 + 2] = static_cast<uint8_t>(ctx->h[i] >> 8);
        result[i * 4 + 3] = static_cast<uint8_t>(ctx->h[i]);
    }
    return result;
}

std::string Sha256HexDigest(SHA256_CTX* ctx) {
    std::vector<uint8_t> bin_digest = Sha256Digest(ctx);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : bin_digest) {
        oss << std::setw(2) << static_cast<unsigned>(b);
    }
    return oss.str();
}

std::wstring Sha256HexDigestW(SHA256_CTX* ctx) {
    std::vector<uint8_t> bin_digest = Sha256Digest(ctx);
    std::wostringstream oss;
    oss << std::hex << std::setfill(L'0');
    for (uint8_t b : bin_digest) {
        oss << std::setw(2) << static_cast<unsigned>(b);
    }
    return oss.str();
}

void Sha256Reset(SHA256_CTX* ctx) {
    ctx->total_bytes = 0;
    ctx->buffer.clear();
    ctx->buffer.reserve(64);
    ctx->h[0] = 0x6a09e667;
    ctx->h[1] = 0xbb67ae85;
    ctx->h[2] = 0x3c6ef372;
    ctx->h[3] = 0xa54ff53a;
    ctx->h[4] = 0x510e527f;
    ctx->h[5] = 0x9b05688c;
    ctx->h[6] = 0x1f83d9ab;
    ctx->h[7] = 0x5be0cd19;
    ctx->finalized = false;
}

// ================= SHA384 =================
// SHA-384常量
const uint64_t sha384_k[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

inline uint64_t sha384_rotr64(uint64_t x, uint32_t n) {
    return (x >> n) | (x << (64 - n));
}

inline uint64_t sha384_ch(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (~x & z);
}

inline uint64_t sha384_maj(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint64_t sha384_sigma0(uint64_t x) {
    return sha384_rotr64(x, 28) ^ sha384_rotr64(x, 34) ^ sha384_rotr64(x, 39);
}

inline uint64_t sha384_sigma1(uint64_t x) {
    return sha384_rotr64(x, 14) ^ sha384_rotr64(x, 18) ^ sha384_rotr64(x, 41);
}

inline uint64_t sha384_gamma0(uint64_t x) {
    return sha384_rotr64(x, 1) ^ sha384_rotr64(x, 8) ^ (x >> 7);
}

inline uint64_t sha384_gamma1(uint64_t x) {
    return sha384_rotr64(x, 19) ^ sha384_rotr64(x, 61) ^ (x >> 6);
}

void Sha384ProcessBlock(SHA384_CTX* ctx, const uint8_t* block) {
    uint64_t w[80] = { 0 };

    // 加载前16个字（大端序）
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<uint64_t>(block[i * 8]) << 56) |
            (static_cast<uint64_t>(block[i * 8 + 1]) << 48) |
            (static_cast<uint64_t>(block[i * 8 + 2]) << 40) |
            (static_cast<uint64_t>(block[i * 8 + 3]) << 32) |
            (static_cast<uint64_t>(block[i * 8 + 4]) << 24) |
            (static_cast<uint64_t>(block[i * 8 + 5]) << 16) |
            (static_cast<uint64_t>(block[i * 8 + 6]) << 8) |
            (static_cast<uint64_t>(block[i * 8 + 7]));
    }

    // 扩展消息调度数组（16-79）
    for (int i = 16; i < 80; ++i) {
        w[i] = sha384_gamma1(w[i - 2]) + w[i - 7] + sha384_gamma0(w[i - 15]) + w[i - 16];
    }

    // 初始化工作变量
    uint64_t a = ctx->h[0];
    uint64_t b = ctx->h[1];
    uint64_t c = ctx->h[2];
    uint64_t d = ctx->h[3];
    uint64_t e = ctx->h[4];
    uint64_t f = ctx->h[5];
    uint64_t g = ctx->h[6];
    uint64_t h_val = ctx->h[7];

    // 主循环（80轮）
    for (int i = 0; i < 80; ++i) {
        uint64_t t1 = h_val + sha384_sigma1(e) + sha384_ch(e, f, g) + sha384_k[i] + w[i];
        uint64_t t2 = sha384_sigma0(a) + sha384_maj(a, b, c);

        h_val = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // 更新哈希值
    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
    ctx->h[5] += f;
    ctx->h[6] += g;
    ctx->h[7] += h_val;
}

void Sha384Init(SHA384_CTX* ctx) {
    // SHA-384初始哈希值
    ctx->h[0] = 0xcbbb9d5dc1059ed8;
    ctx->h[1] = 0x629a292a367cd507;
    ctx->h[2] = 0x9159015a3070dd17;
    ctx->h[3] = 0x152fecd8f70e5939;
    ctx->h[4] = 0x67332667ffc00b31;
    ctx->h[5] = 0x8eb44a8768581511;
    ctx->h[6] = 0xdb0c2e0d64f98fa7;
    ctx->h[7] = 0x47b5481dbefa4fa4;

    ctx->length = 0;
    ctx->buffer_size = 0;
    ctx->finalized = false;
}

void Sha384Update(SHA384_CTX* ctx, const void* data, size_t size) {
    if (ctx->finalized) return;
    const uint8_t* input = static_cast<const uint8_t*>(data);
    size_t offset = 0;

    // 处理缓冲区中已有的数据
    if (ctx->buffer_size > 0) {
        size_t copy_len = std::min<size_t>(128 - ctx->buffer_size, size);
        memcpy(ctx->buffer + ctx->buffer_size, input, copy_len);
        ctx->buffer_size += copy_len;
        offset += copy_len;

        if (ctx->buffer_size == 128) {
            Sha384ProcessBlock(ctx, ctx->buffer);
            ctx->length += 128;
            ctx->buffer_size = 0;
        }
    }

    // 处理完整的块
    while (offset + 128 <= size) {
        Sha384ProcessBlock(ctx, input + offset);
        ctx->length += 128;
        offset += 128;
    }

    // 将剩余数据存入缓冲区
    if (offset < size) {
        size_t remaining = size - offset;
        memcpy(ctx->buffer, input + offset, remaining);
        ctx->buffer_size = remaining;
    }
}

void Sha384Update(SHA384_CTX* ctx, const std::vector<uint8_t>& data) {
    Sha384Update(ctx, data.data(), data.size());
}

void Sha384Update(SHA384_CTX* ctx, const std::string& data) {
    Sha384Update(ctx, data.data(), data.size());
}

void Sha384DoFinalize(SHA384_CTX* ctx) {
    if (ctx->finalized) return;
    // 保存原始长度
    uint64_t original_length = ctx->length + ctx->buffer_size;
    uint64_t original_bits = original_length * 8;

    // 添加填充
    size_t padding_len = (ctx->buffer_size < 112) ? (112 - ctx->buffer_size) : (240 - ctx->buffer_size);
    std::vector<uint8_t> padding(padding_len + 16);
    padding[0] = 0x80;

    // 添加长度信息（大端序）
    for (int i = 0; i < 8; ++i) {
        padding[padding_len + 8 + i] = static_cast<uint8_t>(original_bits >> (56 - i * 8));
    }

    // 处理填充数据
    Sha384Update(ctx, padding.data(), padding.size());
    ctx->finalized = true;
}

void Sha384Finalize(SHA384_CTX* ctx) {
    if (!ctx->finalized) Sha384DoFinalize(ctx);
}

std::string Sha384HexDigest(SHA384_CTX* ctx) {
    if (!ctx->finalized) Sha384DoFinalize(ctx);
    // 生成十六进制摘要（取前384位，即前6个64位字）
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < 6; ++i) {
        for (int j = 7; j >= 0; --j) {
            uint8_t byte = static_cast<uint8_t>((ctx->h[i] >> (j * 8)) & 0xFF);
            ss << std::setw(2) << static_cast<unsigned>(byte);
        }
    }
    return ss.str();
}

std::wstring Sha384HexDigestW(SHA384_CTX* ctx) {
    if (!ctx->finalized) Sha384DoFinalize(ctx);
    // 生成十六进制摘要（取前384位，即前6个64位字）
    std::wstringstream ss;
    ss << std::hex << std::setfill(L'0');
    for (int i = 0; i < 6; ++i) {
        for (int j = 7; j >= 0; --j) {
            uint8_t byte = static_cast<uint8_t>((ctx->h[i] >> (j * 8)) & 0xFF);
            ss << std::setw(2) << static_cast<unsigned>(byte);
        }
    }
    return ss.str();
}

std::vector<uint8_t> Sha384Digest(SHA384_CTX* ctx) {
    if (!ctx->finalized) Sha384DoFinalize(ctx);
    // 获取十六进制摘要
    std::string hex = Sha384HexDigest(ctx);

    // 转换为二进制数据
    std::vector<uint8_t> bin;
    bin.reserve(48); // SHA-384产生48字节摘要

    for (size_t i = 0; i < hex.length(); i += 2) {
        unsigned int byte;
        std::stringstream ss;
        ss << std::hex << hex.substr(i, 2);
        ss >> byte;
        bin.push_back(static_cast<uint8_t>(byte));
    }

    return bin;
}

void Sha384Reset(SHA384_CTX* ctx) {
    ctx->h[0] = 0xcbbb9d5dc1059ed8;
    ctx->h[1] = 0x629a292a367cd507;
    ctx->h[2] = 0x9159015a3070dd17;
    ctx->h[3] = 0x152fecd8f70e5939;
    ctx->h[4] = 0x67332667ffc00b31;
    ctx->h[5] = 0x8eb44a8768581511;
    ctx->h[6] = 0xdb0c2e0d64f98fa7;
    ctx->h[7] = 0x47b5481dbefa4fa4;

    ctx->length = 0;
    ctx->buffer_size = 0;
    ctx->finalized = false;
}

// ================= SHA512 =================
const uint64_t sha512_K[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

inline uint64_t sha512_ROTR(uint64_t x, uint64_t n) {
    return (x >> n) | (x << (64 - n));
}

inline uint64_t sha512_Ch(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (~x & z);
}

inline uint64_t sha512_Maj(uint64_t x, uint64_t y, uint64_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint64_t sha512_Sigma0(uint64_t x) {
    return sha512_ROTR(x, 28) ^ sha512_ROTR(x, 34) ^ sha512_ROTR(x, 39);
}

inline uint64_t sha512_Sigma1(uint64_t x) {
    return sha512_ROTR(x, 14) ^ sha512_ROTR(x, 18) ^ sha512_ROTR(x, 41);
}

inline uint64_t sha512_sigma0(uint64_t x) {
    return sha512_ROTR(x, 1) ^ sha512_ROTR(x, 8) ^ (x >> 7);
}

inline uint64_t sha512_sigma1(uint64_t x) {
    return sha512_ROTR(x, 19) ^ sha512_ROTR(x, 61) ^ (x >> 6);
}

void Sha512ProcessBlock(SHA512_CTX* ctx, const uint8_t* block) {
    uint64_t w[80] = { 0 };
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 8; j++) {
            w[i] = (w[i] << 8) | static_cast<uint64_t>(block[i * 8 + j]);
        }
    }
    for (int i = 16; i < 80; i++) {
        w[i] = sha512_sigma1(w[i - 2]) + w[i - 7] + sha512_sigma0(w[i - 15]) + w[i - 16];
    }
    uint64_t a = ctx->h[0], b = ctx->h[1], c = ctx->h[2], d = ctx->h[3];
    uint64_t e = ctx->h[4], f = ctx->h[5], g = ctx->h[6], h_val = ctx->h[7];
    for (int i = 0; i < 80; i++) {
        uint64_t T1 = h_val + sha512_Sigma1(e) + sha512_Ch(e, f, g) + sha512_K[i] + w[i];
        uint64_t T2 = sha512_Sigma0(a) + sha512_Maj(a, b, c);
        h_val = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;
    }
    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d; ctx->h[4] += e; ctx->h[5] += f; ctx->h[6] += g; ctx->h[7] += h_val;
}

void Sha512Init(SHA512_CTX* ctx) {
    ctx->h[0] = 0x6a09e667f3bcc908;
    ctx->h[1] = 0xbb67ae8584caa73b;
    ctx->h[2] = 0x3c6ef372fe94f82b;
    ctx->h[3] = 0xa54ff53a5f1d36f1;
    ctx->h[4] = 0x510e527fade682d1;
    ctx->h[5] = 0x9b05688c2b3e6c1f;
    ctx->h[6] = 0x1f83d9abfb41bd6b;
    ctx->h[7] = 0x5be0cd19137e2179;
    ctx->total_bytes[0] = 0;
    ctx->total_bytes[1] = 0;
    ctx->buffer.clear();
    ctx->finalized = false;
}

void Sha512Update(SHA512_CTX* ctx, const void* data, size_t len) {
    if (ctx->finalized) {
        throw std::runtime_error("SHA512: cannot update after finalization");
    }
    const uint8_t* d = static_cast<const uint8_t*>(data);
    size_t index = 0;
    uint64_t prev_total = ctx->total_bytes[1];
    ctx->total_bytes[1] += static_cast<uint64_t>(len);
    if (ctx->total_bytes[1] < prev_total) {
        ctx->total_bytes[0]++;
    }
    if (!ctx->buffer.empty()) {
        size_t remaining = 128 - ctx->buffer.size();
        if (len < remaining) {
            ctx->buffer.insert(ctx->buffer.end(), d, d + len);
            return;
        }
        ctx->buffer.insert(ctx->buffer.end(), d, d + remaining);
        Sha512ProcessBlock(ctx, ctx->buffer.data());
        index = remaining;
        len -= remaining;
        ctx->buffer.clear();
    }
    while (len - index >= 128) {
        Sha512ProcessBlock(ctx, d + index);
        index += 128;
    }
    if (index < len) {
        ctx->buffer.insert(ctx->buffer.end(), d + index, d + len);
    }
}

void Sha512Update(SHA512_CTX* ctx, const std::string& data) {
    Sha512Update(ctx, data.data(), data.size());
}

void Sha512Update(SHA512_CTX* ctx, const std::vector<uint8_t>& data) {
    Sha512Update(ctx, data.data(), data.size());
}

void Sha512DoFinalize(SHA512_CTX* ctx) {
    if (ctx->finalized) return;
    uint64_t total_bits_low = ctx->total_bytes[1] << 3;
    uint64_t total_bits_high = (ctx->total_bytes[0] << 3) | (ctx->total_bytes[1] >> 61);
    ctx->buffer.push_back(0x80);
    size_t orig_size = ctx->buffer.size();
    size_t padding_len = (orig_size % 128 < 112) ? (112 - orig_size % 128) : (240 - orig_size % 128);
    ctx->buffer.insert(ctx->buffer.end(), padding_len, 0);
    for (int i = 7; i >= 0; --i) {
        ctx->buffer.push_back(static_cast<uint8_t>((total_bits_high >> (i * 8)) & 0xFF));
    }
    for (int i = 7; i >= 0; --i) {
        ctx->buffer.push_back(static_cast<uint8_t>((total_bits_low >> (i * 8)) & 0xFF));
    }
    size_t i = 0;
    while (i + 128 <= ctx->buffer.size()) {
        Sha512ProcessBlock(ctx, &ctx->buffer[i]);
        i += 128;
    }
    ctx->finalized = true;
    ctx->buffer.clear();
}

void Sha512Finalize(SHA512_CTX* ctx) {
    if (!ctx->finalized) Sha512DoFinalize(ctx);
}

std::vector<uint8_t> Sha512Digest(SHA512_CTX* ctx) {
    if (!ctx->finalized) Sha512DoFinalize(ctx);
    std::vector<uint8_t> result(64);
    for (int i = 0; i < 8; i++) {
        for (int j = 7; j >= 0; j--) {
            result[i * 8 + (7 - j)] = static_cast<uint8_t>((ctx->h[i] >> (j * 8)) & 0xFF);
        }
    }
    return result;
}

std::string Sha512HexDigest(SHA512_CTX* ctx) {
    std::vector<uint8_t> bin_digest = Sha512Digest(ctx);
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : bin_digest) {
        oss << std::setw(2) << static_cast<unsigned>(b);
    }
    return oss.str();
}

std::wstring Sha512HexDigestW(SHA512_CTX* ctx) {
    std::vector<uint8_t> bin_digest = Sha512Digest(ctx);
    std::wostringstream oss;
    oss << std::hex << std::setfill(L'0');
    for (uint8_t b : bin_digest) {
        oss << std::setw(2) << static_cast<unsigned>(b);
    }
    return oss.str();
}

void Sha512Reset(SHA512_CTX* ctx) {
    ctx->h[0] = 0x6a09e667f3bcc908;
    ctx->h[1] = 0xbb67ae8584caa73b;
    ctx->h[2] = 0x3c6ef372fe94f82b;
    ctx->h[3] = 0xa54ff53a5f1d36f1;
    ctx->h[4] = 0x510e527fade682d1;
    ctx->h[5] = 0x9b05688c2b3e6c1f;
    ctx->h[6] = 0x1f83d9abfb41bd6b;
    ctx->h[7] = 0x5be0cd19137e2179;
    ctx->total_bytes[0] = 0;
    ctx->total_bytes[1] = 0;
    ctx->buffer.clear();
    ctx->finalized = false;
}