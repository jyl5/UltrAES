// hash.h
// Copyright (c) 2025 金煜力
// CRC32 & MD5 & SHA 哈希校验和计算

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <array>

// ================= CRC32 =================
typedef struct {
    uint32_t crc;
} CRC32_CTX;

void Crc32Init(CRC32_CTX* ctx);
void Crc32Update(CRC32_CTX* ctx, const void* data, size_t length);
void Crc32Update(CRC32_CTX* ctx, const std::string& str);
void Crc32Update(CRC32_CTX* ctx, const std::vector<uint8_t>& data);
std::string Crc32HexDigest(CRC32_CTX* ctx);
std::wstring Crc32HexDigestW(CRC32_CTX* ctx);
uint32_t Crc32Digest(CRC32_CTX* ctx);
void Crc32Reset(CRC32_CTX* ctx);

// ================= MD5 =================
typedef struct {
    uint32_t A, B, C, D;
    uint64_t total_bytes;
    std::vector<uint8_t> buffer;
    bool finished;
    std::array<uint8_t, 16> digest_result;
} MD5_CTX;

void Md5Init(MD5_CTX* ctx);
void Md5Update(MD5_CTX* ctx, const void* data, size_t length);
void Md5Update(MD5_CTX* ctx, const std::string& data);
void Md5Update(MD5_CTX* ctx, const std::vector<uint8_t>& data);
void Md5Finalize(MD5_CTX* ctx);
std::string Md5Digest(MD5_CTX* ctx);
std::string Md5HexDigest(MD5_CTX* ctx);
std::wstring Md5HexDigestW(MD5_CTX* ctx);
void Md5Reset(MD5_CTX* ctx);

// ================= SHA1 =================
typedef struct {
    uint32_t h0, h1, h2, h3, h4;
    uint64_t total_bytes;
    std::vector<uint8_t> buffer;
    bool finished;
    std::array<uint8_t, 20> digest_result;
} SHA1_CTX;

void Sha1Init(SHA1_CTX* ctx);
void Sha1Update(SHA1_CTX* ctx, const void* data, size_t length);
void Sha1Update(SHA1_CTX* ctx, const std::string& data);
void Sha1Update(SHA1_CTX* ctx, const std::vector<uint8_t>& data);
void Sha1Finalize(SHA1_CTX* ctx);
std::string Sha1Digest(SHA1_CTX* ctx);
std::string Sha1HexDigest(SHA1_CTX* ctx);
std::wstring Sha1HexDigestW(SHA1_CTX* ctx);
void Sha1Reset(SHA1_CTX* ctx);

// ================= SHA256 =================
typedef struct {
    uint64_t total_bytes;
    std::vector<uint8_t> buffer;
    uint32_t h[8];
    bool finalized;
} SHA256_CTX;

void Sha256Init(SHA256_CTX* ctx);
void Sha256Update(SHA256_CTX* ctx, const void* data, size_t len);
void Sha256Update(SHA256_CTX* ctx, const std::string& data);
void Sha256Update(SHA256_CTX* ctx, const std::vector<uint8_t>& data);
void Sha256Finalize(SHA256_CTX* ctx);
std::vector<uint8_t> Sha256Digest(SHA256_CTX* ctx);
std::string Sha256HexDigest(SHA256_CTX* ctx);
std::wstring Sha256HexDigestW(SHA256_CTX* ctx);
void Sha256Reset(SHA256_CTX* ctx);

// ================= SHA384 =================
typedef struct {
    uint64_t h[8];
    uint64_t length;
    uint8_t buffer[128];
    size_t buffer_size;
    bool finalized;
} SHA384_CTX;

void Sha384Init(SHA384_CTX* ctx);
void Sha384Update(SHA384_CTX* ctx, const void* data, size_t size);
void Sha384Update(SHA384_CTX* ctx, const std::vector<uint8_t>& data);
void Sha384Update(SHA384_CTX* ctx, const std::string& data);
void Sha384Finalize(SHA384_CTX* ctx);
std::string Sha384HexDigest(SHA384_CTX* ctx);
std::wstring Sha384HexDigestW(SHA384_CTX* ctx);
std::vector<uint8_t> Sha384Digest(SHA384_CTX* ctx);
void Sha384Reset(SHA384_CTX* ctx);

// ================= SHA512 =================
typedef struct {
    uint64_t total_bytes[2];
    std::vector<uint8_t> buffer;
    uint64_t h[8];
    bool finalized;
} SHA512_CTX;

void Sha512Init(SHA512_CTX* ctx);
void Sha512Update(SHA512_CTX* ctx, const void* data, size_t len);
void Sha512Update(SHA512_CTX* ctx, const std::string& data);
void Sha512Update(SHA512_CTX* ctx, const std::vector<uint8_t>& data);
void Sha512Finalize(SHA512_CTX* ctx);
std::vector<uint8_t> Sha512Digest(SHA512_CTX* ctx);
std::string Sha512HexDigest(SHA512_CTX* ctx);
std::wstring Sha512HexDigestW(SHA512_CTX* ctx);
void Sha512Reset(SHA512_CTX* ctx);