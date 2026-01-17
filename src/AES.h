// AES.h
// Copyright (c) 2025 金煜力
// AES-256 (CBC) 加解密

#pragma once

#include <vector>
#include <string>
#include <functional>
#include <cstdint>
#include <atomic>

typedef std::function<void(int)> ProgressCallback;

void aes256_cbc_file(const std::wstring& input_file,
    const std::wstring& output_file,
    const std::vector<uint8_t>& key,
    const std::wstring& mode,
    ProgressCallback progressCallback = nullptr);

std::vector<uint8_t> generate_aes256_key();
std::vector<uint8_t> read_key(const std::wstring& file_path);
bool write_key(const std::wstring& file_path, const std::vector<uint8_t>& data);

// Pause/resume control for long-running file processing
void request_pause();
void resume_processing();
bool is_processing_paused();