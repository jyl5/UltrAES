// inifile.h
// Copyright (c) 2025 金煜力
// INI配置文件读写

#pragma once

#include <cstddef>
#include <cstdint>

// 前向声明INIFILE_CTX结构体
struct INIFILE_CTX;

// 错误码
enum INI_ERROR_CODE {
    INI_SUCCESS = 0,
    INI_ERROR_FILE_NOT_FOUND,
    INI_ERROR_MEMORY_ALLOCATION,
    INI_ERROR_SYNTAX,
    INI_ERROR_SECTION_NOT_FOUND,
    INI_ERROR_KEY_NOT_FOUND,
    INI_ERROR_INVALID_CONTEXT,
    INI_ERROR_INVALID_PARAMETER,
    INI_ERROR_IO_ERROR,
    INI_ERROR_BUFFER_OVERFLOW
};

// 字符串列表结构
struct INI_STRING_LIST {
    char** strings;
    int32_t count;
    int32_t capacity;
};

// 创建INI解析器上下文
INIFILE_CTX* ini_create_ctx();

// 释放INI解析器上下文
void ini_free_ctx(INIFILE_CTX* ctx);

// 从文件加载INI配置
INI_ERROR_CODE ini_load_from_file(INIFILE_CTX* ctx, const char* filename);

// 从内存字符串加载INI配置
INI_ERROR_CODE ini_load_from_memory(INIFILE_CTX* ctx, const char* data, size_t size);

// 从字符串加载INI配置
INI_ERROR_CODE ini_load_from_string(INIFILE_CTX* ctx, const char* str);

// 获取字符串值
const char* ini_get_string(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    const char* default_value = nullptr);

// 获取整数值
int32_t ini_get_int(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    int32_t default_value = 0);

// 获取长整数值
int64_t ini_get_long(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    int64_t default_value = 0);

// 获取布尔值
bool ini_get_bool(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    bool default_value = false);

// 获取浮点数值
float ini_get_float(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    float default_value = 0.0f);

// 获取双精度浮点数值
double ini_get_double(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    double default_value = 0.0);

// 设置字符串值
INI_ERROR_CODE ini_set_string(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    const char* value);

// 设置整数值
INI_ERROR_CODE ini_set_int(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    int32_t value);

// 设置长整数值
INI_ERROR_CODE ini_set_long(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    int64_t value);

// 设置布尔值
INI_ERROR_CODE ini_set_bool(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    bool value);

// 设置浮点数值
INI_ERROR_CODE ini_set_float(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    float value);

// 设置双精度浮点数值
INI_ERROR_CODE ini_set_double(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    double value);

// 检查节是否存在
bool ini_has_section(INIFILE_CTX* ctx, const char* section);

// 检查键是否存在
bool ini_has_key(INIFILE_CTX* ctx, const char* section, const char* key);

// 删除键
INI_ERROR_CODE ini_delete_key(INIFILE_CTX* ctx,
    const char* section,
    const char* key);

// 删除节
INI_ERROR_CODE ini_delete_section(INIFILE_CTX* ctx, const char* section);

// 重命名节
INI_ERROR_CODE ini_rename_section(INIFILE_CTX* ctx,
    const char* old_section,
    const char* new_section);

// 重命名键
INI_ERROR_CODE ini_rename_key(INIFILE_CTX* ctx,
    const char* section,
    const char* old_key,
    const char* new_key);

// 保存到文件
INI_ERROR_CODE ini_save_to_file(INIFILE_CTX* ctx, const char* filename);

// 转换为字符串
char* ini_to_string(INIFILE_CTX* ctx, size_t* output_size = nullptr);

// 释放字符串内存
void ini_free_string(char* str);

// 获取错误信息
const char* ini_get_error(INIFILE_CTX* ctx);

// 获取节的列表
INI_ERROR_CODE ini_get_sections(INIFILE_CTX* ctx, INI_STRING_LIST* list);

// 获取指定节中的所有键
INI_ERROR_CODE ini_get_keys(INIFILE_CTX* ctx, const char* section, INI_STRING_LIST* list);

// 释放字符串列表
void ini_free_string_list(INI_STRING_LIST* list);

// 清除所有配置
void ini_clear(INIFILE_CTX* ctx);

// 合并另一个INI上下文
INI_ERROR_CODE ini_merge(INIFILE_CTX* dest, INIFILE_CTX* src, bool overwrite = true);

// 获取配置项数量
int32_t ini_get_section_count(INIFILE_CTX* ctx);
int32_t ini_get_key_count(INIFILE_CTX* ctx, const char* section);
int32_t ini_get_total_key_count(INIFILE_CTX* ctx);

// 设置是否区分大小写
void ini_set_case_sensitive(INIFILE_CTX* ctx, bool case_sensitive);

// 设置是否允许重复键
void ini_set_allow_duplicate_keys(INIFILE_CTX* ctx, bool allow);

// 设置是否允许空值
void ini_set_allow_empty_values(INIFILE_CTX* ctx, bool allow);

// 设置默认节名（用于全局键值）
void ini_set_default_section(INIFILE_CTX* ctx, const char* default_section);