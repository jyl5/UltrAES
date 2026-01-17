// inifile.cpp
// Copyright (c) 2025 金煜力
// INI配置文件读写

#include "inifile.h"
#include <map>
#include <string>
#include <vector>
#include <cctype>
#include <memory>
#include <fstream>
#include <sstream>
#include <cstring>
#include <cstdarg>
#include <cstdlib>
#include <iostream>
#include <algorithm>
#include <unordered_map>

// 默认字符串列表容量
#define DEFAULT_STRING_LIST_CAPACITY 16

// INI条目结构
struct INIEntry {
    std::string value;
    std::string comment;
    int32_t line_number;  // 记录行号用于保持顺序

    INIEntry() : line_number(0) {}
    INIEntry(const std::string& val, const std::string& com = "", int32_t line = 0)
        : value(val), comment(com), line_number(line) {
    }
};

// INI节结构
struct INISection {
    std::map<std::string, INIEntry> entries;
    std::string comment;
    int32_t line_number;  // 记录行号用于保持顺序
    std::vector<std::string> entry_order;  // 保持插入顺序

    INISection() : line_number(0) {}
    INISection(const std::string& com, int32_t line = 0)
        : comment(com), line_number(line) {
    }
};

// INI上下文实现
struct INIFILE_CTX {
    std::map<std::string, INISection> sections;
    std::string last_error;
    std::string default_section;  // 默认节名

    // 配置选项
    bool case_sensitive;
    bool allow_duplicate_keys;
    bool allow_empty_values;

    // 解析状态
    int32_t total_lines;

    // 构造函数
    INIFILE_CTX()
        : case_sensitive(false)
        , allow_duplicate_keys(false)
        , allow_empty_values(true)
        , total_lines(0)
        , default_section("") {
    }
};

// 辅助函数：安全复制字符串
static char* safe_strdup(const char* str) {
    if (!str) return nullptr;
    size_t len = strlen(str);
    char* result = new char[len + 1];
    if (result) {
        strncpy_s(result, len + 1, str, len);
        result[len] = '\0';
    }
    return result;
}

// 辅助函数：安全复制字符串到缓冲区
static size_t safe_strcpy(char* dest, const char* src, size_t dest_size) {
    if (!dest || !src || dest_size == 0) return 0;

    // 计算源字符串长度
    size_t src_len = 0;
    const char* p = src;
    while (*p && src_len < dest_size) {
        src_len++;
        p++;
    }
    
    errno_t err = strncpy_s(dest, dest_size, src, src_len);

    if (err == 0) {
        // 成功，返回实际拷贝的字符数（不包括空字符）
        size_t copy_len = 0;
        while (copy_len < dest_size && dest[copy_len] != '\0') {
            copy_len++;
        }
        return copy_len;
    }
    else {
        // 发生错误，返回0
        return 0;
    }
}

// 辅助函数：初始化字符串列表
static void init_string_list(INI_STRING_LIST* list) {
    if (!list) return;

    list->strings = nullptr;
    list->count = 0;
    list->capacity = 0;
}

// 辅助函数：确保字符串列表有足够容量
static bool ensure_string_list_capacity(INI_STRING_LIST* list, int32_t min_capacity) {
    if (!list) return false;

    if (min_capacity <= list->capacity) {
        return true;
    }

    // 计算新容量（以2的幂增长）
    int32_t new_capacity = list->capacity == 0 ? DEFAULT_STRING_LIST_CAPACITY : list->capacity;
    while (new_capacity < min_capacity) {
        new_capacity *= 2;
        // 防止溢出
        if (new_capacity < 0 || new_capacity > 1000000) {
            return false;
        }
    }

    char** new_strings = new char* [new_capacity];
    if (!new_strings) {
        return false;
    }

    // 复制现有字符串指针
    if (list->strings) {
        for (int32_t i = 0; i < list->count && i < new_capacity; i++) {
            new_strings[i] = list->strings[i];
        }
        delete[] list->strings;
    }

    // 初始化新分配的空间
    for (int32_t i = list->count; i < new_capacity; i++) {
        new_strings[i] = nullptr;
    }

    list->strings = new_strings;
    list->capacity = new_capacity;

    return true;
}

// 辅助函数：向字符串列表添加字符串
static bool add_to_string_list(INI_STRING_LIST* list, const char* str) {
    if (!list || !str) return false;

    if (!ensure_string_list_capacity(list, list->count + 1)) {
        return false;
    }

    list->strings[list->count] = safe_strdup(str);
    if (!list->strings[list->count]) {
        return false;
    }

    list->count++;
    return true;
}

// 辅助函数：修剪字符串两端的空白字符
static std::string trim(const std::string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, (last - first + 1));
}

// 辅助函数：转换为小写（用于大小写不敏感的比较）
static std::string to_lower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(),
        [](unsigned char c) { return std::tolower(c); });
    return result;
}

// 辅助函数：转换为标准键名（根据大小写敏感性）
static std::string normalize_key(const std::string& key, bool case_sensitive) {
    if (case_sensitive) {
        return key;
    }
    else {
        return to_lower(key);
    }
}

// 内部错误设置函数
static void set_error(INIFILE_CTX* ctx, const char* format, ...) {
    if (!ctx) return;

    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    ctx->last_error = buffer;
}

// 创建INI解析器上下文
INIFILE_CTX* ini_create_ctx() {
    try {
        return new INIFILE_CTX();
    }
    catch (const std::exception& e) {
        return nullptr;
    }
}

// 释放INI解析器上下文
void ini_free_ctx(INIFILE_CTX* ctx) {
    if (ctx) {
        delete ctx;
    }
}

// 获取错误信息
const char* ini_get_error(INIFILE_CTX* ctx) {
    if (!ctx) return "Invalid context";
    return ctx->last_error.c_str();
}

// 设置是否区分大小写
void ini_set_case_sensitive(INIFILE_CTX* ctx, bool case_sensitive) {
    if (ctx) {
        ctx->case_sensitive = case_sensitive;
    }
}

// 设置是否允许重复键
void ini_set_allow_duplicate_keys(INIFILE_CTX* ctx, bool allow) {
    if (ctx) {
        ctx->allow_duplicate_keys = allow;
    }
}

// 设置是否允许空值
void ini_set_allow_empty_values(INIFILE_CTX* ctx, bool allow) {
    if (ctx) {
        ctx->allow_empty_values = allow;
    }
}

// 设置默认节名
void ini_set_default_section(INIFILE_CTX* ctx, const char* default_section) {
    if (ctx && default_section) {
        ctx->default_section = default_section;
    }
}

// 解析一行INI内容
static bool parse_line(INIFILE_CTX* ctx, const std::string& line,
    int32_t line_number, std::string& section,
    std::string& key, std::string& value,
    std::string& comment) {
    std::string trimmed = trim(line);

    // 空行
    if (trimmed.empty()) {
        return false;
    }

    // 注释行
    if (trimmed[0] == ';' || trimmed[0] == '#') {
        if (trimmed.length() > 1) {
            comment = trim(trimmed.substr(1));
        }
        return false;
    }

    // 解析节
    if (trimmed[0] == '[') {
        size_t end = trimmed.find(']');
        if (end == std::string::npos) {
            set_error(ctx, "Line %d: missing ']' in section declaration", line_number);
            return false;
        }

        section = trim(trimmed.substr(1, end - 1));
        if (section.empty()) {
            set_error(ctx, "Line %d: empty section name", line_number);
            return false;
        }

        // 检查节名后的注释
        if (end + 1 < trimmed.length()) {
            std::string rest = trimmed.substr(end + 1);
            size_t comment_pos = rest.find_first_of(";#");
            if (comment_pos != std::string::npos) {
                comment = trim(rest.substr(comment_pos + 1));
            }
        }

        return false;  // 节声明不是键值对
    }

    // 解析键值对
    size_t equals_pos = trimmed.find('=');
    if (equals_pos == std::string::npos) {
        set_error(ctx, "Line %d: missing '=' in key-value pair", line_number);
        return false;
    }

    key = trim(trimmed.substr(0, equals_pos));
    if (key.empty()) {
        set_error(ctx, "Line %d: empty key name", line_number);
        return false;
    }

    std::string value_part = trimmed.substr(equals_pos + 1);

    // 分离值和注释
    bool in_quotes = false;
    size_t comment_pos = std::string::npos;

    for (size_t i = 0; i < value_part.length(); i++) {
        char c = value_part[i];
        if (c == '"') {
            in_quotes = !in_quotes;
        }
        else if (!in_quotes && (c == ';' || c == '#')) {
            comment_pos = i;
            break;
        }
    }

    if (comment_pos != std::string::npos) {
        value = trim(value_part.substr(0, comment_pos));
        comment = trim(value_part.substr(comment_pos + 1));
    }
    else {
        value = trim(value_part);
    }

    // 处理引号
    if (value.length() >= 2 && value[0] == '"' && value[value.length() - 1] == '"') {
        value = value.substr(1, value.length() - 2);
    }

    return true;
}

// 从内存加载INI配置
INI_ERROR_CODE ini_load_from_memory(INIFILE_CTX* ctx, const char* data, size_t size) {
    if (!ctx) return INI_ERROR_INVALID_CONTEXT;
    if (!data || size == 0) return INI_ERROR_INVALID_PARAMETER;

    try {
        std::string content(data, size);
        return ini_load_from_string(ctx, content.c_str());
    }
    catch (const std::exception& e) {
        set_error(ctx, "Exception: %s", e.what());
        return INI_ERROR_MEMORY_ALLOCATION;
    }
}

// 从字符串加载INI配置
INI_ERROR_CODE ini_load_from_string(INIFILE_CTX* ctx, const char* str) {
    if (!ctx) return INI_ERROR_INVALID_CONTEXT;
    if (!str) return INI_ERROR_INVALID_PARAMETER;

    ctx->sections.clear();
    ctx->last_error.clear();
    ctx->total_lines = 0;

    std::istringstream stream(str);
    std::string line;
    int32_t line_number = 0;
    std::string current_section = ctx->default_section;

    while (std::getline(stream, line)) {
        line_number++;
        ctx->total_lines++;

        std::string section, key, value, comment;
        bool is_key_value = parse_line(ctx, line, line_number, section, key, value, comment);

        if (!ctx->last_error.empty()) {
            return INI_ERROR_SYNTAX;
        }

        if (!section.empty()) {
            current_section = section;

            // 检查节是否已存在
            std::string norm_section = normalize_key(current_section, ctx->case_sensitive);
            if (ctx->sections.find(norm_section) != ctx->sections.end()) {
                // 节已存在，合并注释
                if (!comment.empty()) {
                    ctx->sections[norm_section].comment = comment;
                }
            }
            else {
                // 创建新节
                INISection new_section(comment, line_number);
                ctx->sections[norm_section] = new_section;
            }
        }
        else if (is_key_value) {
            if (key.empty()) {
                set_error(ctx, "Line %d: empty key name", line_number);
                return INI_ERROR_SYNTAX;
            }

            std::string norm_section = normalize_key(current_section, ctx->case_sensitive);
            std::string norm_key = normalize_key(key, ctx->case_sensitive);

            // 检查键是否已存在
            if (ctx->sections[norm_section].entries.find(norm_key) !=
                ctx->sections[norm_section].entries.end()) {
                if (!ctx->allow_duplicate_keys) {
                    set_error(ctx, "Line %d: duplicate key '%s' in section '%s'",
                        line_number, key.c_str(), current_section.c_str());
                    return INI_ERROR_SYNTAX;
                }
            }

            INIEntry entry(value, comment, line_number);

            ctx->sections[norm_section].entries[norm_key] = entry;
            ctx->sections[norm_section].entry_order.push_back(norm_key);
        }
    }

    return INI_SUCCESS;
}

// 从文件加载INI配置
INI_ERROR_CODE ini_load_from_file(INIFILE_CTX* ctx, const char* filename) {
    if (!ctx) return INI_ERROR_INVALID_CONTEXT;
    if (!filename) return INI_ERROR_INVALID_PARAMETER;

    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        set_error(ctx, "Cannot open file: %s", filename);
        return INI_ERROR_FILE_NOT_FOUND;
    }

    try {
        // 获取文件大小
        file.seekg(0, std::ios::end);
        size_t file_size = static_cast<size_t>(file.tellg());
        file.seekg(0, std::ios::beg);

        // 读取文件内容
        std::vector<char> buffer(file_size + 1);
        if (file_size > 0) {
            file.read(buffer.data(), file_size);
        }
        buffer[file_size] = '\0';

        file.close();

        return ini_load_from_memory(ctx, buffer.data(), file_size);
    }
    catch (const std::exception& e) {
        set_error(ctx, "Exception while reading file: %s", e.what());
        return INI_ERROR_IO_ERROR;
    }
}

// 获取字符串值
const char* ini_get_string(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    const char* default_value) {
    if (!ctx || !key) {
        return default_value;
    }

    try {
        std::string section_str = section ? section : ctx->default_section;
        std::string key_str = key;

        std::string norm_section = normalize_key(section_str, ctx->case_sensitive);
        std::string norm_key = normalize_key(key_str, ctx->case_sensitive);

        auto section_it = ctx->sections.find(norm_section);
        if (section_it != ctx->sections.end()) {
            auto it = section_it->second.entries.find(norm_key);
            if (it != section_it->second.entries.end()) {
                return it->second.value.c_str();
            }
        }
    }
    catch (const std::exception& e) {
        set_error(ctx, "Exception: %s", e.what());
    }

    return default_value;
}

// 获取整数值
int32_t ini_get_int(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    int32_t default_value) {
    const char* str_value = ini_get_string(ctx, section, key, nullptr);
    if (!str_value) return default_value;

    try {
        return static_cast<int32_t>(std::stoi(str_value));
    }
    catch (const std::exception&) {
        return default_value;
    }
}

// 获取长整数值
int64_t ini_get_long(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    int64_t default_value) {
    const char* str_value = ini_get_string(ctx, section, key, nullptr);
    if (!str_value) return default_value;

    try {
        return std::stoll(str_value);
    }
    catch (const std::exception&) {
        return default_value;
    }
}

// 获取布尔值
bool ini_get_bool(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    bool default_value) {
    const char* str_value = ini_get_string(ctx, section, key, nullptr);
    if (!str_value) return default_value;

    std::string value = to_lower(str_value);
    if (value == "true" || value == "yes" || value == "on" || value == "1" || value == "enable") {
        return true;
    }
    else if (value == "false" || value == "no" || value == "off" || value == "0" || value == "disable") {
        return false;
    }

    return default_value;
}

// 获取浮点数值
float ini_get_float(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    float default_value) {
    const char* str_value = ini_get_string(ctx, section, key, nullptr);
    if (!str_value) return default_value;

    try {
        return std::stof(str_value);
    }
    catch (const std::exception&) {
        return default_value;
    }
}

// 获取双精度浮点数值
double ini_get_double(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    double default_value) {
    const char* str_value = ini_get_string(ctx, section, key, nullptr);
    if (!str_value) return default_value;

    try {
        return std::stod(str_value);
    }
    catch (const std::exception&) {
        return default_value;
    }
}

// 检查节是否存在
bool ini_has_section(INIFILE_CTX* ctx, const char* section) {
    if (!ctx || !section) return false;

    std::string section_str = section;
    std::string norm_section = normalize_key(section_str, ctx->case_sensitive);

    return ctx->sections.find(norm_section) != ctx->sections.end();
}

// 检查键是否存在
bool ini_has_key(INIFILE_CTX* ctx, const char* section, const char* key) {
    if (!ctx || !key) return false;

    std::string section_str = section ? section : ctx->default_section;
    std::string key_str = key;

    std::string norm_section = normalize_key(section_str, ctx->case_sensitive);
    std::string norm_key = normalize_key(key_str, ctx->case_sensitive);

    auto section_it = ctx->sections.find(norm_section);
    if (section_it != ctx->sections.end()) {
        return section_it->second.entries.find(norm_key) != section_it->second.entries.end();
    }

    return false;
}

// 设置字符串值
INI_ERROR_CODE ini_set_string(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    const char* value) {
    if (!ctx || !key) {
        return INI_ERROR_INVALID_PARAMETER;
    }

    try {
        std::string section_str = section ? section : ctx->default_section;
        std::string key_str = key;
        std::string value_str = value ? value : "";

        if (!ctx->allow_empty_values && value_str.empty()) {
            return INI_ERROR_INVALID_PARAMETER;
        }

        std::string norm_section = normalize_key(section_str, ctx->case_sensitive);
        std::string norm_key = normalize_key(key_str, ctx->case_sensitive);

        // 确保节存在
        if (ctx->sections.find(norm_section) == ctx->sections.end()) {
            INISection new_section;
            ctx->sections[norm_section] = new_section;
        }

        // 检查键是否已存在
        if (ctx->sections[norm_section].entries.find(norm_key) ==
            ctx->sections[norm_section].entries.end()) {
            // 新键，添加到顺序列表
            ctx->sections[norm_section].entry_order.push_back(norm_key);
        }

        INIEntry entry(value_str, "", -1);  // -1 表示由代码设置，而不是从文件解析
        ctx->sections[norm_section].entries[norm_key] = entry;

        return INI_SUCCESS;
    }
    catch (const std::exception& e) {
        set_error(ctx, "Exception: %s", e.what());
        return INI_ERROR_MEMORY_ALLOCATION;
    }
}

// 设置整数值
INI_ERROR_CODE ini_set_int(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    int32_t value) {
    try {
        std::string str_value = std::to_string(value);
        return ini_set_string(ctx, section, key, str_value.c_str());
    }
    catch (const std::exception& e) {
        set_error(ctx, "Exception: %s", e.what());
        return INI_ERROR_MEMORY_ALLOCATION;
    }
}

// 设置长整数值
INI_ERROR_CODE ini_set_long(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    int64_t value) {
    try {
        std::string str_value = std::to_string(value);
        return ini_set_string(ctx, section, key, str_value.c_str());
    }
    catch (const std::exception& e) {
        set_error(ctx, "Exception: %s", e.what());
        return INI_ERROR_MEMORY_ALLOCATION;
    }
}

// 设置布尔值
INI_ERROR_CODE ini_set_bool(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    bool value) {
    const char* str_value = value ? "true" : "false";
    return ini_set_string(ctx, section, key, str_value);
}

// 设置浮点数值
INI_ERROR_CODE ini_set_float(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    float value) {
    try {
        std::string str_value = std::to_string(value);
        return ini_set_string(ctx, section, key, str_value.c_str());
    }
    catch (const std::exception& e) {
        set_error(ctx, "Exception: %s", e.what());
        return INI_ERROR_MEMORY_ALLOCATION;
    }
}

// 设置双精度浮点数值
INI_ERROR_CODE ini_set_double(INIFILE_CTX* ctx,
    const char* section,
    const char* key,
    double value) {
    try {
        std::string str_value = std::to_string(value);
        return ini_set_string(ctx, section, key, str_value.c_str());
    }
    catch (const std::exception& e) {
        set_error(ctx, "Exception: %s", e.what());
        return INI_ERROR_MEMORY_ALLOCATION;
    }
}

// 删除键
INI_ERROR_CODE ini_delete_key(INIFILE_CTX* ctx,
    const char* section,
    const char* key) {
    if (!ctx || !key) {
        return INI_ERROR_INVALID_PARAMETER;
    }

    try {
        std::string section_str = section ? section : ctx->default_section;
        std::string key_str = key;

        std::string norm_section = normalize_key(section_str, ctx->case_sensitive);
        std::string norm_key = normalize_key(key_str, ctx->case_sensitive);

        auto section_it = ctx->sections.find(norm_section);
        if (section_it != ctx->sections.end()) {
            auto it = section_it->second.entries.find(norm_key);
            if (it != section_it->second.entries.end()) {
                section_it->second.entries.erase(it);

                // 从顺序列表中移除
                auto& order = section_it->second.entry_order;
                order.erase(std::remove(order.begin(), order.end(), norm_key), order.end());

                return INI_SUCCESS;
            }
        }

        return INI_ERROR_KEY_NOT_FOUND;
    }
    catch (const std::exception& e) {
        set_error(ctx, "Exception: %s", e.what());
        return INI_ERROR_MEMORY_ALLOCATION;
    }
}

// 删除节
INI_ERROR_CODE ini_delete_section(INIFILE_CTX* ctx, const char* section) {
    if (!ctx || !section) {
        return INI_ERROR_INVALID_PARAMETER;
    }

    try {
        std::string section_str = section;
        std::string norm_section = normalize_key(section_str, ctx->case_sensitive);

        auto it = ctx->sections.find(norm_section);
        if (it != ctx->sections.end()) {
            ctx->sections.erase(it);
            return INI_SUCCESS;
        }

        return INI_ERROR_SECTION_NOT_FOUND;
    }
    catch (const std::exception& e) {
        set_error(ctx, "Exception: %s", e.what());
        return INI_ERROR_MEMORY_ALLOCATION;
    }
}

// 重命名节
INI_ERROR_CODE ini_rename_section(INIFILE_CTX* ctx,
    const char* old_section,
    const char* new_section) {
    if (!ctx || !old_section || !new_section) {
        return INI_ERROR_INVALID_PARAMETER;
    }

    try {
        std::string old_section_str = old_section;
        std::string new_section_str = new_section;

        std::string norm_old_section = normalize_key(old_section_str, ctx->case_sensitive);
        std::string norm_new_section = normalize_key(new_section_str, ctx->case_sensitive);

        if (norm_old_section == norm_new_section) {
            return INI_SUCCESS;  // 新旧节名相同，无需操作
        }

        auto it = ctx->sections.find(norm_old_section);
        if (it == ctx->sections.end()) {
            return INI_ERROR_SECTION_NOT_FOUND;
        }

        if (ctx->sections.find(norm_new_section) != ctx->sections.end()) {
            set_error(ctx, "Section '%s' already exists", new_section);
            return INI_ERROR_INVALID_PARAMETER;
        }

        // 移动节内容
        ctx->sections[norm_new_section] = std::move(it->second);
        ctx->sections.erase(it);

        return INI_SUCCESS;
    }
    catch (const std::exception& e) {
        set_error(ctx, "Exception: %s", e.what());
        return INI_ERROR_MEMORY_ALLOCATION;
    }
}

// 重命名键
INI_ERROR_CODE ini_rename_key(INIFILE_CTX* ctx,
    const char* section,
    const char* old_key,
    const char* new_key) {
    if (!ctx || !old_key || !new_key) {
        return INI_ERROR_INVALID_PARAMETER;
    }

    try {
        std::string section_str = section ? section : ctx->default_section;
        std::string old_key_str = old_key;
        std::string new_key_str = new_key;

        std::string norm_section = normalize_key(section_str, ctx->case_sensitive);
        std::string norm_old_key = normalize_key(old_key_str, ctx->case_sensitive);
        std::string norm_new_key = normalize_key(new_key_str, ctx->case_sensitive);

        if (norm_old_key == norm_new_key) {
            return INI_SUCCESS;  // 新旧键名相同，无需操作
        }

        auto section_it = ctx->sections.find(norm_section);
        if (section_it == ctx->sections.end()) {
            return INI_ERROR_SECTION_NOT_FOUND;
        }

        auto it = section_it->second.entries.find(norm_old_key);
        if (it == section_it->second.entries.end()) {
            return INI_ERROR_KEY_NOT_FOUND;
        }

        if (section_it->second.entries.find(norm_new_key) != section_it->second.entries.end()) {
            set_error(ctx, "Key '%s' already exists in section '%s'", new_key, section);
            return INI_ERROR_INVALID_PARAMETER;
        }

        // 移动键值对
        section_it->second.entries[norm_new_key] = std::move(it->second);
        section_it->second.entries.erase(it);

        // 更新顺序列表
        auto& order = section_it->second.entry_order;
        for (size_t i = 0; i < order.size(); i++) {
            if (order[i] == norm_old_key) {
                order[i] = norm_new_key;
                break;
            }
        }

        return INI_SUCCESS;
    }
    catch (const std::exception& e) {
        set_error(ctx, "Exception: %s", e.what());
        return INI_ERROR_MEMORY_ALLOCATION;
    }
}

// 转换为字符串
char* ini_to_string(INIFILE_CTX* ctx, size_t* output_size) {
    if (!ctx) {
        if (output_size) *output_size = 0;
        return nullptr;
    }

    try {
        std::ostringstream stream;
        bool first_section = true;

        // 处理默认节的条目
        if (!ctx->default_section.empty()) {
            auto section_it = ctx->sections.find(normalize_key(ctx->default_section, ctx->case_sensitive));
            if (section_it != ctx->sections.end()) {
                first_section = false;

                // 节注释
                if (!section_it->second.comment.empty()) {
                    stream << "; " << section_it->second.comment << std::endl;
                }

                // 节声明
                stream << "[" << ctx->default_section << "]" << std::endl;

                // 节内的条目
                for (const auto& key : section_it->second.entry_order) {
                    const auto& entry = section_it->second.entries.at(key);
                    stream << key << " = " << entry.value;
                    if (!entry.comment.empty()) {
                        stream << " ; " << entry.comment;
                    }
                    stream << std::endl;
                }

                stream << std::endl;
            }
        }

        // 保存其他各节的条目
        for (const auto& section_pair : ctx->sections) {
            // 跳过默认节（如果已处理）
            if (!ctx->default_section.empty() &&
                normalize_key(section_pair.first, ctx->case_sensitive) ==
                normalize_key(ctx->default_section, ctx->case_sensitive)) {
                continue;
            }

            if (!first_section) {
                stream << std::endl;
            }
            first_section = false;

            // 节注释
            if (!section_pair.second.comment.empty()) {
                stream << "; " << section_pair.second.comment << std::endl;
            }

            // 节声明
            stream << "[" << section_pair.first << "]" << std::endl;

            // 节内的条目（按照插入顺序）
            for (const auto& key : section_pair.second.entry_order) {
                const auto& entry = section_pair.second.entries.at(key);
                stream << key << " = " << entry.value;
                if (!entry.comment.empty()) {
                    stream << " ; " << entry.comment;
                }
                stream << std::endl;
            }
        }

        std::string result = stream.str();
        size_t len = result.length();
        char* cstr = new char[len + 1];

        safe_strcpy(cstr, result.c_str(), len + 1);

        if (output_size) {
            *output_size = len;
        }

        return cstr;
    }
    catch (const std::exception& e) {
        set_error(ctx, "Exception: %s", e.what());
        if (output_size) *output_size = 0;
        return nullptr;
    }
}

// 保存到文件
INI_ERROR_CODE ini_save_to_file(INIFILE_CTX* ctx, const char* filename) {
    if (!ctx) return INI_ERROR_INVALID_CONTEXT;
    if (!filename) return INI_ERROR_INVALID_PARAMETER;

    try {
        size_t size = 0;
        char* content = ini_to_string(ctx, &size);
        if (!content) {
            return INI_ERROR_MEMORY_ALLOCATION;
        }

        std::ofstream file(filename);
        if (!file.is_open()) {
            ini_free_string(content);
            set_error(ctx, "Cannot open file for writing: %s", filename);
            return INI_ERROR_FILE_NOT_FOUND;
        }

        if (size > 0) {
            file.write(content, size);
        }
        file.close();

        ini_free_string(content);
        return INI_SUCCESS;
    }
    catch (const std::exception& e) {
        set_error(ctx, "Exception: %s", e.what());
        return INI_ERROR_IO_ERROR;
    }
}

// 释放字符串内存
void ini_free_string(char* str) {
    if (str) {
        delete[] str;
    }
}

// 获取节的列表
INI_ERROR_CODE ini_get_sections(INIFILE_CTX* ctx, INI_STRING_LIST* list) {
    if (!ctx || !list) {
        return INI_ERROR_INVALID_PARAMETER;
    }

    init_string_list(list);

    try {
        for (const auto& section : ctx->sections) {
            if (!add_to_string_list(list, section.first.c_str())) {
                ini_free_string_list(list);
                return INI_ERROR_MEMORY_ALLOCATION;
            }
        }

        return INI_SUCCESS;
    }
    catch (const std::exception& e) {
        set_error(ctx, "Exception: %s", e.what());
        ini_free_string_list(list);
        return INI_ERROR_MEMORY_ALLOCATION;
    }
}

// 获取指定节中的所有键
INI_ERROR_CODE ini_get_keys(INIFILE_CTX* ctx, const char* section, INI_STRING_LIST* list) {
    if (!ctx || !list) {
        return INI_ERROR_INVALID_PARAMETER;
    }

    init_string_list(list);

    try {
        std::string section_str = section ? section : ctx->default_section;
        std::string norm_section = normalize_key(section_str, ctx->case_sensitive);

        auto section_it = ctx->sections.find(norm_section);
        if (section_it == ctx->sections.end()) {
            return INI_SUCCESS;  // 返回空列表，不是错误
        }

        for (const auto& key : section_it->second.entry_order) {
            if (!add_to_string_list(list, key.c_str())) {
                ini_free_string_list(list);
                return INI_ERROR_MEMORY_ALLOCATION;
            }
        }

        return INI_SUCCESS;
    }
    catch (const std::exception& e) {
        set_error(ctx, "Exception: %s", e.what());
        ini_free_string_list(list);
        return INI_ERROR_MEMORY_ALLOCATION;
    }
}

// 释放字符串列表
void ini_free_string_list(INI_STRING_LIST* list) {
    if (!list) return;

    if (list->strings) {
        for (int32_t i = 0; i < list->count; i++) {
            if (list->strings[i]) {
                delete[] list->strings[i];
            }
        }
        delete[] list->strings;
    }

    list->strings = nullptr;
    list->count = 0;
    list->capacity = 0;
}

// 清除所有配置
void ini_clear(INIFILE_CTX* ctx) {
    if (!ctx) return;

    ctx->sections.clear();
    ctx->last_error.clear();
    ctx->total_lines = 0;
}

// 合并另一个INI上下文
INI_ERROR_CODE ini_merge(INIFILE_CTX* dest, INIFILE_CTX* src, bool overwrite) {
    if (!dest || !src) {
        return INI_ERROR_INVALID_CONTEXT;
    }

    try {
        for (const auto& src_section : src->sections) {
            for (const auto& src_entry : src_section.second.entries) {
                // 检查目标中是否已存在
                bool exists = false;
                if (dest->sections.find(src_section.first) != dest->sections.end()) {
                    exists = dest->sections[src_section.first].entries.find(src_entry.first) !=
                        dest->sections[src_section.first].entries.end();
                }

                // 如果不存在或允许覆盖，则合并
                if (!exists || overwrite) {
                    // 确保节存在
                    if (dest->sections.find(src_section.first) == dest->sections.end()) {
                        INISection new_section;
                        dest->sections[src_section.first] = new_section;
                    }

                    // 复制条目
                    dest->sections[src_section.first].entries[src_entry.first] = src_entry.second;

                    // 如果键不存在于顺序列表中，添加它
                    auto& order = dest->sections[src_section.first].entry_order;
                    if (std::find(order.begin(), order.end(), src_entry.first) == order.end()) {
                        order.push_back(src_entry.first);
                    }
                }
            }
        }

        return INI_SUCCESS;
    }
    catch (const std::exception& e) {
        set_error(dest, "Exception while merging: %s", e.what());
        return INI_ERROR_MEMORY_ALLOCATION;
    }
}

// 获取配置项数量
int32_t ini_get_section_count(INIFILE_CTX* ctx) {
    if (!ctx) return 0;
    return static_cast<int32_t>(ctx->sections.size());
}

int32_t ini_get_key_count(INIFILE_CTX* ctx, const char* section) {
    if (!ctx || !section) return 0;

    std::string section_str = section;
    std::string norm_section = normalize_key(section_str, ctx->case_sensitive);

    auto it = ctx->sections.find(norm_section);
    if (it != ctx->sections.end()) {
        return static_cast<int32_t>(it->second.entries.size());
    }

    return 0;
}

int32_t ini_get_total_key_count(INIFILE_CTX* ctx) {
    if (!ctx) return 0;

    int32_t total = 0;
    for (const auto& section : ctx->sections) {
        total += static_cast<int32_t>(section.second.entries.size());
    }

    return total;
}