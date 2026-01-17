// smart.cpp
// Copyright (c) 2025 金煜力
// 用户操作自动化算法

#include "smart.h"
#include <string>
#include <cwchar>
#include <vector>
#include <Windows.h>
#include <algorithm>

// 字符串是否以一个字符串开头
bool str_endwith(std::wstring str, std::wstring end, bool ig) {
    int src_len = str.length();
    int end_len = end.length();
    if (src_len < end_len) return false;
    std::wstring temp = str.substr(src_len - end_len, end_len);
    if (ig) {
        std::transform(temp.begin(), temp.end(), temp.begin(), ::towlower);
        std::transform(end.begin(), end.end(), end.begin(), ::towlower);
    }
    return temp == end;
}

// 字符串是否以一个字符串结束
bool str_beginwith(std::wstring str, std::wstring begin, bool ig) {
    int begin_len = begin.length();
    if (str.length() < begin_len) return false;
    std::wstring temp = str.substr(0, begin_len);
    if (ig) {
        std::transform(temp.begin(), temp.end(), temp.begin(), ::towlower);
        std::transform(begin.begin(), begin.end(), begin.begin(), ::towlower);
    }
    return temp == begin;
}

// 去除最后一个后缀名
std::wstring removeLastExtName(const std::wstring& filename) {
    size_t pos = filename.find_last_of(L'.');
    if (pos == std::wstring::npos) {
        return filename;
    }
    return filename.substr(0, pos);
}

// 提取文件名
std::wstring getFileNameFromPath(const std::wstring& filePath) {
    size_t pos = filePath.find_last_of(L"/\\");
    if (pos != std::wstring::npos) {
        return filePath.substr(pos + 1);
    }
    return filePath;
}

// 提取所在目录
std::wstring getFileDirectory(const std::wstring& filepath) {
    std::size_t pos = filepath.find_last_of(L"/\\");
    if (pos != std::wstring::npos) {
        return filepath.substr(0, pos + 1);
    }
    else {
        return L"";
    }
}

// 枚举目录文件（宽字符版本）
std::vector<std::wstring> EnumDirFile(const std::wstring& path, const std::wstring& filter) {
    std::vector<std::wstring> files;
    std::wstring searchPath = path;
    if (!searchPath.empty() && searchPath.back() != L'\\' && searchPath.back() != L'/') {
        searchPath += L"\\";
    }
    searchPath += filter;

    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return files; // 返回空向量
    }

    do {
        // 跳过目录和特殊文件
        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            std::wstring fileName = findData.cFileName;
            if (fileName != L"." && fileName != L"..") {
                // 构建完整路径
                std::wstring fullPath = path;
                if (!fullPath.empty() && fullPath.back() != L'\\' && fullPath.back() != L'/') {
                    fullPath += L"\\";
                }
                fullPath += fileName;
                files.push_back(fullPath);
            }
        }
    } while (FindNextFileW(hFind, &findData) != 0);

    FindClose(hFind);

    // 对结果进行排序
    std::sort(files.begin(), files.end());

    return files;
}

// 判断是否使用了通配符
bool IsPathUsingFilter(const std::wstring& path)
{
    return std::find_if(path.begin(), path.end(), [](wchar_t c) {
        return c == L'*' || c == L'?';
        }) != path.end();
}
