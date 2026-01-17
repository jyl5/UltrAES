// smart.h
// Copyright (c) 2025 金煜力
// 用户操作自动化算法

#pragma once

#include <string>
#include <vector>

// 字符串是否以一个字符串开头
bool str_beginwith(std::wstring str, std::wstring begin, bool ig);
// 字符串是否以一个字符串结尾
bool str_endwith(std::wstring str, std::wstring end, bool ig);
// 去除最后一个后缀名
std::wstring removeLastExtName(const std::wstring& filename);
// 提取文件名
std::wstring getFileNameFromPath(const std::wstring& filePath);
// 提取所在目录
std::wstring getFileDirectory(const std::wstring& filepath);
// 枚举目录文件
std::vector<std::wstring> EnumDirFile(const std::wstring& path, const std::wstring& filter);
// 判断是否使用了通配符
bool IsPathUsingFilter(const std::wstring& path);
