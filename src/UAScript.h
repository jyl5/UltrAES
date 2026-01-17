// UAScript.h
// Copyright (c) 2025 金煜力
// UltrAES脚本

#pragma once

#include <string>
#include <vector>
#include <Windows.h>

// 错误码
#define UASC_ERR_ARGC_TOO_LITTLE        10000
#define UASC_ERR_INV_ARG                10001
#define UASC_ERR_PROCESS_FAIL           10002
#define UASC_ERR_UNKNOWN_COMMAND        10003
#define UASC_ERR_FILE_NOT_FOUND         10004
#define UASC_ERR_KEY_READ_FAIL          10005
#define UASC_ERR_MISSING_REQUIRED_ARG   10006

// 进度条函数
void progressBar(int len, int nPos, int nMin, int nMax, wchar_t progressChar, wchar_t emptyChar, bool bShowNum);
// 字符串分割函数
std::vector<std::wstring> strsplit(const std::wstring& str, const std::wstring& delimiter);
// 运行脚本行
UINT RunUAScriptLine(const std::vector<std::wstring>& toks, int lineNumber, std::wstring& errorDetails);
// 运行脚本文件
void RunUAScriptFile(const std::wstring& filename);