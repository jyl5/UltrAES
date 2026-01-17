// UAScript.cpp
// Copyright (c) 2025 金煜力
// UltrAES脚本

#include "AES.h"
#include "hash.h"
#include "UAScript.h"
#include <cwchar>
#include <string>
#include <vector>
#include <conio.h>
#include <cstring>
#include <cstdint>
#include <fstream>
#include <Windows.h>
#include <functional>

void progressBar(int len, int nPos, int nMin, int nMax, wchar_t progressChar, wchar_t emptyChar, bool bShowNum) {
    float percentage = 0.0f;
    if (nMax != nMin) {
        percentage = static_cast<float>(nPos - nMin) / (nMax - nMin);
    }

    if (percentage < 0.0f) percentage = 0.0f;
    if (percentage > 1.0f) percentage = 1.0f;

    int progressLength = static_cast<int>(percentage * len);

    std::wstring bar = L"[";
    for (int i = 0; i < progressLength; ++i) {
        bar += progressChar;
    }
    for (int i = progressLength; i < len; ++i) {
        bar += emptyChar;
    }
    bar += L"]";
    wprintf(L"%ls", bar.c_str());
    if (bShowNum) {
        int percent = static_cast<int>(percentage * 100);
        wprintf(L" %d%%", percent);
    }
}

void setProgress(int nProgress) {
    progressBar(50, nProgress, 0, 100, L'*', L'-', true);
    wprintf(L"\r");
}

std::vector<std::wstring> strsplit(const std::wstring& str, const std::wstring& delimiter) {
    std::vector<std::wstring> result;
    if (str.empty()) return result;
    if (delimiter.empty()) {
        result.push_back(str);
        return result;
    }

    size_t start = 0;
    size_t end = str.find(delimiter);

    while (end != std::wstring::npos) {
        result.push_back(str.substr(start, end - start));
        start = end + delimiter.length();
        end = str.find(delimiter, start);
    }

    result.push_back(str.substr(start));
    return result;
}

UINT RunUAScriptLine(const std::vector<std::wstring>& toks, int lineNumber, std::wstring& errorDetails) {
    int tokcnt = toks.size();

    // 空行或注释行
    if (tokcnt == 0 || toks[0].empty() || toks[0][0] == L'#') {
        return 0;
    }

    std::wstring mode, infile, outfile, s_key;

    // 检查命令是否有效
    if (_wcsicmp(toks[0].c_str(), L"genkey") == 0) {
        if (tokcnt < 4) {
            errorDetails = L"genkey 命令需要至少3个参数：-rdbyte/-frompwd 和 -out";
            return UASC_ERR_ARGC_TOO_LITTLE;
        }

        bool fpwd = false;
        std::wstring pwd;
        bool hasOutFile = false;

        for (int i = 1; i < tokcnt; i++) {
            if (_wcsicmp(toks[i].c_str(), L"-rdbyte") == 0) {
                fpwd = false;
            }
            else if (_wcsicmp(toks[i].c_str(), L"-frompwd") == 0) {
                if (i + 1 >= tokcnt) {
                    errorDetails = L"-frompwd 参数需要一个密码值";
                    return UASC_ERR_MISSING_REQUIRED_ARG;
                }
                fpwd = true;
                pwd = toks[i + 1];
                i++;
            }
            else if (_wcsicmp(toks[i].c_str(), L"-out") == 0) {
                if (i + 1 >= tokcnt) {
                    errorDetails = L"-out 参数需要一个输出文件名";
                    return UASC_ERR_MISSING_REQUIRED_ARG;
                }
                outfile = toks[i + 1];
                hasOutFile = true;
                i++;
            }
            else {
                errorDetails = L"无效参数: " + toks[i];
                return UASC_ERR_INV_ARG;
            }
        }

        if (!hasOutFile) {
            errorDetails = L"缺少必需的 -out 参数";
            return UASC_ERR_MISSING_REQUIRED_ARG;
        }

        std::vector<uint8_t> key;
        if (fpwd) {
            if (pwd.empty()) {
                errorDetails = L"密码不能为空";
                return UASC_ERR_INV_ARG;
            }
            SHA256_CTX _sha256_ctx;
            Sha256Init(&_sha256_ctx);
            Sha256Update(&_sha256_ctx, std::string(pwd.begin(), pwd.end()));
            key = Sha256Digest(&_sha256_ctx);
            Sha256Finalize(&_sha256_ctx);
        }
        else {
            key = generate_aes256_key();
        }

        if (!write_key(outfile, key)) {
            errorDetails = L"无法写入密钥文件: " + outfile;
            return UASC_ERR_PROCESS_FAIL;
        }
        wprintf(L"已生成密钥：%ls\n", outfile.c_str());
    }
    else if (_wcsicmp(toks[0].c_str(), L"enc") == 0 || _wcsicmp(toks[0].c_str(), L"dec") == 0) {
        bool isEncrypt = (_wcsicmp(toks[0].c_str(), L"enc") == 0);

        if (tokcnt < 7) {
            errorDetails = isEncrypt ?
                L"enc 命令需要至少6个参数：-usekey/-usepwd、-key、-in、-out" :
                L"dec 命令需要至少6个参数：-usekey/-usepwd、-key、-in、-out";
            return UASC_ERR_ARGC_TOO_LITTLE;
        }

        bool usepwd = false;
        bool hasKey = false, hasInFile = false, hasOutFile = false;

        for (int i = 1; i < tokcnt; i++) {
            if (_wcsicmp(toks[i].c_str(), L"-usepwd") == 0) {
                usepwd = true;
            }
            else if (_wcsicmp(toks[i].c_str(), L"-usekey") == 0) {
                usepwd = false;
            }
            else if (_wcsicmp(toks[i].c_str(), L"-key") == 0) {
                if (i + 1 >= tokcnt) {
                    errorDetails = L"-key 参数需要一个密钥文件或密码";
                    return UASC_ERR_MISSING_REQUIRED_ARG;
                }
                s_key = toks[i + 1];
                hasKey = true;
                i++;
            }
            else if (_wcsicmp(toks[i].c_str(), L"-in") == 0) {
                if (i + 1 >= tokcnt) {
                    errorDetails = L"-in 参数需要一个输入文件名";
                    return UASC_ERR_MISSING_REQUIRED_ARG;
                }
                infile = toks[i + 1];
                hasInFile = true;
                i++;
            }
            else if (_wcsicmp(toks[i].c_str(), L"-out") == 0) {
                if (i + 1 >= tokcnt) {
                    errorDetails = L"-out 参数需要一个输出文件名";
                    return UASC_ERR_MISSING_REQUIRED_ARG;
                }
                outfile = toks[i + 1];
                hasOutFile = true;
                i++;
            }
            else {
                errorDetails = L"无效参数: " + toks[i];
                return UASC_ERR_INV_ARG;
            }
        }

        if (!hasKey) {
            errorDetails = L"缺少必需的 -key 参数";
            return UASC_ERR_MISSING_REQUIRED_ARG;
        }
        if (!hasInFile) {
            errorDetails = L"缺少必需的 -in 参数";
            return UASC_ERR_MISSING_REQUIRED_ARG;
        }
        if (!hasOutFile) {
            errorDetails = L"缺少必需的 -out 参数";
            return UASC_ERR_MISSING_REQUIRED_ARG;
        }

        // 检查输入文件是否存在
        std::ifstream testFile(infile, std::ios::binary);
        if (!testFile) {
            errorDetails = L"输入文件不存在: " + infile;
            return UASC_ERR_FILE_NOT_FOUND;
        }
        testFile.close();

        std::vector<uint8_t> key;
        if (usepwd) {
            if (s_key.empty()) {
                errorDetails = L"密码不能为空";
                return UASC_ERR_INV_ARG;
            }
            SHA256_CTX _sha256_ctx;
            Sha256Init(&_sha256_ctx);
            Sha256Update(&_sha256_ctx, std::string(s_key.begin(), s_key.end()));
            key = Sha256Digest(&_sha256_ctx);
            Sha256Finalize(&_sha256_ctx);
        }
        else {
            key = read_key(s_key);
            if (key.empty()) {
                errorDetails = L"无法读取密钥文件: " + s_key;
                return UASC_ERR_KEY_READ_FAIL;
            }
        }

        try {
            aes256_cbc_file(infile, outfile, key, isEncrypt ? L"enc" : L"dec", std::bind(&setProgress, std::placeholders::_1));
        }
        catch (std::exception& e) {
            errorDetails = L"处理失败: " + std::wstring(e.what(), e.what() + strlen(e.what()));
            return UASC_ERR_PROCESS_FAIL;
        }

        Sleep(10);
        wprintf(L"\n已%s文件：%ls\n", isEncrypt ? L"加密" : L"解密", infile.c_str());
    }
    else {
        errorDetails = L"未知命令: " + toks[0];
        return UASC_ERR_UNKNOWN_COMMAND;
    }
    return 0;
}

void RunUAScriptFile(const std::wstring& filename) {
    // 检查文件是否存在
    std::ifstream testFile(filename, std::ios::binary);
    if (!testFile) {
        wprintf(L"错误：无法打开脚本文件：%ls\n", filename.c_str());
        return;
    }
    testFile.close();

    // 自动检测编码并读取脚本
    std::ifstream fin(filename, std::ios::binary);
    if (!fin) {
        wprintf(L"无法打开脚本文件：%ls\n", filename.c_str());
        return;
    }

    // 读取BOM
    char bom[4] = { 0 };
    fin.read(bom, 4);
    size_t readlen = fin.gcount();

    // 检测编码
    enum class FileEnc { UTF8, UTF16LE, UTF16BE, ANSI };
    FileEnc enc = FileEnc::ANSI;
    size_t skip = 0;

    if (readlen >= 3 && (unsigned char)bom[0] == 0xEF && (unsigned char)bom[1] == 0xBB && (unsigned char)bom[2] == 0xBF) {
        enc = FileEnc::UTF8;
        skip = 3;
    }
    else if (readlen >= 2 && (unsigned char)bom[0] == 0xFF && (unsigned char)bom[1] == 0xFE) {
        enc = FileEnc::UTF16LE;
        skip = 2;
    }
    else if (readlen >= 2 && (unsigned char)bom[0] == 0xFE && (unsigned char)bom[1] == 0xFF) {
        enc = FileEnc::UTF16BE;
        skip = 2;
    }
    else {
        // 无BOM，假定为ANSI或UTF-8
        enc = FileEnc::UTF8;
        skip = 0;
    }

    // 回到内容起始
    fin.clear();
    fin.seekg(skip, std::ios::beg);
    std::wstring s;
    int lcnt = 1;

    if (enc == FileEnc::UTF8) {
        // 读取剩余内容到string
        std::string content((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());

        // 按行分割
        size_t pos = 0, next;
        while (pos < content.size()) {
            next = content.find('\n', pos);
            std::string line = (next == std::string::npos) ? content.substr(pos) : content.substr(pos, next - pos);

            // 去除前后空白字符和回车
            if (!line.empty() && line.back() == '\r') line.pop_back();

            size_t start = line.find_first_not_of(" \t");
            if (start == std::string::npos) {
                line = "";
            }
            else {
                size_t end = line.find_last_not_of(" \t");
                line = line.substr(start, end - start + 1);
            }

            // 跳过空行和注释
            if (line.empty() || line[0] == '#') {
                lcnt++;
                if (next == std::string::npos) break;
                pos = next + 1;
                continue;
            }

            // 转换为宽字符串
            int wlen = MultiByteToWideChar(CP_UTF8, 0, line.c_str(), (int)line.size(), NULL, 0);
            if (wlen > 0) {
                std::wstring ws(wlen, 0);
                MultiByteToWideChar(CP_UTF8, 0, line.c_str(), (int)line.size(), &ws[0], wlen);

                // 分割命令行
                std::vector<std::wstring> toked = strsplit(ws, L" ");
                std::wstring errorDetails;
                UINT flag = RunUAScriptLine(toked, lcnt, errorDetails);

                if (flag != 0) {
                    wprintf(L"第 %d 行错误：%ls\n", lcnt, errorDetails.c_str());
                    wprintf(L"是否继续执行？(按 'a' 中断，按其他键继续): ");

                    int ch = _getch();
                    if (ch == 'a' || ch == 'A') {
                        wprintf(L"\n脚本执行已中断。\n\n");
                        return;
                    }
                    else {
                        wprintf(L"\n");
                    }
                }
            }
            lcnt++;
            wprintf(L"\n");
            if (next == std::string::npos) break;
            pos = next + 1;
        }
    }
    else if (enc == FileEnc::UTF16LE) {
        // 读取剩余内容到char数组
        std::vector<char> buf((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
        size_t wlen = buf.size() / 2;
        std::wstring ws(wlen, 0);
        memcpy(&ws[0], buf.data(), wlen * 2);

        size_t pos = 0, next;
        while (pos < ws.size()) {
            next = ws.find(L'\n', pos);
            std::wstring line = (next == std::wstring::npos) ? ws.substr(pos) : ws.substr(pos, next - pos);

            // 去除前后空白字符和回车
            if (!line.empty() && line.back() == L'\r') line.pop_back();

            size_t start = line.find_first_not_of(L" \t");
            if (start == std::wstring::npos) {
                line = L"";
            }
            else {
                size_t end = line.find_last_not_of(L" \t");
                line = line.substr(start, end - start + 1);
            }

            // 跳过空行和注释
            if (line.empty() || line[0] == L'#') {
                lcnt++;
                if (next == std::wstring::npos) break;
                pos = next + 1;
                continue;
            }

            std::vector<std::wstring> toked = strsplit(line, L" ");
            std::wstring errorDetails;
            UINT flag = RunUAScriptLine(toked, lcnt, errorDetails);

            if (flag != 0) {
                wprintf(L"第 %d 行错误：%ls\n", lcnt, errorDetails.c_str());
                wprintf(L"是否继续执行？(按 'a' 中断，按其他键继续): ");

                int ch = _getch();
                if (ch == 'a' || ch == 'A') {
                    wprintf(L"\n脚本执行已中断。\n\n");
                    return;
                }
                else {
                    wprintf(L"\n");
                }
            }
            lcnt++;
            wprintf(L"\n");
            if (next == std::wstring::npos) break;
            pos = next + 1;
        }
    }
    else if (enc == FileEnc::UTF16BE) {
        // 读取剩余内容到char数组
        std::vector<char> buf((std::istreambuf_iterator<char>(fin)), std::istreambuf_iterator<char>());
        size_t wlen = buf.size() / 2;
        std::wstring ws(wlen, 0);
        for (size_t i = 0; i < wlen; ++i) {
            ws[i] = (wchar_t)(((unsigned char)buf[2 * i + 1] << 8) | (unsigned char)buf[2 * i]);
        }

        size_t pos = 0, next;
        while (pos < ws.size()) {
            next = ws.find(L'\n', pos);
            std::wstring line = (next == std::wstring::npos) ? ws.substr(pos) : ws.substr(pos, next - pos);

            // 去除前后空白字符和回车
            if (!line.empty() && line.back() == L'\r') line.pop_back();

            size_t start = line.find_first_not_of(L" \t");
            if (start == std::wstring::npos) {
                line = L"";
            }
            else {
                size_t end = line.find_last_not_of(L" \t");
                line = line.substr(start, end - start + 1);
            }

            // 跳过空行和注释
            if (line.empty() || line[0] == L'#') {
                lcnt++;
                if (next == std::wstring::npos) break;
                pos = next + 1;
                continue;
            }

            std::vector<std::wstring> toked = strsplit(line, L" ");
            std::wstring errorDetails;
            UINT flag = RunUAScriptLine(toked, lcnt, errorDetails);

            if (flag != 0) {
                wprintf(L"第 %d 行错误：%ls\n", lcnt, errorDetails.c_str());
                wprintf(L"是否继续执行？(按 'a' 中断，按其他键继续): ");

                int ch = _getch();
                if (ch == 'a' || ch == 'A') {
                    wprintf(L"\n脚本执行已中断。\n\n");
                    return;
                }
                else {
                    wprintf(L"\n");
                }
            }
            lcnt++;
            wprintf(L"\n");
            if (next == std::wstring::npos) break;
            pos = next + 1;
        }
    }
    else {
        // ANSI，假定为本地代码页
        fin.clear();
        fin.seekg(skip, std::ios::beg);
        std::string line;
        while (std::getline(fin, line)) {
            // 去除回车
            if (!line.empty() && line.back() == '\r') line.pop_back();

            // 去除前后空白字符
            size_t start = line.find_first_not_of(" \t");
            if (start == std::string::npos) {
                line = "";
            }
            else {
                size_t end = line.find_last_not_of(" \t");
                line = line.substr(start, end - start + 1);
            }

            // 跳过空行和注释
            if (line.empty() || line[0] == '#') {
                lcnt++;
                continue;
            }

            int wlen = MultiByteToWideChar(CP_ACP, 0, line.c_str(), (int)line.size(), NULL, 0);
            if (wlen > 0) {
                std::wstring ws(wlen, 0);
                MultiByteToWideChar(CP_ACP, 0, line.c_str(), (int)line.size(), &ws[0], wlen);

                std::vector<std::wstring> toked = strsplit(ws, L" ");
                std::wstring errorDetails;
                UINT flag = RunUAScriptLine(toked, lcnt, errorDetails);

                if (flag != 0) {
                    wprintf(L"第 %d 行错误：%ls\n", lcnt, errorDetails.c_str());
                    wprintf(L"是否继续执行？(按 'a' 中断，按其他键继续): ");

                    int ch = _getch();
                    if (ch == 'a' || ch == 'A') {
                        wprintf(L"\n脚本执行已中断。\n\n");
                        return;
                    }
                    else {
                        wprintf(L"\n");
                    }
                }
            }
            lcnt++;
            wprintf(L"\n");
        }
    }

    wprintf(L"脚本执行完成。\n");
}