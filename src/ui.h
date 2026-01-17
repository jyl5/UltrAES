// ui.h
// Copyright (c) 2025-2026 金煜力
// 用户界面操作 & 子类化

#pragma once

#include <Windows.h>
#include <string>
#include <map>

// 移动窗口到屏幕中央
void MoveWindowToMidOfScreen(HWND hwnd);
// 开启高DPI感知
bool EnableHighDpi();
// 设置窗口始终置顶
void SetWindowAlwaysOnTop(HWND hwnd, bool bTop);
// 刷新窗口
void RefreshWindow(HWND hwnd);
// 打开文件对话框
LPCWSTR BrowseOpenFile(LPCWSTR filter, LPCWSTR defaultPath, LPCWSTR defaultExt, HWND parentWindow);
// 保存文件对话框
LPCWSTR BrowseSaveFile(LPCWSTR filter, LPCWSTR defaultPath, LPCWSTR defaultFileName, LPCWSTR defaultExt, HWND parentWindow);
// 在一个控件的位置上创建工具栏
HWND CreateToolBarAtControlPos(HWND hWndParent, int nControlID, bool hideCtl);

// ============================== 进度条显示文本子类化 ==============================
// // 定义进度条消息和模式
#define TPBM_SETTEXT (WM_USER + 100)
#define TPBM_SETMODE (WM_USER + 101)

// 进度条模式定义
#define TPBMOD_NORMAL   0  // 正常模式 - 绿色
#define TPBMOD_PAUSE    1  // 暂停模式 - 黄色
#define TPBMOD_ERROR    2  // 错误模式 - 红色

// 进度条子类化过程
LRESULT CALLBACK ProgressBarProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR, DWORD_PTR);
// 设置进度条文本
void SetTextProgressBarText(HWND hProgress, std::wstring text);
// 设置进度条模式
void SetTextProgressBarMode(HWND hProgress, int mode);