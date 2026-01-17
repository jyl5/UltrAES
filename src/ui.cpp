// ui.cpp
// Copyright (c) 2025-2026 金煜力
// 用户界面操作 & 子类化

#include "ui.h"
#include <map>
#include <string>
#include <Windows.h>
#include <commdlg.h>
#include <CommCtrl.h>

#pragma comment(lib, "comctl32.lib")

#ifdef _UNICODE
#if defined _M_IX86
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_IA64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='ia64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_X64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif
#endif

// 移动窗口到屏幕中央
void MoveWindowToMidOfScreen(HWND hwnd) {
    // 获取屏幕信息
	int screenWidth = GetSystemMetrics(SM_CXSCREEN);
	int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    // 获取窗口信息
	RECT rect;
	GetWindowRect(hwnd, &rect);
    // 计算位置
	int width = rect.right - rect.left;
	int height = rect.bottom - rect.top;
	int x = (screenWidth - width) / 2;
	int y = (screenHeight - height) / 2;
    // 移动窗口
	SetWindowPos(hwnd, NULL, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
}

// 开启高DPI感知
bool EnableHighDpi() {
    HMODULE hUser32 = GetModuleHandle(L"user32.dll");
    if (hUser32)
    {
        typedef BOOL(WINAPI* SetProcessDPIAwareProc)();
        SetProcessDPIAwareProc setProcessDPIAware = (SetProcessDPIAwareProc)GetProcAddress(hUser32, "SetProcessDPIAware");
        if (setProcessDPIAware)
        {
            if (setProcessDPIAware())
            {
                return true;
            }
        }
    }
    return false;
}

// 设置窗口置顶
void SetWindowAlwaysOnTop(HWND hwnd, bool bTop) {
    if (hwnd == NULL || !IsWindow(hwnd))
        return;
    SetWindowPos(
        hwnd,
        bTop ? HWND_TOPMOST : HWND_NOTOPMOST,
        0, 0, 0, 0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE
    );
}

// 刷新窗口
void RefreshWindow(HWND hwnd) {
    RedrawWindow(hwnd, NULL, NULL,
        RDW_INVALIDATE | RDW_UPDATENOW | RDW_ERASE);
}

// 打开文件对话框
LPCWSTR BrowseOpenFile(LPCWSTR filter, LPCWSTR defaultPath, LPCWSTR defaultExt, HWND parentWindow) {
    static wchar_t resultPath[MAX_PATH] = L"";
    OPENFILENAMEW ofn;
    wchar_t szFile[MAX_PATH] = L"";
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = parentWindow;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile) / sizeof(wchar_t);
    ofn.lpstrFilter = filter;
    if (defaultExt && wcslen(defaultExt) > 0) ofn.lpstrDefExt = defaultExt;
    if (defaultPath && wcslen(defaultPath) > 0) ofn.lpstrInitialDir = defaultPath;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
    if (GetOpenFileNameW(&ofn) == TRUE) {
        wcscpy_s(resultPath, MAX_PATH, szFile);
        return resultPath;
    }
    return L"";
}

// 保存文件对话框
LPCWSTR BrowseSaveFile(LPCWSTR filter, LPCWSTR defaultPath, LPCWSTR defaultFileName, LPCWSTR defaultExt, HWND parentWindow) {
    static wchar_t resultPath[MAX_PATH] = L"";
    OPENFILENAMEW ofn;
    wchar_t szFile[MAX_PATH] = L"";
    if (defaultFileName && wcslen(defaultFileName) > 0) wcscpy_s(szFile, MAX_PATH, defaultFileName);
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = parentWindow;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile) / sizeof(wchar_t);
    ofn.lpstrFilter = filter;
    if (defaultExt && wcslen(defaultExt) > 0) ofn.lpstrDefExt = defaultExt;
    if (defaultPath && wcslen(defaultPath) > 0) ofn.lpstrInitialDir = defaultPath;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;
    if (GetSaveFileNameW(&ofn) == TRUE) {
        wcscpy_s(resultPath, MAX_PATH, szFile);
        return resultPath;
    }
    return L"";
}

// 在一个控件的位置上创建工具栏
HWND CreateToolBarAtControlPos(HWND hWndParent, int nControlID, bool hideCtl)
{
    // 获取指定控件
    HWND hWndControl = GetDlgItem(hWndParent, nControlID);
    if (!hWndControl)
    {
        return NULL;
    }

    // 获取控件的位置和大小
    RECT rcControl;
    if (!GetWindowRect(hWndControl, &rcControl))
    {
        return NULL;
    }

    // 将屏幕坐标转换为父窗口客户区坐标
    POINT ptTopLeft = { rcControl.left, rcControl.top };
    POINT ptBottomRight = { rcControl.right, rcControl.bottom };
    ScreenToClient(hWndParent, &ptTopLeft);
    ScreenToClient(hWndParent, &ptBottomRight);

    // 计算控件在父窗口中的矩形
    RECT rcControlInParent = {
        ptTopLeft.x,
        ptTopLeft.y,
        ptBottomRight.x,
        ptBottomRight.y
    };

    // 创建工具栏
    HWND hWndToolBar = CreateWindowEx(
        0,
        TOOLBARCLASSNAME,
        NULL,
        WS_CHILD | WS_VISIBLE | TBSTYLE_FLAT | TBSTYLE_TOOLTIPS | CCS_NODIVIDER | CCS_NORESIZE,
        rcControlInParent.left,
        rcControlInParent.top,
        rcControlInParent.right - rcControlInParent.left,
        rcControlInParent.bottom - rcControlInParent.top,
        hWndParent,
        NULL,
        GetModuleHandle(NULL),
        NULL
    );

    if (!hWndToolBar)
    {
        return NULL;
    }

    // 初始化工具栏
    SendMessage(hWndToolBar, TB_BUTTONSTRUCTSIZE, (WPARAM)sizeof(TBBUTTON), 0);

    // 设置工具栏图标大小（可选，根据需要调整）
    SendMessage(hWndToolBar, TB_SETBITMAPSIZE, 0, MAKELONG(16, 16));
    SendMessage(hWndToolBar, TB_SETBUTTONSIZE, 0, MAKELONG(24, 24));

    // 隐藏原始控件
    if (hideCtl)ShowWindow(hWndControl, SW_HIDE);

    return hWndToolBar;
}

// ============================== 进度条显示文本子类化 ==============================
// 进度条数据结构
struct PROGRESSBAR_DATA {
    int pos;                // 当前位置
    int min;                // 最小值
    int max;                // 最大值
    int mode;               // 当前模式
    wchar_t text[256];      // 显示文本
    COLORREF fillColor;     // 填充颜色

    PROGRESSBAR_DATA() {
        pos = 0;
        min = 0;
        max = 100;
        mode = TPBMOD_NORMAL;
        text[0] = L'\0';
        fillColor = RGB(6, 176, 37);  // 默认绿色
    }

    // 根据模式更新填充颜色
    void UpdateFillColor() {
        switch (mode) {
        case TPBMOD_NORMAL:
            fillColor = RGB(6, 176, 37);     // 绿色
            break;
        case TPBMOD_PAUSE:
            fillColor = RGB(255, 200, 0);    // 黄色
            break;
        case TPBMOD_ERROR:
            fillColor = RGB(220, 0, 0);      // 红色
            break;
        default:
            fillColor = RGB(6, 176, 37);     // 默认绿色
            break;
        }
    }
};

// 进度条子类过程
LRESULT CALLBACK ProgressBarProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
    UINT_PTR, DWORD_PTR) {
    // 获取或创建进度条数据
    static std::map<HWND, PROGRESSBAR_DATA*> progressDataMap;
    PROGRESSBAR_DATA* pData = nullptr;

    auto it = progressDataMap.find(hwnd);
    if (it == progressDataMap.end()) {
        // 第一次访问此窗口，创建数据
        pData = new PROGRESSBAR_DATA();
        progressDataMap[hwnd] = pData;
    }
    else {
        pData = it->second;
    }

    switch (msg) {
    case WM_NCDESTROY:
        // 窗口销毁时清理数据
        if (pData) {
            delete pData;
            progressDataMap.erase(hwnd);
        }
        break;

    case PBM_SETRANGE:
        pData->min = LOWORD(lParam);
        pData->max = HIWORD(lParam);
        break;

    case PBM_SETPOS:
        pData->pos = (int)wParam;
        InvalidateRect(hwnd, nullptr, TRUE);
        break;

    case TPBM_SETTEXT: // 自定义消息：设置进度条文本
        if (lParam) {
            wcsncpy_s(pData->text, (const wchar_t*)lParam, 255);
            pData->text[255] = L'\0';
        }
        else {
            pData->text[0] = L'\0';
        }
        InvalidateRect(hwnd, nullptr, TRUE);
        return 0;

    case TPBM_SETMODE: // 自定义消息：设置进度条模式
        pData->mode = (int)wParam;
        if (pData->mode < TPBMOD_NORMAL || pData->mode > TPBMOD_ERROR) {
            pData->mode = TPBMOD_NORMAL;
        }
        pData->UpdateFillColor();
        InvalidateRect(hwnd, nullptr, TRUE);
        return 0;

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc;
        GetClientRect(hwnd, &rc);

        // 首先绘制淡灰色边框
        HBRUSH bBorder = CreateSolidBrush(RGB(200, 200, 200));
        FrameRect(hdc, &rc, bBorder);
        DeleteObject(bBorder);

        // 调整内部区域（边框内部）
        RECT rcInner = rc;
        rcInner.left += 1;
        rcInner.top += 1;
        rcInner.right -= 1;
        rcInner.bottom -= 1;

        // 计算填充区域
        int fill = (pData->max > pData->min) ?
            ((pData->pos - pData->min) * (rcInner.right - rcInner.left) /
                (pData->max - pData->min)) : 0;
        RECT rcFill = rcInner;
        rcFill.right = rcInner.left + fill;

        // 根据模式绘制填充区域
        HBRUSH bFill = CreateSolidBrush(pData->fillColor);
        FillRect(hdc, &rcFill, bFill);
        DeleteObject(bFill);

        // 绘制剩余区域
        RECT rcRest = rcInner;
        rcRest.left = rcFill.right;
        HBRUSH bRest = CreateSolidBrush(RGB(230, 230, 230));
        FillRect(hdc, &rcRest, bRest);
        DeleteObject(bRest);

        // 如果有自定义文本，则居中绘制
        if (wcslen(pData->text) > 0) {
            SetBkMode(hdc, TRANSPARENT);
            HFONT hFont = (HFONT)SendMessage(hwnd, WM_GETFONT, 0, 0);
            HFONT hOldFont = hFont ? (HFONT)SelectObject(hdc, hFont) : nullptr;

            // 设置剪辑区域为填充区域，在填充部分绘制白色文字
            HRGN hrgnFill = CreateRectRgnIndirect(&rcFill);
            SelectClipRgn(hdc, hrgnFill);
            SetTextColor(hdc, RGB(255, 255, 255)); // 白色文字

            // 根据模式调整文字颜色（对于浅色填充可能不适用）
            if (pData->mode == TPBMOD_PAUSE) {
                // 黄色背景上用黑色文字可能更清晰
                SetTextColor(hdc, RGB(0, 0, 0));
            }

            DrawTextW(hdc, pData->text, -1, &rcInner, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            DeleteObject(hrgnFill);

            // 设置剪辑区域为剩余区域，在空白部分绘制黑色文字
            HRGN hrgnRest = CreateRectRgnIndirect(&rcRest);
            SelectClipRgn(hdc, hrgnRest);
            SetTextColor(hdc, RGB(0, 0, 0)); // 黑色文字
            DrawTextW(hdc, pData->text, -1, &rcInner, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            DeleteObject(hrgnRest);

            // 恢复剪辑区域
            SelectClipRgn(hdc, nullptr);

            if (hOldFont) SelectObject(hdc, hOldFont);
        }

        EndPaint(hwnd, &ps);
        return 0;
    }
    }
    return DefSubclassProc(hwnd, msg, wParam, lParam);
}

// 设置进度条文本
void SetTextProgressBarText(HWND hProgress, std::wstring text) {
    SendMessageW(hProgress, TPBM_SETTEXT, 0, (LPARAM)text.c_str());
}

// 设置进度条模式
void SetTextProgressBarMode(HWND hProgress, int mode) {
    SendMessageW(hProgress, TPBM_SETMODE, (WPARAM)mode, 0);
}