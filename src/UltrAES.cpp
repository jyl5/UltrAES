// UltrAES.cpp
// Copyright (c) 2025-2026 金煜力
// 主程序

#include "ui.h"
#include "AES.h"
#include "hash.h"
#include "smart.h"
#include "inifile.h"
#include "UAScript.h"
#include "resource.h"
#include <io.h>
#include <atomic>
#include <vector>
#include <thread>
#include <conio.h>
#include <fcntl.h>
#include <fstream>
#include <cstdint>
#include <Windows.h>
#include <Richedit.h>
#include <ShObjIdl.h>
#include <CommCtrl.h>

#pragma comment(lib, "ole32.lib")

// 全局变量
HINSTANCE hInstance;
HWND hWnd;
HWND hToolBar;
HICON hIcon;
HMENU KeyfileSplitDropMenu;
HMODULE hRichedMod;
bool usePwd = false;
bool winAOnTop = true;
bool isTaskBarNormalState = false;
std::wstring lastoutfile;
std::wstring progressTip;
std::wstring crc32, md5, sha1, sha256, sha512;
ITaskbarList3* pTaskbarList = NULL;
INIFILE_CTX* inifile;

// Processing state
static std::atomic<bool> g_isProcessing(false);

// 底部工具栏按钮ID
#define IDC_TBTN_HASH			10000
#define IDC_TBTN_ABOUT			10001

void OnBtnOpenInputFile() {
    LPCWSTR filename = BrowseOpenFile(L"所有文件 (*.*)\0*.*\0", L"", L"", hWnd);
    if (lstrcmpW(filename, L"") == 0) return;
    SetWindowTextW(GetDlgItem(hWnd, IDC_EDIT_INPUT_FILE), filename);
}

void OnBtnSaveOutFile() {
    wchar_t infilename[MAX_PATH];
    GetWindowTextW(GetDlgItem(hWnd, IDC_EDIT_INPUT_FILE), infilename, MAX_PATH);
    LPCWSTR defOutfile;
    LPCWSTR infiledir;
    std::wstring inFileDir;
    inFileDir = getFileDirectory(infilename);
    infiledir = inFileDir.c_str();
    std::wstring outFileName;
    if (str_endwith(infilename, L".enc", true)) {
        outFileName = removeLastExtName(infilename);
    }
    else {
        outFileName = std::wstring(infilename) + L".enc";
    }
    defOutfile = outFileName.c_str();
    LPCWSTR filename = BrowseSaveFile(L"所有文件 (*.*)\0*.*\0", infiledir, defOutfile, L"", hWnd);
    if (lstrcmpW(filename, L"") == 0) return;
    SetWindowTextW(GetDlgItem(hWnd, IDC_EDIT_OUTPUT_FILE), filename);
}

void OnMenuKeyfileSplitOpenKey() {
	CheckMenuItem(KeyfileSplitDropMenu, IDM_KEYFILE_DROP_OPENKEY, MF_CHECKED | MF_BYCOMMAND);
	CheckMenuItem(KeyfileSplitDropMenu, IDM_KEYFILE_DROP_GENKEY, MF_UNCHECKED | MF_BYCOMMAND);
	SetWindowTextW(GetDlgItem(hWnd, IDC_SPLIT_KEYFILE), L"浏览");
}

void OnMenuKeyfileSplitGenKey() {
	CheckMenuItem(KeyfileSplitDropMenu, IDM_KEYFILE_DROP_OPENKEY, MF_UNCHECKED | MF_BYCOMMAND);
	CheckMenuItem(KeyfileSplitDropMenu, IDM_KEYFILE_DROP_GENKEY, MF_CHECKED | MF_BYCOMMAND);
	SetWindowTextW(GetDlgItem(hWnd, IDC_SPLIT_KEYFILE), L"生成");
}

void OnCheckUsePwd() {
	if (IsDlgButtonChecked(hWnd, IDC_CHECK_USEPWD) == BST_CHECKED) {
		usePwd = true;
		EnableWindow(GetDlgItem(hWnd, IDC_SPLIT_KEYFILE), FALSE);
		SetWindowTextW(GetDlgItem(hWnd, IDC_EDIT_KEY), L"");
		ShowWindow(GetDlgItem(hWnd, IDC_CHECK_SHOWPWD), SW_SHOW);
		if (IsDlgButtonChecked(hWnd, IDC_CHECK_SHOWPWD) == BST_CHECKED) {
			SendMessageW(GetDlgItem(hWnd, IDC_EDIT_KEY), EM_SETPASSWORDCHAR, 0, 0);
		}
		else {
			SendMessageW(GetDlgItem(hWnd, IDC_EDIT_KEY), EM_SETPASSWORDCHAR, (WPARAM)L'●', 0);
		}
	}
	else {
		usePwd = false;
		EnableWindow(GetDlgItem(hWnd, IDC_SPLIT_KEYFILE), TRUE);
		SetWindowTextW(GetDlgItem(hWnd, IDC_EDIT_KEY), L"");
		ShowWindow(GetDlgItem(hWnd, IDC_CHECK_SHOWPWD), SW_HIDE);
		SendMessageW(GetDlgItem(hWnd, IDC_EDIT_KEY), EM_SETPASSWORDCHAR, 0, 0);
	}
	ini_set_bool(inifile, "startup", "UsePwd", usePwd);
	ini_save_to_file(inifile, "config.ini");
	RefreshWindow(hWnd);
}

void OnCheckShowPwd() {
	if (IsDlgButtonChecked(hWnd, IDC_CHECK_SHOWPWD) == BST_CHECKED) {
		SendMessageW(GetDlgItem(hWnd, IDC_EDIT_KEY), EM_SETPASSWORDCHAR, 0, 0);
	}
	else {
		SendMessageW(GetDlgItem(hWnd, IDC_EDIT_KEY), EM_SETPASSWORDCHAR, (WPARAM)L'●', 0);
	}
	RefreshWindow(hWnd);
}

void OnCheckWinTopmost() {
	winAOnTop = !winAOnTop;
	CheckDlgButton(hWnd, IDC_CHECK_WINTOPMOST, winAOnTop ? BST_CHECKED : BST_UNCHECKED);
	SetWindowAlwaysOnTop(hWnd, winAOnTop);
	ini_set_bool(inifile, "startup", "WindowOnTop", winAOnTop);
	ini_save_to_file(inifile, "config.ini");
}

void OnSplitKeyfile() {
    if (CheckMenuItem(KeyfileSplitDropMenu, IDM_KEYFILE_DROP_GENKEY, MF_BYCOMMAND) == MF_CHECKED) {
        LPCWSTR keyfile = BrowseSaveFile(L"密钥文件 (*.key)\0*.key\0", L"", L"keyfile.key", L".key", hWnd);
        if (lstrcmpW(keyfile, L"") == 0) return;
        std::vector<uint8_t> key = generate_aes256_key();
        bool flag = write_key(keyfile, key);
        if (!flag) {
            MessageBox(hWnd, L"无法写入密钥文件！", L"UltrAES", MB_ICONERROR);
            return;
        }
        SetWindowTextW(GetDlgItem(hWnd, IDC_EDIT_KEY), keyfile);
        MessageBox(hWnd, L"已成功生成密钥！", L"UltrAES", MB_ICONINFORMATION);
    }
    else {
        LPCWSTR keyfile = BrowseOpenFile(L"密钥文件 (*.key)\0*.key\0所有文件 (*.*)\0*.*\0", L"", L"", hWnd);
        if (lstrcmpW(keyfile, L"") == 0) return;
        SetWindowTextW(GetDlgItem(hWnd, IDC_EDIT_KEY), keyfile);
    }
}

void EnableControls(bool bEnable) {
	EnableWindow(GetDlgItem(hWnd, IDC_EDIT_INPUT_FILE), bEnable);
	EnableWindow(GetDlgItem(hWnd, IDC_EDIT_KEY), bEnable);
	EnableWindow(GetDlgItem(hWnd, IDC_EDIT_OUTPUT_FILE), bEnable);
	EnableWindow(GetDlgItem(hWnd, IDC_BTN_OPEN_INPUT_FILE), bEnable);
	if (!usePwd) EnableWindow(GetDlgItem(hWnd, IDC_SPLIT_KEYFILE), bEnable);
	EnableWindow(GetDlgItem(hWnd, IDC_BTN_SAVE_OUTFILE), bEnable);
	EnableWindow(GetDlgItem(hWnd, IDC_CHECK_USEPWD), bEnable);
	EnableWindow(GetDlgItem(hWnd, IDC_CHECK_SHOWPWD), bEnable);
	EnableWindow(GetDlgItem(hWnd, IDC_COMBO_MODE), bEnable);
	EnableWindow(GetDlgItem(hWnd, IDC_BTN_START_CRYPT), bEnable);
	if (!lastoutfile.empty()) SendMessageW(hToolBar, TB_ENABLEBUTTON, (WPARAM)IDC_TBTN_HASH, (LPARAM)bEnable);
	SendMessageW(hToolBar, TB_ENABLEBUTTON, (WPARAM)IDC_TBTN_ABOUT, (LPARAM)bEnable);
}

void SetProcessProgress(int nPos) {
    SendMessageW(GetDlgItem(hWnd, IDC_PROGRESSBAR), PBM_SETPOS, nPos, 0);
    SetTextProgressBarText(GetDlgItem(hWnd, IDC_PROGRESSBAR), progressTip + std::to_wstring(nPos) + L"%");
    if (!isTaskBarNormalState) {
        isTaskBarNormalState = true;
        pTaskbarList->SetProgressState(hWnd, TBPF_NORMAL);
    }
    pTaskbarList->SetProgressValue(hWnd, nPos, 100);
}

void OnBtnStartCrypt() {
    g_isProcessing.store(true);
    SetDlgItemTextW(hWnd, IDC_BTN_START_CRYPT, L"暂停");
    EnableControls(false);
    EnableWindow(GetDlgItem(hWnd, IDC_BTN_START_CRYPT), TRUE);
    EnableWindow(GetDlgItem(hWnd, IDC_BTN_EXIT), FALSE);
    std::wstring infile, outfile, s_key, mode;
    std::vector<uint8_t> key;
    wchar_t temp[MAX_PATH];
    GetWindowTextW(GetDlgItem(hWnd, IDC_EDIT_INPUT_FILE), temp, MAX_PATH);
    infile = temp;
    GetWindowTextW(GetDlgItem(hWnd, IDC_EDIT_KEY), temp, MAX_PATH);
    s_key = temp;
    GetWindowTextW(GetDlgItem(hWnd, IDC_EDIT_OUTPUT_FILE), temp, MAX_PATH);
    outfile = temp;
    GetWindowTextW(GetDlgItem(hWnd, IDC_COMBO_MODE), temp, MAX_PATH);
    if (lstrcmpW(temp, L"自动检测") == 0) {
        if (str_endwith(infile, L".enc", true)) {
            mode = L"dec";
            progressTip = L"正在解密: ";
        }
        else {
            mode = L"enc";
            progressTip = L"正在加密: ";
        }
    }
    else if (lstrcmpW(temp, L"加密") == 0) {
        mode = L"enc";
        progressTip = L"正在加密: ";
    }
    else {
        mode = L"dec";
        progressTip = L"正在解密: ";
    }
    try {
        if (usePwd) {
            SHA256_CTX _sha256;
            Sha256Init(&_sha256);
            Sha256Update(&_sha256, std::string(s_key.begin(), s_key.end()));
            key = Sha256Digest(&_sha256);
        }
        else {
            key = read_key(s_key);
            if (key.empty()) {
                if (pTaskbarList) pTaskbarList->SetProgressState(hWnd, TBPF_ERROR);
				SetTextProgressBarMode(GetDlgItem(hWnd, IDC_PROGRESSBAR), TPBMOD_ERROR);
                MessageBox(hWnd, L"密钥文件读取失败！", L"UltrAES", MB_ICONERROR);
                EnableControls(true);
                SetProcessProgress(0);
                SetTextProgressBarText(GetDlgItem(hWnd, IDC_PROGRESSBAR), L"准备就绪");
				SetTextProgressBarMode(GetDlgItem(hWnd, IDC_PROGRESSBAR), TPBMOD_NORMAL);
                g_isProcessing.store(false);
                if (pTaskbarList) pTaskbarList->SetProgressState(hWnd, TBPF_NOPROGRESS);
                isTaskBarNormalState = false;
                SetDlgItemTextW(hWnd, IDC_BTN_START_CRYPT, L"开始");
                return;
            }
        }
        isTaskBarNormalState = false;
        SetProcessProgress(0);
        aes256_cbc_file(infile, outfile, key, mode, std::bind(&SetProcessProgress, std::placeholders::_1));
        lastoutfile = outfile;
        if (pTaskbarList) {
            pTaskbarList->SetProgressValue(hWnd, 0, 100);
            pTaskbarList->SetProgressState(hWnd, TBPF_NOPROGRESS);
        }
        isTaskBarNormalState = false;
        FlashWindow(hWnd, FALSE);
        if (mode == L"enc") {
            MessageBox(hWnd, L"加密完成！", L"UltrAES", MB_ICONINFORMATION);
            SetTextProgressBarText(GetDlgItem(hWnd, IDC_PROGRESSBAR), L"加密完成: 100%");
        }
        else {
            MessageBox(hWnd, L"解密完成！", L"UltrAES", MB_ICONINFORMATION);
            SetTextProgressBarText(GetDlgItem(hWnd, IDC_PROGRESSBAR), L"解密完成: 100%");
        }
        if (IsDlgButtonChecked(hWnd, IDC_CHECK_DELSRC) == BST_CHECKED) {
            if (!DeleteFileW(infile.c_str())) MessageBox(hWnd, L"未能删除输入文件！", L"UltrAES", MB_ICONWARNING);
        }
        EnableControls(true);
        SendMessageW(hToolBar, TB_ENABLEBUTTON, (WPARAM)IDC_TBTN_HASH, (LPARAM)TRUE);
        g_isProcessing.store(false);
        SetDlgItemTextW(hWnd, IDC_BTN_START_CRYPT, L"开始");
        EnableWindow(GetDlgItem(hWnd, IDC_BTN_EXIT), TRUE);
    }
    catch (std::exception& e) {
        if (pTaskbarList) pTaskbarList->SetProgressState(hWnd, TBPF_ERROR);
		SetTextProgressBarMode(GetDlgItem(hWnd, IDC_PROGRESSBAR), TPBMOD_ERROR);
        MessageBoxA(hWnd, e.what(), "UltrAES", MB_ICONERROR);
        EnableControls(true);
        SetProcessProgress(0);
        SetTextProgressBarText(GetDlgItem(hWnd, IDC_PROGRESSBAR), L"准备就绪");
		SetTextProgressBarMode(GetDlgItem(hWnd, IDC_PROGRESSBAR), TPBMOD_NORMAL);
        g_isProcessing.store(false);
        SetDlgItemTextW(hWnd, IDC_BTN_START_CRYPT, L"开始");
        EnableWindow(GetDlgItem(hWnd, IDC_BTN_EXIT), TRUE);
        if (pTaskbarList) pTaskbarList->SetProgressState(hWnd, TBPF_NOPROGRESS);
        isTaskBarNormalState = false;
        return;
    }
}

INT_PTR CALLBACK HashDlgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_INITDIALOG: {
        MoveWindowToMidOfScreen(hwnd);
        SetWindowTextW(GetDlgItem(hwnd, IDC_EDIT_CRC32), crc32.c_str());
        SetWindowTextW(GetDlgItem(hwnd, IDC_EDIT_MD5), md5.c_str());
        SetWindowTextW(GetDlgItem(hwnd, IDC_EDIT_SHA1), sha1.c_str());
        SetWindowTextW(GetDlgItem(hwnd, IDC_EDIT_SHA256), sha256.c_str());
        SetWindowTextW(GetDlgItem(hwnd, IDC_EDIT_SHA512), sha512.c_str());
        return TRUE;
	}
	case WM_COMMAND: {
		switch (LOWORD(wParam)) {
		case IDC_BTN_HASH_CLOSE: {
			SendMessageW(hwnd, WM_CLOSE, 0, 0);
			break;
		}
		}
		break;
	}
	case WM_CLOSE: {
		EndDialog(hwnd, 0);
		break;
	}
	}
	return FALSE;
}

void OnTBtnHash() {
    progressTip = L"正在计算哈希值: ";
	EnableControls(false);
	SendMessageW(hToolBar, TB_ENABLEBUTTON, (WPARAM)IDC_TBTN_HASH, (LPARAM)FALSE);

    if (lastoutfile.empty()) {
        MessageBox(hWnd, L"没有可用的输出文件！", L"UltrAES", MB_ICONWARNING);
        EnableControls(true);
        SendMessageW(hToolBar, TB_ENABLEBUTTON, (WPARAM)IDC_TBTN_HASH, (LPARAM)TRUE);
        SetProcessProgress(0);
        SetTextProgressBarText(GetDlgItem(hWnd, IDC_PROGRESSBAR), std::wstring(L"准备就绪"));
        return;
    }

    HANDLE hFile = CreateFileW(lastoutfile.c_str(), GENERIC_READ, FILE_SHARE_READ,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		MessageBox(hWnd, L"无法打开文件进行计算！", L"UltrAES", MB_ICONERROR);
		EnableControls(true);
		SendMessageW(hToolBar, TB_ENABLEBUTTON, (WPARAM)IDC_TBTN_HASH, (LPARAM)TRUE);
		SetProcessProgress(0);
        SetTextProgressBarText(GetDlgItem(hWnd, IDC_PROGRESSBAR), std::wstring(L"准备就绪"));
		return;
	}

	LARGE_INTEGER liFileSize;
	if (!GetFileSizeEx(hFile, &liFileSize)) {
		CloseHandle(hFile);
		MessageBox(hWnd, L"无法获取文件大小！", L"UltrAES", MB_ICONERROR);
		EnableControls(true);
		SendMessageW(hToolBar, TB_ENABLEBUTTON, (WPARAM)IDC_TBTN_HASH, (LPARAM)TRUE);
		SetProcessProgress(0);
		SetTextProgressBarText(GetDlgItem(hWnd, IDC_PROGRESSBAR), std::wstring(L"准备就绪"));
		return;
	}

	ULONGLONG filesize = static_cast<ULONGLONG>(liFileSize.QuadPart);
	if (filesize == 0) {
		CloseHandle(hFile);
		MessageBox(hWnd, L"文件为空，无法计算哈希。", L"UltrAES", MB_ICONWARNING);
		EnableControls(true);
		SendMessageW(hToolBar, TB_ENABLEBUTTON, (WPARAM)IDC_TBTN_HASH, (LPARAM)TRUE);
		SetProcessProgress(0);
		SetTextProgressBarText(GetDlgItem(hWnd, IDC_PROGRESSBAR), std::wstring(L"准备就绪"));
		return;
	}

	const size_t bufferSize = 2 * 1024 * 1024;
	std::vector<uint8_t> buffer(bufferSize);
	DWORD bytesRead = 0;
	ULONGLONG totalRead = 0;
	int lastProgress = -1;

	CRC32_CTX _crc32_ctx;
	MD5_CTX _md5_ctx;
	SHA1_CTX _sha1_ctx;
	SHA256_CTX _sha256_ctx;
	SHA512_CTX _sha512_ctx;

	Crc32Init(&_crc32_ctx);
	Md5Init(&_md5_ctx);
	Sha1Init(&_sha1_ctx);
	Sha256Init(&_sha256_ctx);
	Sha512Init(&_sha512_ctx);

	const int numThreads = 6;
	std::vector<std::thread> threads;
	threads.reserve(numThreads);

	while (ReadFile(hFile, buffer.data(), static_cast<DWORD>(buffer.size()), &bytesRead, NULL) && bytesRead > 0) {
		const uint8_t* dataPtr = buffer.data();
		const size_t len = static_cast<size_t>(bytesRead);
		
		threads.clear();
		threads.push_back(std::thread([dataPtr, len, &_crc32_ctx]() { Crc32Update(&_crc32_ctx, dataPtr, len); }));
		threads.push_back(std::thread([dataPtr, len, &_md5_ctx]() { Md5Update(&_md5_ctx, dataPtr, len); }));
		threads.push_back(std::thread([dataPtr, len, &_sha1_ctx]() { Sha1Update(&_sha1_ctx, dataPtr, len); }));
		threads.push_back(std::thread([dataPtr, len, &_sha256_ctx]() { Sha256Update(&_sha256_ctx, dataPtr, len); }));
		threads.push_back(std::thread([dataPtr, len, &_sha512_ctx]() { Sha512Update(&_sha512_ctx, dataPtr, len); }));
		
		for (auto& thread : threads) thread.join();

		totalRead += bytesRead;

		int currentProgress = static_cast<int>((totalRead * 100) / filesize);
		if (currentProgress != lastProgress) {
			SetProcessProgress(currentProgress);
			lastProgress = currentProgress;
		}
	}

	CloseHandle(hFile);

	// 获取最终哈希值
    crc32 = Crc32HexDigestW(&_crc32_ctx);
    md5 = Md5HexDigestW(&_md5_ctx);
    sha1 = Sha1HexDigestW(&_sha1_ctx);
    sha256 = Sha256HexDigestW(&_sha256_ctx);
    sha512 = Sha512HexDigestW(&_sha512_ctx);

    progressTip = L"哈希计算完成: ";
    SetProcessProgress(100);
	if (pTaskbarList) {
		pTaskbarList->SetProgressValue(hWnd, 0, 100);
		pTaskbarList->SetProgressState(hWnd, TBPF_NOPROGRESS);
	}
	isTaskBarNormalState = false;

	DialogBox(hInstance, MAKEINTRESOURCE(IDD_HASH), hWnd, HashDlgProc);

	EnableControls(true);
	SendMessageW(hToolBar, TB_ENABLEBUTTON, (WPARAM)IDC_TBTN_HASH, (LPARAM)TRUE);
}

INT_PTR CALLBACK AboutDlgProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
	switch (uMsg) {
	case WM_INITDIALOG: {
		HWND hEdit = GetDlgItem(hwnd, IDC_EDIT_TEXT_ABOUT);
		std::wstring text = (L"UltrAES - 可靠的文件加解密工具\n"
			"版本1.1.0 (Build 162)\n"
			"Copyright (c) 2025-2026 金煜力");
		SetWindowTextW(hEdit, text.c_str());

		CHARFORMAT2 cf;
		ZeroMemory(&cf, sizeof(CHARFORMAT2));
		cf.cbSize = sizeof(CHARFORMAT2);
		cf.dwMask = CFM_FACE | CFM_SIZE | CFM_COLOR | CFM_BOLD;
		cf.yHeight = 180;
		cf.crTextColor = RGB(0, 0, 0);
		wcscpy_s(cf.szFaceName, L"Segoe UI");
		SendMessageW(hEdit, EM_SETCHARFORMAT, SCF_ALL, (LPARAM)&cf);

		SendMessageW(hEdit, EM_SETSEL, 0, 20);
		cf.yHeight = 200;
		cf.dwEffects = CFE_BOLD;
		SendMessageW(hEdit, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
		SendMessageW(hEdit, EM_SETSEL, 0, 0);

		return TRUE;
	}
	case WM_COMMAND: {
		switch (LOWORD(wParam)) {
		case IDOK: {
			SendMessageW(hwnd, WM_CLOSE, 0, 0);
			break;
		}
		}
		break;
	}
	case WM_CLOSE: {
		EndDialog(hwnd, 0);
		break;
	}
	}
	return FALSE;
}

void OnTBtnAbout() {
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_ABOUT), hWnd, AboutDlgProc);
}

void OnDropFile(HDROP hDrop) {
	if (g_isProcessing.load()) {
		DragFinish(hDrop);
		return;
	}
	
	UINT fileCount = DragQueryFileW(hDrop, 0xFFFFFFFF, NULL, 0);

	if (fileCount == 0) {
		DragFinish(hDrop);
		return;
	}

	wchar_t filePath[MAX_PATH];
	if (DragQueryFileW(hDrop, 0, filePath, MAX_PATH) > 0) {
		DWORD attr = GetFileAttributesW(filePath);
		if (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY)) {
			MessageBox(hWnd, L"不支持文件夹拖放，请拖放单个文件", L"UltrAES", MB_ICONWARNING);
			DragFinish(hDrop);
			return;
		}
		
		if (_waccess(filePath, 0) == -1) {
			MessageBox(hWnd, L"文件不存在或无法访问", L"UltrAES", MB_ICONERROR);
			DragFinish(hDrop);
			return;
		}
		
		if (usePwd) {
			SetWindowTextW(GetDlgItem(hWnd, IDC_EDIT_INPUT_FILE), filePath);
		}
		else {
			UINT mbres = MessageBox(hWnd, L"消除歧义：是否要将拖入的文件作为密钥文件？", L"UltrAES", MB_YESNOCANCEL | MB_ICONQUESTION);
			if (mbres == IDYES) {
				SetWindowTextW(GetDlgItem(hWnd, IDC_EDIT_KEY), filePath);
			}
			else if (mbres == IDNO) {
				SetWindowTextW(GetDlgItem(hWnd, IDC_EDIT_INPUT_FILE), filePath);
			}
		}
	}
	DragFinish(hDrop);
}

void OnEditInputFileChange() {
	wchar_t infilename[MAX_PATH];
	GetWindowTextW(GetDlgItem(hWnd, IDC_EDIT_INPUT_FILE), infilename, MAX_PATH);
	std::wstring outFileName;
	if (wcslen(infilename) > 0) {
		if (str_endwith(infilename, L".enc", true)) {
			outFileName = removeLastExtName(infilename);
		}
		else {
			outFileName = std::wstring(infilename) + L".enc";
		}
	}
	else {
		outFileName = L"";
	}
	SetWindowTextW(GetDlgItem(hWnd, IDC_EDIT_OUTPUT_FILE), outFileName.c_str());
}

bool initWindow() {
	// 初始化任务栏接口
	HRESULT hr = CoInitialize(NULL);
	if (FAILED(hr)) {
		MessageBox(hWnd, L"COM初始化失败！", L"UltrAES", MB_ICONERROR);
		return false;
	}
	hr = CoCreateInstance(CLSID_TaskbarList, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&pTaskbarList));
	if (SUCCEEDED(hr)) {
		hr = pTaskbarList->HrInit();
		if (FAILED(hr)) {
			pTaskbarList->Release();
			CoUninitialize();
			MessageBox(hWnd, L"ITaskbarList3初始化失败！", L"UltrAES", MB_ICONERROR);
			return false;
		}
	}
	else {
		CoUninitialize();
		MessageBox(hWnd, L"创建ITaskbarList3实例失败！", L"UltrAES", MB_ICONERROR);
		return false;
	}
	// 加载RichEdit定义
	hRichedMod = LoadLibraryW(L"Riched20.dll");
	if (hRichedMod == NULL) {
		MessageBox(hWnd, L"无法加载RichEdit定义！", L"UltrAES", MB_ICONERROR);
		return false;
	}
	// 设置窗口图标
	hIcon = LoadIconW(hInstance, MAKEINTRESOURCE(IDI_ICON_ULTRAES));
	SendMessageW(hWnd, WM_SETICON, 0, (LPARAM)hIcon);
	// 处理模式下拉框
	HWND hCombo = GetDlgItem(hWnd, IDC_COMBO_MODE);
	SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"自动检测");
	SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"加密");
	SendMessageW(hCombo, CB_ADDSTRING, 0, (LPARAM)L"解密");
	SendMessageW(hCombo, CB_SETCURSEL, 0, 0);
	// 密钥文件分割按钮
	KeyfileSplitDropMenu = GetSubMenu(LoadMenuW(hInstance, MAKEINTRESOURCE(IDR_MENU_KEYFILE_SPLIT)), 0);
	CheckMenuItem(KeyfileSplitDropMenu, IDM_KEYFILE_DROP_OPENKEY, MF_CHECKED | MF_BYCOMMAND);
	CheckMenuItem(KeyfileSplitDropMenu, IDM_KEYFILE_DROP_GENKEY, MF_UNCHECKED | MF_BYCOMMAND);
	// 读取配置
	const char* default_ini =
		"[startup]\n"
		"UsePwd = false\n"
		"WindowOnTop = true\n";
	inifile = ini_create_ctx();
	ini_set_case_sensitive(inifile, true);
	INI_ERROR_CODE error = ini_load_from_file(inifile, "config.ini");
	if (error != INI_SUCCESS ||
		!ini_has_section(inifile, "startup") ||
		!ini_has_key(inifile, "startup", "UsePwd") || !ini_has_key(inifile, "startup", "WindowOnTop")) {
		ini_load_from_string(inifile, default_ini);
		ini_save_to_file(inifile, "config.ini");
	}
	usePwd = ini_get_bool(inifile, "startup", "UsePwd", false);
	winAOnTop = ini_get_bool(inifile, "startup", "WindowOnTop", true);
	// 密钥选项
	CheckDlgButton(hWnd, IDC_CHECK_USEPWD, usePwd ? BST_CHECKED : BST_UNCHECKED);
	ShowWindow(GetDlgItem(hWnd, IDC_CHECK_SHOWPWD), usePwd ? SW_SHOW : SW_HIDE);
	if (usePwd) {
		OnCheckShowPwd();
	}
	EnableWindow(GetDlgItem(hWnd, IDC_SPLIT_KEYFILE), !usePwd);
	// 窗口始终置顶
	CheckDlgButton(hWnd, IDC_CHECK_WINTOPMOST, winAOnTop ? BST_CHECKED : BST_UNCHECKED);
	SetWindowAlwaysOnTop(hWnd, winAOnTop);
	// 设置进度条文本
	HWND hProgress = GetDlgItem(hWnd, IDC_PROGRESSBAR);
	SetWindowSubclass(hProgress, ProgressBarProc, 1, 0);
	SendMessageW(hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
	SendMessageW(hProgress, PBM_SETPOS, 0, 0);
    SetTextProgressBarText(hProgress, std::wstring(L"准备就绪"));
	// 创建底部工具栏
	hToolBar = CreateToolBarAtControlPos(hWnd, IDC_TOOLBAR_RECT, true);
	TBBUTTON tbButtons[] = {
		// iBitmap, idCommand, fsState, fsStyle, bReserved, dwData, iString
		{ 0, IDC_TBTN_HASH, TBSTATE_ENABLED, TBSTYLE_BUTTON, 0, 0, 0 },
		{ 1, IDC_TBTN_ABOUT, TBSTATE_ENABLED, TBSTYLE_BUTTON, 0, 0, 0 }
	};
	HIMAGELIST hImageList = ImageList_Create(20, 20, ILC_COLOR32 | ILC_MASK, 8, 0);
	ImageList_AddIcon(hImageList, LoadIconW(hInstance, MAKEINTRESOURCE(IDI_ICON_HASH)));
	ImageList_AddIcon(hImageList, LoadIconW(hInstance, MAKEINTRESOURCE(IDI_ICON_ABOUT)));
	// 添加按钮到工具栏
	SendMessageW(hToolBar, TB_ADDBUTTONS,
		(WPARAM)sizeof(tbButtons) / sizeof(TBBUTTON),
		(LPARAM)&tbButtons);
	SendMessageW(hToolBar, TB_SETIMAGELIST, 0, (LPARAM)hImageList);
	SendMessageW(hToolBar, TB_ENABLEBUTTON, (WPARAM)IDC_TBTN_HASH, (LPARAM)FALSE);
	// 允许拖入文件
	DragAcceptFiles(hWnd, TRUE);

	return true;
}

INT_PTR CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_INITDIALOG: {
        MoveWindowToMidOfScreen(hwnd);
        hInstance = GetModuleHandleW(NULL);
        hWnd = hwnd;
        if (!initWindow()) {
            SendMessageW(hWnd, WM_CLOSE, 0, 0);
            return FALSE;
        }
        return TRUE;
    }

    case WM_NOTIFY: {
        LPNMHDR nmhdr = (LPNMHDR)lParam;
        if (nmhdr->idFrom == IDC_SPLIT_KEYFILE && nmhdr->code == BCN_DROPDOWN) {
            LPNMBCDROPDOWN pDropDown = (LPNMBCDROPDOWN)lParam;
            RECT rcButton;
            GetWindowRect(GetDlgItem(hwnd, IDC_SPLIT_KEYFILE), &rcButton);
            TrackPopupMenu(
                KeyfileSplitDropMenu,
                TPM_LEFTALIGN | TPM_TOPALIGN,
                rcButton.left,
                rcButton.bottom,
                0,
                hwnd,
                NULL);
            return TRUE;
        }
        if (nmhdr->code == TTN_GETDISPINFO) {
            LPTOOLTIPTEXT lpttt = (LPTOOLTIPTEXT)lParam;
            switch (lpttt->hdr.idFrom) {
            case IDC_TBTN_HASH: {
                lstrcpyW(lpttt->szText, L"计算输出文件哈希值");
                break;
            }
            case IDC_TBTN_ABOUT: {
                lstrcpyW(lpttt->szText, L"关于");
                break;
            }
            }
            return TRUE;
        }
        break;
    }

    case WM_DROPFILES: {
        OnDropFile((HDROP)wParam);
        return TRUE;
    }
    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case IDC_EDIT_INPUT_FILE: {
            if (HIWORD(wParam) == EN_CHANGE) {
                OnEditInputFileChange();
                return TRUE;
            }
            break;
        }
        case IDC_BTN_OPEN_INPUT_FILE: {
            OnBtnOpenInputFile();
            return TRUE;
        }
        case IDC_BTN_SAVE_OUTFILE: {
            OnBtnSaveOutFile();
            return TRUE;
        }
        case IDM_KEYFILE_DROP_OPENKEY: {
            OnMenuKeyfileSplitOpenKey();
            return TRUE;
        }
        case IDM_KEYFILE_DROP_GENKEY: {
            OnMenuKeyfileSplitGenKey();
            return TRUE;
        }
        case IDC_CHECK_USEPWD: {
            OnCheckUsePwd();
            return TRUE;
        }
        case IDC_CHECK_SHOWPWD: {
            OnCheckShowPwd();
            return TRUE;
        }
        case IDC_CHECK_WINTOPMOST: {
            OnCheckWinTopmost();
            return TRUE;
        }
        case IDC_SPLIT_KEYFILE: {
            OnSplitKeyfile();
            return TRUE;
        }
        case IDC_BTN_START_CRYPT: {
            if (!g_isProcessing.load()) {
                std::thread t_crypt(&OnBtnStartCrypt);
                t_crypt.detach();
                g_isProcessing.store(true);
                SetDlgItemTextW(hWnd, IDC_BTN_START_CRYPT, L"暂停");
            }
            else {
                if (!is_processing_paused()) {
                    request_pause();
                    SetDlgItemTextW(hWnd, IDC_BTN_START_CRYPT, L"继续");
                    EnableWindow(GetDlgItem(hWnd, IDC_BTN_EXIT), TRUE);
                    if (pTaskbarList) {
                        pTaskbarList->SetProgressState(hWnd, TBPF_PAUSED);
                        isTaskBarNormalState = false;
                    }
					SetTextProgressBarMode(GetDlgItem(hWnd, IDC_PROGRESSBAR), TPBMOD_PAUSE);
                }
                else {
                    resume_processing();
                    SetDlgItemTextW(hWnd, IDC_BTN_START_CRYPT, L"暂停");
                    EnableWindow(GetDlgItem(hWnd, IDC_BTN_START_CRYPT), TRUE);
                    EnableWindow(GetDlgItem(hWnd, IDC_BTN_EXIT), FALSE);
                    if (pTaskbarList) {
                        pTaskbarList->SetProgressState(hWnd, TBPF_NORMAL);
                        isTaskBarNormalState = true;
                    }
					SetTextProgressBarMode(GetDlgItem(hWnd, IDC_PROGRESSBAR), TPBMOD_NORMAL);
                }
            }
            return TRUE;
        }
        case IDC_BTN_EXIT: {
            SendMessageW(hwnd, WM_CLOSE, 0, 0);
            return TRUE;
        }
        case IDC_TBTN_HASH: {
            std::thread t_calchash(&OnTBtnHash);
            t_calchash.detach();
            return TRUE;
        }
        case IDC_TBTN_ABOUT: {
            OnTBtnAbout();
            return TRUE;
        }
        }
        break;
    }

    case WM_CLOSE: {
        EndDialog(hwnd, 0);
        return TRUE;
    }

    case WM_DESTROY: {
        if (pTaskbarList) {
            pTaskbarList->Release();
            pTaskbarList = nullptr;
        }
        CoUninitialize();
        if (hRichedMod) {
            FreeLibrary(hRichedMod);
            hRichedMod = nullptr;
        }
		ini_free_ctx(inifile);
        PostQuitMessage(0);
        return TRUE;
    }
    }
    return FALSE;
}

int APIENTRY wWinMain(
	_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR lpCmdLine,
	_In_ int nCmdShow
) {
	int argc;
	LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argc == 3 && lstrcmpW(argv[1], L"-s") == 0) {
		if (AllocConsole()) {
			FILE* fp;
			freopen_s(&fp, "CONOUT$", "w", stdout);
			freopen_s(&fp, "CONOUT$", "w", stderr);
			freopen_s(&fp, "CONIN$", "r", stdin);

			SetConsoleOutputCP(CP_UTF8);
			SetConsoleCP(CP_UTF8);
			int flag = _setmode(_fileno(stdout), _O_U8TEXT);

			RunUAScriptFile(argv[2]);
			
			wprintf(L"请按任意键退出: ");
			int ch = _getch();
		}
        return 0;
    }
	EnableHighDpi();
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG), NULL, WndProc);
	return 0;
}