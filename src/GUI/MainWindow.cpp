#include "GUI/MainWindow.h"
#include "GUI/Theme.h"
#include "GUI/Panels/OverviewPanel.h"
#include "GUI/Panels/SectionsPanel.h"
#include "GUI/Panels/ImportsPanel.h"
#include "GUI/Panels/ExportsPanel.h"
#include "GUI/Panels/TLSPanel.h"
#include "GUI/Panels/ResourcesPanel.h"
#include "GUI/Panels/StringsPanel.h"
#include "GUI/Panels/HexPanel.h"
#include "GUI/Panels/AnalysisPanel.h"
#include "Core/PEParser.h"
#include "Export/JSONExporter.h"
#include "Utils/StringUtils.h"
#include "Utils/HexFormatter.h"
#include "resource.h"
#include <shellapi.h>
#include <uxtheme.h>
#include <sstream>

#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "UxTheme.lib")

HWND            MainWindow::s_hwnd        = nullptr;
HWND            MainWindow::s_hwndTab     = nullptr;
HWND            MainWindow::s_hwndStatus  = nullptr;
HWND            MainWindow::s_hwndToolbar = nullptr;
HWND            MainWindow::s_hwndBtnOpen   = nullptr;
HWND            MainWindow::s_hwndBtnExport = nullptr;
HWND            MainWindow::s_hwndBtnSaveOverlay = nullptr;
HWND            MainWindow::s_hwndFileInfo  = nullptr;
HWND            MainWindow::s_panels[9] = {};
PEAnalysisResult MainWindow::s_result     = {};
PEFile          MainWindow::s_peFile     = {};
HINSTANCE       MainWindow::s_hInstance   = nullptr;
int             MainWindow::s_currentTab  = 0;
bool            MainWindow::s_hasFile     = false;

static const wchar_t* TAB_LABELS[9] = {
    L"  Overview  ",
    L"  Sections  ",
    L"  Imports   ",
    L"  Exports   ",
    L"  TLS       ",
    L"  Resources ",
    L"  Strings   ",
    L"  Hex View  ",
    L"  Analysis  "
};

bool MainWindow::Register(HINSTANCE hInstance) {
    s_hInstance = hInstance;

    OverviewPanel::Register(hInstance);
    SectionsPanel::Register(hInstance);
    ImportsPanel::Register(hInstance);
    ExportsPanel::Register(hInstance);
    TLSPanel::Register(hInstance);
    ResourcesPanel::Register(hInstance);
    StringsPanel::Register(hInstance);
    HexPanel::Register(hInstance);
    AnalysisPanel::Register(hInstance);

    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hbrBackground = Theme::brushBgPrimary;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.hIcon         = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hIconSm       = LoadIcon(nullptr, IDI_APPLICATION);
    return RegisterClassExW(&wc) != 0;
}

HWND MainWindow::Create(HINSTANCE hInstance) {
    HWND hwnd = CreateWindowExW(
        WS_EX_ACCEPTFILES,
        CLASS_NAME,
        L"PE Parser & Analyzer",
        WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
        CW_USEDEFAULT, CW_USEDEFAULT,
        1280, 780,
        nullptr, nullptr, hInstance, nullptr);
    return hwnd;
}

int MainWindow::RunMessageLoop() {
    MSG msg = {};
    while (GetMessageW(&msg, nullptr, 0, 0)) {
        if (!IsDialogMessageW(s_hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    return (int)msg.wParam;
}

void MainWindow::CreateToolbarArea(HWND hwnd) {
    s_hwndToolbar = CreateWindowExW(0, L"STATIC", L"",
        WS_CHILD | WS_VISIBLE, 0, 0, 100, TOOLBAR_H, hwnd, nullptr, s_hInstance, nullptr);

    s_hwndBtnOpen = CreateWindowExW(0, L"BUTTON", L"Open PE File",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        14, 12, 140, 36, hwnd, (HMENU)ID_FILE_OPEN, s_hInstance, nullptr);
    SendMessageW(s_hwndBtnOpen, WM_SETFONT, (WPARAM)Theme::fontBold, TRUE);

    s_hwndBtnExport = CreateWindowExW(0, L"BUTTON", L"Export JSON",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        162, 12, 130, 36, hwnd, (HMENU)ID_FILE_EXPORT, s_hInstance, nullptr);
    SendMessageW(s_hwndBtnExport, WM_SETFONT, (WPARAM)Theme::fontUI, TRUE);
    EnableWindow(s_hwndBtnExport, FALSE);

    s_hwndBtnSaveOverlay = CreateWindowExW(0, L"BUTTON", L"Save Overlay",
        WS_CHILD | WS_VISIBLE | BS_OWNERDRAW,
        298, 12, 120, 36, hwnd, (HMENU)ID_FILE_SAVE_OVERLAY, s_hInstance, nullptr);
    SendMessageW(s_hwndBtnSaveOverlay, WM_SETFONT, (WPARAM)Theme::fontUI, TRUE);
    EnableWindow(s_hwndBtnSaveOverlay, FALSE);

    s_hwndFileInfo = CreateWindowExW(0, L"STATIC",
        L"Drag & drop a .exe or .dll file here, or click  Open PE File",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        430, 16, 800, 28, hwnd, nullptr, s_hInstance, nullptr);
    SendMessageW(s_hwndFileInfo, WM_SETFONT, (WPARAM)Theme::fontUI, TRUE);
}

void MainWindow::CreateTabControl(HWND hwnd) {
    s_hwndTab = CreateWindowExW(0, WC_TABCONTROLW, L"",
        WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN | TCS_FLATBUTTONS | TCS_OWNERDRAWFIXED,
        0, TOOLBAR_H, 100, 100, hwnd, nullptr, s_hInstance, nullptr);
    SendMessageW(s_hwndTab, WM_SETFONT, (WPARAM)Theme::fontUI, TRUE);

    TCITEMW tci = {};
    tci.mask = TCIF_TEXT;
    for (int i = 0; i < PANEL_COUNT; ++i) {
        tci.pszText = const_cast<wchar_t*>(TAB_LABELS[i]);
        TabCtrl_InsertItem(s_hwndTab, i, &tci);
    }
}

void MainWindow::CreateStatusBar(HWND hwnd) {
    s_hwndStatus = CreateWindowExW(0, STATUSCLASSNAMEW, L"",
        WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
        0, 0, 0, 0, hwnd, nullptr, s_hInstance, nullptr);
    SetWindowTheme(s_hwndStatus, L"DarkMode_Explorer", nullptr);
    SendMessageW(s_hwndStatus, SB_SETBKCOLOR, 0, (LPARAM)Theme::BG_TOOLBAR);
    SendMessageW(s_hwndStatus, WM_SETFONT, (WPARAM)Theme::fontSmall, TRUE);

    int parts[] = { 300, 500, 750, -1 };
    SendMessageW(s_hwndStatus, SB_SETPARTS, 4, (LPARAM)parts);
    SendMessageW(s_hwndStatus, SB_SETTEXTW, 0, (LPARAM)L"  Ready — Open a PE file to begin");
}

void MainWindow::CreateAllPanels(HWND hwnd) {
    RECT rc; GetClientRect(hwnd, &rc);
    int tabHeaderHeight = 35;
    int px = 0;
    int py = TOOLBAR_H + tabHeaderHeight;
    int pw = rc.right;
    int ph = rc.bottom - py - STATUS_H;

    s_panels[0] = OverviewPanel::Create(hwnd, s_hInstance, px, py, pw, ph);
    s_panels[1] = SectionsPanel::Create(hwnd, s_hInstance, px, py, pw, ph);
    s_panels[2] = ImportsPanel::Create(hwnd, s_hInstance, px, py, pw, ph);
    s_panels[3] = ExportsPanel::Create(hwnd, s_hInstance, px, py, pw, ph);
    s_panels[4] = TLSPanel::Create(hwnd, s_hInstance, px, py, pw, ph);
    s_panels[5] = ResourcesPanel::Create(hwnd, s_hInstance, px, py, pw, ph);
    s_panels[6] = StringsPanel::Create(hwnd, s_hInstance, px, py, pw, ph);
    s_panels[7] = HexPanel::Create(hwnd, s_hInstance, px, py, pw, ph);
    s_panels[8] = AnalysisPanel::Create(hwnd, s_hInstance, px, py, pw, ph);

    for (int i = 1; i < PANEL_COUNT; ++i)
        ShowWindow(s_panels[i], SW_HIDE);
}

void MainWindow::OnCreate(HWND hwnd) {
    s_hwnd = hwnd;
    Theme::ApplyDarkTitleBar(hwnd);

    HMENU hMenu = CreateMenu();
    HMENU hFile = CreatePopupMenu();
    AppendMenuW(hFile, MF_STRING, ID_FILE_OPEN,   L"&Open PE File...\tCtrl+O");
    AppendMenuW(hFile, MF_STRING, ID_FILE_EXPORT, L"Export &JSON...\tCtrl+S");
    AppendMenuW(hFile, MF_STRING, ID_FILE_SAVE_OVERLAY, L"Save &Overlay...");
    AppendMenuW(hFile, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(hFile, MF_STRING, ID_FILE_EXIT,   L"E&xit\tAlt+F4");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hFile, L"&File");

    HMENU hHelp = CreatePopupMenu();
    AppendMenuW(hHelp, MF_STRING, ID_HELP_ABOUT, L"&About");
    AppendMenuW(hMenu, MF_POPUP, (UINT_PTR)hHelp, L"&Help");
    SetMenu(hwnd, hMenu);

    CreateToolbarArea(hwnd);
    CreateTabControl(hwnd);
    CreateStatusBar(hwnd);
    CreateAllPanels(hwnd);

    DragAcceptFiles(hwnd, TRUE);
}

void MainWindow::OnSize(HWND hwnd, int w, int h) {
    int contentY = TOOLBAR_H;
    int tabHeaderHeight = 35;

    if (s_hwndToolbar) SetWindowPos(s_hwndToolbar, nullptr, 0, 0, w, TOOLBAR_H, SWP_NOZORDER);
    if (s_hwndTab)     SetWindowPos(s_hwndTab,     nullptr, 0, contentY, w, tabHeaderHeight, SWP_NOZORDER);
    if (s_hwndStatus)  SendMessageW(s_hwndStatus, WM_SIZE, 0, MAKELPARAM(w, STATUS_H));

    int px = 0;
    int py = contentY + tabHeaderHeight;
    int pw = w;
    int ph = h - py - STATUS_H;

    for (int i = 0; i < PANEL_COUNT; ++i) {
        if (s_panels[i]) {
            SetWindowPos(s_panels[i], nullptr, px, py, pw, ph, SWP_NOZORDER);
        }
    }

    int sbParts[] = { w / 4, w / 2, 3 * w / 4, -1 };
    SendMessageW(s_hwndStatus, SB_SETPARTS, 4, (LPARAM)sbParts);

    InvalidateRect(hwnd, nullptr, TRUE);
}

void MainWindow::SwitchToTab(int tabIndex) {
    if (tabIndex < 0 || tabIndex >= PANEL_COUNT) return;
    for (int i = 0; i < PANEL_COUNT; ++i)
        ShowWindow(s_panels[i], i == tabIndex ? SW_SHOW : SW_HIDE);
    s_currentTab = tabIndex;
}

void MainWindow::UpdateStatusBar() {
    if (!s_hasFile) {
        SendMessageW(s_hwndStatus, SB_SETTEXTW, 0, (LPARAM)L"  Ready");
        return;
    }
    std::wstring arch = s_result.is64Bit ? L"x64 (PE32+)" : L"x86 (PE32)";
    std::wstring size = AnsiToWide(FormatFileSize(s_result.fileSize));
    std::wstring secs = L"Sections: " + std::to_wstring(s_result.sections.size());
    std::wstring imps = L"Imports: " + std::to_wstring(s_result.imports.size()) + L" DLLs";

    std::wstring info = L"  " + AnsiToWide(s_result.fileName) + L"  |  " + arch + L"  |  " + size;
    SendMessageW(s_hwndStatus, SB_SETTEXTW, 0, (LPARAM)info.c_str());
    SendMessageW(s_hwndStatus, SB_SETTEXTW, 1, (LPARAM)(L"  " + secs).c_str());
    SendMessageW(s_hwndStatus, SB_SETTEXTW, 2, (LPARAM)(L"  " + imps).c_str());

    int critCount = 0;
    for (const auto& f : s_result.suspiciousFlags)
        if (f.level == SuspiciousLevel::Critical) ++critCount;
    std::wstring warn = critCount > 0 ?
        L"  CRITICAL: " + std::to_wstring(critCount) + L" flags!" : L"  No critical flags";
    SendMessageW(s_hwndStatus, SB_SETTEXTW, 3, (LPARAM)warn.c_str());
}

void MainWindow::UpdateAllPanels() {
    OverviewPanel::Populate(s_panels[0], s_result);
    SectionsPanel::Populate(s_panels[1], s_result);
    ImportsPanel::Populate(s_panels[2],  s_result);
    ExportsPanel::Populate(s_panels[3],  s_result);
    TLSPanel::Populate(s_panels[4],      s_result);
    ResourcesPanel::Populate(s_panels[5], s_result);
    StringsPanel::Populate(s_panels[6], s_result);
    HexPanel::Populate(s_panels[7], s_result, s_peFile.GetBase());
    AnalysisPanel::Populate(s_panels[8], s_result);
}

void MainWindow::LoadPEFile(HWND hwnd, const std::wstring& path) {
    SendMessageW(s_hwndStatus, SB_SETTEXTW, 0, (LPARAM)L"  Parsing...");
    SetCursor(LoadCursor(nullptr, IDC_WAIT));

    s_peFile.Unload();
    s_peFile.Load(path);

    s_result   = PEParser::Parse(path);
    s_hasFile  = true;

    SetCursor(LoadCursor(nullptr, IDC_ARROW));

    if (!s_result.isValid) {
        std::wstring err = L"Parse error: " + AnsiToWide(s_result.errorMessage);
        SetWindowTextW(s_hwndFileInfo, err.c_str());
        SendMessageW(s_hwndStatus, SB_SETTEXTW, 0, (LPARAM)L"  Error parsing file");
        MessageBoxW(hwnd, err.c_str(), L"PE Parser — Error", MB_ICONERROR | MB_OK);
        return;
    }

    std::wstring arch = s_result.is64Bit ? L"PE32+ (64-bit)" : L"PE32 (32-bit)";
    std::wstring info = AnsiToWide(s_result.fileName) + L"   |   " + arch +
        L"   |   " + AnsiToWide(FormatFileSize(s_result.fileSize));
    SetWindowTextW(s_hwndFileInfo, info.c_str());

    EnableWindow(s_hwndBtnExport, TRUE);
    EnableWindow(s_hwndBtnSaveOverlay, s_result.hasOverlay ? TRUE : FALSE);
    UpdateAllPanels();
    UpdateStatusBar();
    SwitchToTab(s_currentTab);
    TabCtrl_SetCurSel(s_hwndTab, s_currentTab);

    std::wstring title = L"PE Parser & Analyzer — " + AnsiToWide(s_result.fileName);
    SetWindowTextW(hwnd, title.c_str());
}

void MainWindow::OpenFile(HWND hwnd) {
    wchar_t szFile[MAX_PATH] = {};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = hwnd;
    ofn.lpstrFile    = szFile;
    ofn.nMaxFile     = MAX_PATH;
    ofn.lpstrFilter  = L"PE Files (*.exe;*.dll;*.sys;*.ocx)\0*.exe;*.dll;*.sys;*.ocx\0All Files (*.*)\0*.*\0";
    ofn.lpstrTitle   = L"Open PE File";
    ofn.Flags        = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (GetOpenFileNameW(&ofn)) {
        LoadPEFile(hwnd, szFile);
    }
}

void MainWindow::ExportJSON(HWND hwnd) {
    if (!s_hasFile || !s_result.isValid) return;
    wchar_t szFile[MAX_PATH] = {};
    wcscpy_s(szFile, AnsiToWide(s_result.fileName).c_str());
    wcscat_s(szFile, L".json");

    OPENFILENAMEW ofn = {};
    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = hwnd;
    ofn.lpstrFile    = szFile;
    ofn.nMaxFile     = MAX_PATH;
    ofn.lpstrFilter  = L"JSON Files (*.json)\0*.json\0All Files (*.*)\0*.*\0";
    ofn.lpstrTitle   = L"Export Analysis as JSON";
    ofn.lpstrDefExt  = L"json";
    ofn.Flags        = OFN_OVERWRITEPROMPT;
    if (GetSaveFileNameW(&ofn)) {
        bool ok = JSONExporter::Export(s_result, std::wstring(szFile));
        if (ok) {
            MessageBoxW(hwnd, (L"Exported successfully:\n" + std::wstring(szFile)).c_str(),
                L"Export Complete", MB_ICONINFORMATION | MB_OK);
        } else {
            MessageBoxW(hwnd, L"Failed to write JSON file.", L"Export Error", MB_ICONERROR | MB_OK);
        }
    }
}

void MainWindow::ShowAbout(HWND hwnd) {
    MessageBoxW(hwnd,
        L"PE Parser & Analyzer v1.0\n\n"
        L"A reverse engineering tool for analyzing Windows\n"
        L"Portable Executable (PE) files.\n\n"
        L"Supports: PE32 (x86) and PE32+ (x64)\n"
        L"Features: DOS/File/Optional Headers, Sections,\n"
        L"          IAT, EAT, TLS Callbacks, Resources,\n"
        L"          Suspicious Analysis, JSON Export\n\n"
        L"Built with C++20 + Win32 API",
        L"About PE Parser", MB_ICONINFORMATION | MB_OK);
}

void MainWindow::OnCommand(HWND hwnd, WPARAM wParam) {
    switch (LOWORD(wParam)) {
    case ID_FILE_OPEN:   OpenFile(hwnd);   break;
    case ID_FILE_EXPORT: ExportJSON(hwnd); break;
    case ID_FILE_SAVE_OVERLAY: SaveOverlay(hwnd); break;
    case ID_FILE_EXIT:   DestroyWindow(hwnd); break;
    case ID_HELP_ABOUT:  ShowAbout(hwnd);  break;
    }
}

void MainWindow::OnNotify(HWND hwnd, LPARAM lParam) {
    auto* hdr = reinterpret_cast<NMHDR*>(lParam);
    if (hdr->hwndFrom == s_hwndTab && hdr->code == TCN_SELCHANGE) {
        int sel = TabCtrl_GetCurSel(s_hwndTab);
        SwitchToTab(sel);
    }
}

void MainWindow::OnDropFiles(HWND hwnd, HDROP hDrop) {
    wchar_t path[MAX_PATH] = {};
    if (DragQueryFileW(hDrop, 0, path, MAX_PATH) > 0) {
        LoadPEFile(hwnd, path);
    }
    DragFinish(hDrop);
}

void MainWindow::SaveOverlay(HWND hwnd) {
    if (!s_hasFile || !s_result.hasOverlay) return;
    wchar_t szFile[MAX_PATH] = {};
    wcscpy_s(szFile, AnsiToWide(s_result.fileName).c_str());
    wcscat_s(szFile, L"_overlay.bin");

    OPENFILENAMEW ofn = {};
    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = hwnd;
    ofn.lpstrFile    = szFile;
    ofn.nMaxFile     = MAX_PATH;
    ofn.lpstrFilter  = L"Binary Files (*.bin)\0*.bin\0All Files (*.*)\0*.*\0";
    ofn.lpstrTitle   = L"Save Overlay Payload";
    ofn.lpstrDefExt  = L"bin";
    ofn.Flags        = OFN_OVERWRITEPROMPT;
    if (GetSaveFileNameW(&ofn)) {
        HANDLE hFile = CreateFileW(ofn.lpstrFile, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            const BYTE* overlayData = s_peFile.GetBase() + s_result.overlayOffset;
            WriteFile(hFile, overlayData, static_cast<DWORD>(s_result.overlaySize), &written, nullptr);
            CloseHandle(hFile);
            MessageBoxW(hwnd, L"Overlay saved successfully!", L"Save Complete", MB_ICONINFORMATION | MB_OK);
        } else {
            MessageBoxW(hwnd, L"Failed to save overlay file.", L"Error", MB_ICONERROR | MB_OK);
        }
    }
}

void MainWindow::OnPaint(HWND hwnd) {
    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hwnd, &ps);

    RECT rc; GetClientRect(hwnd, &rc);
    RECT toolbarRect = { 0, 0, rc.right, TOOLBAR_H };
    FillRect(hdc, &toolbarRect, Theme::brushBgToolbar);

    HPEN pen = CreatePen(PS_SOLID, 1, Theme::ACCENT_PURPLE);
    HPEN oldPen = (HPEN)SelectObject(hdc, pen);
    MoveToEx(hdc, 0, TOOLBAR_H - 1, nullptr);
    LineTo(hdc, rc.right, TOOLBAR_H - 1);

    HFONT oldFont = (HFONT)SelectObject(hdc, Theme::fontTitle);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, Theme::ACCENT_PURPLE);
    RECT titleRect = { 310, 10, 800, 50 };
    DrawTextW(hdc, L"", -1, &titleRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    SelectObject(hdc, oldFont);
    SelectObject(hdc, oldPen);
    DeleteObject(pen);

    EndPaint(hwnd, &ps);
}

void MainWindow::OnDestroy(HWND hwnd) {
    s_peFile.Unload();
    Theme::Cleanup();
    PostQuitMessage(0);
}

LRESULT CALLBACK MainWindow::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE:
        OnCreate(hwnd);
        return 0;
    case WM_SIZE:
        OnSize(hwnd, LOWORD(lParam), HIWORD(lParam));
        return 0;
    case WM_COMMAND:
        OnCommand(hwnd, wParam);
        return 0;
    case WM_DRAWITEM: {
        DRAWITEMSTRUCT* pdis = reinterpret_cast<DRAWITEMSTRUCT*>(lParam);
        if (pdis->hwndItem == s_hwndTab) {
            int index = pdis->itemID;
            bool selected = (index == TabCtrl_GetCurSel(s_hwndTab));
            FillRect(pdis->hDC, &pdis->rcItem, selected ? Theme::brushBgPrimary : Theme::brushBgToolbar);
            if (selected) {
                HPEN pen = CreatePen(PS_SOLID, 1, Theme::ACCENT_PURPLE);
                HPEN oldPen = (HPEN)SelectObject(pdis->hDC, pen);
                MoveToEx(pdis->hDC, pdis->rcItem.left, pdis->rcItem.bottom - 1, nullptr);
                LineTo(pdis->hDC, pdis->rcItem.right, pdis->rcItem.bottom - 1);
                SelectObject(pdis->hDC, oldPen);
                DeleteObject(pen);
            }
            SetBkMode(pdis->hDC, TRANSPARENT);
            SetTextColor(pdis->hDC, selected ? Theme::TEXT_PRIMARY : Theme::TEXT_MUTED);
            SelectObject(pdis->hDC, selected ? Theme::fontBold : Theme::fontUI);
            RECT textRect = pdis->rcItem;
            DrawTextW(pdis->hDC, TAB_LABELS[index], -1, &textRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            return TRUE;
        }
        if (pdis->hwndItem == s_hwndBtnOpen || pdis->hwndItem == s_hwndBtnExport || pdis->hwndItem == s_hwndBtnSaveOverlay) {
            bool disabled = !IsWindowEnabled(pdis->hwndItem);
            bool pressed = (pdis->itemState & ODS_SELECTED);
            HBRUSH bgBrush = Theme::brushBgInput;
            if (disabled) {
                bgBrush = Theme::brushBgSecondary;
            } else if (pressed) {
                bgBrush = Theme::brushBgPanel;
            }
            FillRect(pdis->hDC, &pdis->rcItem, bgBrush);
            HPEN borderPen = CreatePen(PS_SOLID, 1, disabled ? Theme::SEPARATOR : Theme::BORDER);
            HPEN oldPen = (HPEN)SelectObject(pdis->hDC, borderPen);
            HBRUSH oldBrush = (HBRUSH)SelectObject(pdis->hDC, GetStockObject(NULL_BRUSH));
            RoundRect(pdis->hDC, pdis->rcItem.left, pdis->rcItem.top, pdis->rcItem.right, pdis->rcItem.bottom, 4, 4);
            SelectObject(pdis->hDC, oldBrush);
            SelectObject(pdis->hDC, oldPen);
            DeleteObject(borderPen);
            COLORREF txtCol = Theme::TEXT_PRIMARY;
            if (disabled) {
                txtCol = Theme::TEXT_MUTED;
            } else if (pdis->hwndItem == s_hwndBtnOpen) {
                txtCol = Theme::ACCENT_PURPLE;
            }
            SetTextColor(pdis->hDC, txtCol);
            SetBkMode(pdis->hDC, TRANSPARENT);
            SelectObject(pdis->hDC, Theme::fontUI);
            wchar_t szBtnText[64] = {};
            GetWindowTextW(pdis->hwndItem, szBtnText, 64);
            RECT textRect = pdis->rcItem;
            DrawTextW(pdis->hDC, szBtnText, -1, &textRect, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            return TRUE;
        }
        break;
    }
    case WM_NOTIFY:
        OnNotify(hwnd, lParam);
        return 0;
    case WM_DROPFILES:
        OnDropFiles(hwnd, (HDROP)wParam);
        return 0;
    case WM_PAINT:
        OnPaint(hwnd);
        return 0;
    case WM_ERASEBKGND: {
        RECT rc; GetClientRect(hwnd, &rc);
        RECT below = { 0, TOOLBAR_H, rc.right, rc.bottom };
        FillRect((HDC)wParam, &rc,    Theme::brushBgToolbar);
        FillRect((HDC)wParam, &below, Theme::brushBgPrimary);
        return 1;
    }
    case WM_CTLCOLORBTN:
        SetTextColor((HDC)wParam, Theme::TEXT_ON_DARK);
        SetBkColor((HDC)wParam, Theme::BG_TOOLBAR);
        return (LRESULT)Theme::brushBgToolbar;
    case WM_CTLCOLORSTATIC:
        SetTextColor((HDC)wParam, Theme::TEXT_PRIMARY);
        SetBkColor((HDC)wParam, Theme::BG_TOOLBAR);
        return (LRESULT)Theme::brushBgToolbar;
    case WM_KEYDOWN:
        if (GetKeyState(VK_CONTROL) & 0x8000) {
            if (wParam == 'O') { OpenFile(hwnd); return 0; }
            if (wParam == 'S') { ExportJSON(hwnd); return 0; }
        }
        break;
    case WM_DESTROY:
        OnDestroy(hwnd);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}
