#include "GUI/Panels/HexPanel.h"
#include "GUI/Theme.h"
#include "Utils/StringUtils.h"
#include <commctrl.h>
#include <cstdio>
#include <vector>

static HWND s_hwndCombo = nullptr;
static HWND s_hwndLV = nullptr;
static const BYTE* s_fileBase = nullptr;
static uint64_t s_fileSize = 0;
static std::vector<SectionInfo> s_sections;
static uint64_t s_viewOffset = 0;
static uint64_t s_viewSize = 0;

bool HexPanel::Register(HINSTANCE hInstance) {
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hbrBackground = Theme::brushBgPrimary;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    return RegisterClassExW(&wc) != 0;
}

HWND HexPanel::Create(HWND parent, HINSTANCE hInstance, int x, int y, int w, int h) {
    return CreateWindowExW(0, CLASS_NAME, L"",
        WS_CHILD | WS_CLIPCHILDREN,
        x, y, w, h, parent, nullptr, hInstance, nullptr);
}

void HexPanel::Populate(HWND panel, const PEAnalysisResult& result, const BYTE* fileBase) {
    s_fileBase = fileBase;
    s_fileSize = result.fileSize;
    s_sections = result.sections;

    SendMessageW(s_hwndCombo, CB_RESETCONTENT, 0, 0);
    SendMessageW(s_hwndCombo, CB_ADDSTRING, 0, (LPARAM)L"Entire File");

    for (const auto& sec : s_sections) {
        std::wstring name = AnsiToWide(sec.name);
        SendMessageW(s_hwndCombo, CB_ADDSTRING, 0, (LPARAM)name.c_str());
    }

    SendMessageW(s_hwndCombo, CB_SETCURSEL, 0, 0);

    s_viewOffset = 0;
    s_viewSize = s_fileSize;

    ListView_SetItemCount(s_hwndLV, (s_viewSize + 15) / 16);
    InvalidateRect(s_hwndLV, nullptr, TRUE);
}

void HexPanel::Resize(HWND panel, int w, int h) {
    SetWindowPos(panel, nullptr, 0, 0, w, h, SWP_NOMOVE | SWP_NOZORDER);
}

void HexPanel::Clear(HWND panel) {
    s_fileBase = nullptr;
    s_fileSize = 0;
    s_viewOffset = 0;
    s_viewSize = 0;
    s_sections.clear();
    SendMessageW(s_hwndCombo, CB_RESETCONTENT, 0, 0);
    ListView_SetItemCount(s_hwndLV, 0);
    InvalidateRect(s_hwndLV, nullptr, TRUE);
}

LRESULT CALLBACK HexPanel::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        s_hwndCombo = CreateWindowExW(0, WC_COMBOBOXW, L"",
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
            10, 10, 250, 300, hwnd, nullptr, reinterpret_cast<LPCREATESTRUCT>(lParam)->hInstance, nullptr);
        SendMessageW(s_hwndCombo, WM_SETFONT, (WPARAM)Theme::fontUI, TRUE);

        s_hwndLV = CreateWindowExW(0, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_OWNERDATA | LVS_SHOWSELALWAYS | WS_VSCROLL,
            10, 45, 100, 100, hwnd, nullptr, reinterpret_cast<LPCREATESTRUCT>(lParam)->hInstance, nullptr);
        
        Theme::ApplyDarkListView(s_hwndLV);
        SendMessageW(s_hwndLV, WM_SETFONT, (WPARAM)Theme::fontMono, TRUE);

        LVCOLUMNW col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        
        col.pszText = const_cast<wchar_t*>(L"Offset");
        col.cx = 100;
        ListView_InsertColumn(s_hwndLV, 0, &col);

        col.pszText = const_cast<wchar_t*>(L"Bytes (Hex)");
        col.cx = 400;
        ListView_InsertColumn(s_hwndLV, 1, &col);

        col.pszText = const_cast<wchar_t*>(L"ASCII");
        col.cx = 200;
        ListView_InsertColumn(s_hwndLV, 2, &col);

        break;
    }
    case WM_SIZE: {
        int w = LOWORD(lParam);
        int h = HIWORD(lParam);
        SetWindowPos(s_hwndCombo, nullptr, 10, 10, w - 20, 30, SWP_NOZORDER);
        SetWindowPos(s_hwndLV, nullptr, 10, 45, w - 20, h - 55, SWP_NOZORDER);
        break;
    }
    case WM_COMMAND: {
        if (HIWORD(wParam) == CBN_SELCHANGE && reinterpret_cast<HWND>(lParam) == s_hwndCombo) {
            int sel = static_cast<int>(SendMessageW(s_hwndCombo, CB_GETCURSEL, 0, 0));
            if (sel == 0) {
                s_viewOffset = 0;
                s_viewSize = s_fileSize;
            } else if (sel > 0 && sel - 1 < static_cast<int>(s_sections.size())) {
                const auto& sec = s_sections[sel - 1];
                s_viewOffset = sec.pointerToRawData;
                s_viewSize = sec.sizeOfRawData;
            }
            ListView_SetItemCount(s_hwndLV, (s_viewSize + 15) / 16);
            InvalidateRect(s_hwndLV, nullptr, TRUE);
        }
        break;
    }
    case WM_NOTIFY: {
        NMHDR* nmhdr = reinterpret_cast<NMHDR*>(lParam);
        if (nmhdr->hwndFrom == s_hwndLV && nmhdr->code == LVN_GETDISPINFO) {
            NMLVDISPINFO* plvdi = reinterpret_cast<NMLVDISPINFO*>(lParam);
            if (plvdi->item.mask & LVIF_TEXT) {
                int row = plvdi->item.iItem;
                int col = plvdi->item.iSubItem;
                uint64_t lineOffset = static_cast<uint64_t>(row) * 16;
                if (lineOffset >= s_viewSize) return 0;
                uint64_t fileOffset = s_viewOffset + lineOffset;
                
                static wchar_t szText[256];
                szText[0] = L'\0';
                
                if (col == 0) {
                    swprintf_s(szText, L"0x%08llX", fileOffset);
                } else if (col == 1) {
                    wchar_t* ptr = szText;
                    int written = 0;
                    for (int i = 0; i < 16; ++i) {
                        uint64_t currOffset = fileOffset + i;
                        if (currOffset < s_fileSize && s_fileBase) {
                            BYTE b = s_fileBase[currOffset];
                            written += swprintf_s(ptr, 256 - written, L"%02X ", b);
                            ptr = szText + written;
                        } else {
                            written += swprintf_s(ptr, 256 - written, L"   ");
                            ptr = szText + written;
                        }
                    }
                } else if (col == 2) {
                    for (int i = 0; i < 16; ++i) {
                        uint64_t currOffset = fileOffset + i;
                        if (currOffset < s_fileSize && s_fileBase) {
                            BYTE b = s_fileBase[currOffset];
                            if (b >= 0x20 && b <= 0x7E) {
                                szText[i] = static_cast<wchar_t>(b);
                            } else {
                                szText[i] = L'.';
                            }
                        } else {
                            szText[i] = L' ';
                        }
                    }
                    szText[16] = L'\0';
                }
                plvdi->item.pszText = szText;
            }
        }
        break;
    }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}
