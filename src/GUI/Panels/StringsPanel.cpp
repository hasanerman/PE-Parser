#include "GUI/Panels/StringsPanel.h"
#include "GUI/Theme.h"
#include "Utils/StringUtils.h"
#include <commctrl.h>
#include <cstdio>
#include <vector>

static HWND s_hwndEditSearch = nullptr;
static HWND s_hwndCheckNetOnly = nullptr;
static HWND s_hwndLV = nullptr;
static std::vector<PEStringInfo> s_allStrings;
static std::vector<PEStringInfo> s_filteredStrings;

static void ApplyFilter() {
    s_filteredStrings.clear();
    wchar_t szSearch[256] = {};
    GetWindowTextW(s_hwndEditSearch, szSearch, 256);
    std::string searchStr = WideToAnsi(szSearch);
    for (char& c : searchStr) {
        c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    }

    bool netOnly = (SendMessageW(s_hwndCheckNetOnly, BM_GETCHECK, 0, 0) == BST_CHECKED);

    for (const auto& str : s_allStrings) {
        if (netOnly && !str.isNetwork) continue;
        if (!searchStr.empty()) {
            std::string lowerVal = str.value;
            for (char& c : lowerVal) {
                c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
            }
            if (lowerVal.find(searchStr) == std::string::npos) continue;
        }
        s_filteredStrings.push_back(str);
    }
    ListView_SetItemCount(s_hwndLV, s_filteredStrings.size());
    InvalidateRect(s_hwndLV, nullptr, TRUE);
}

bool StringsPanel::Register(HINSTANCE hInstance) {
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hbrBackground = Theme::brushBgPrimary;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    return RegisterClassExW(&wc) != 0;
}

HWND StringsPanel::Create(HWND parent, HINSTANCE hInstance, int x, int y, int w, int h) {
    return CreateWindowExW(0, CLASS_NAME, L"",
        WS_CHILD | WS_CLIPCHILDREN,
        x, y, w, h, parent, nullptr, hInstance, nullptr);
}

void StringsPanel::Populate(HWND panel, const PEAnalysisResult& result) {
    s_allStrings = result.strings;
    SetWindowTextW(s_hwndEditSearch, L"");
    SendMessageW(s_hwndCheckNetOnly, BM_SETCHECK, BST_UNCHECKED, 0);
    ApplyFilter();
}

void StringsPanel::Resize(HWND panel, int w, int h) {
    SetWindowPos(panel, nullptr, 0, 0, w, h, SWP_NOMOVE | SWP_NOZORDER);
}

void StringsPanel::Clear(HWND panel) {
    s_allStrings.clear();
    s_filteredStrings.clear();
    SetWindowTextW(s_hwndEditSearch, L"");
    SendMessageW(s_hwndCheckNetOnly, BM_SETCHECK, BST_UNCHECKED, 0);
    ListView_SetItemCount(s_hwndLV, 0);
    InvalidateRect(s_hwndLV, nullptr, TRUE);
}

LRESULT CALLBACK StringsPanel::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        HINSTANCE hInst = reinterpret_cast<LPCREATESTRUCT>(lParam)->hInstance;

        s_hwndEditSearch = CreateWindowExW(0, WC_EDITW, L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            10, 10, 250, 26, hwnd, nullptr, hInst, nullptr);
        SendMessageW(s_hwndEditSearch, WM_SETFONT, (WPARAM)Theme::fontUI, TRUE);

        s_hwndCheckNetOnly = CreateWindowExW(0, L"BUTTON", L"Show URLs/IPs Only",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
            275, 10, 200, 26, hwnd, nullptr, hInst, nullptr);
        SendMessageW(s_hwndCheckNetOnly, WM_SETFONT, (WPARAM)Theme::fontUI, TRUE);

        s_hwndLV = CreateWindowExW(0, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_OWNERDATA | LVS_SHOWSELALWAYS | WS_VSCROLL,
            10, 45, 100, 100, hwnd, nullptr, hInst, nullptr);
        
        Theme::ApplyDarkListView(s_hwndLV);
        SendMessageW(s_hwndLV, WM_SETFONT, (WPARAM)Theme::fontMono, TRUE);
        ListView_SetExtendedListViewStyle(s_hwndLV, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

        LVCOLUMNW col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        
        col.pszText = const_cast<wchar_t*>(L"Offset / RVA");
        col.cx = 140;
        ListView_InsertColumn(s_hwndLV, 0, &col);

        col.pszText = const_cast<wchar_t*>(L"Section");
        col.cx = 100;
        ListView_InsertColumn(s_hwndLV, 1, &col);

        col.pszText = const_cast<wchar_t*>(L"Type");
        col.cx = 80;
        ListView_InsertColumn(s_hwndLV, 2, &col);

        col.pszText = const_cast<wchar_t*>(L"String Value");
        col.cx = 400;
        ListView_InsertColumn(s_hwndLV, 3, &col);

        col.pszText = const_cast<wchar_t*>(L"Network Indicator");
        col.cx = 150;
        ListView_InsertColumn(s_hwndLV, 4, &col);

        break;
    }
    case WM_SIZE: {
        int w = LOWORD(lParam);
        int h = HIWORD(lParam);
        SetWindowPos(s_hwndEditSearch, nullptr, 10, 10, 250, 26, SWP_NOZORDER);
        SetWindowPos(s_hwndCheckNetOnly, nullptr, 270, 10, 200, 26, SWP_NOZORDER);
        SetWindowPos(s_hwndLV, nullptr, 10, 45, w - 20, h - 55, SWP_NOZORDER);
        break;
    }
    case WM_COMMAND: {
        if (HIWORD(wParam) == EN_CHANGE && reinterpret_cast<HWND>(lParam) == s_hwndEditSearch) {
            ApplyFilter();
        } else if (HIWORD(wParam) == BN_CLICKED && reinterpret_cast<HWND>(lParam) == s_hwndCheckNetOnly) {
            ApplyFilter();
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
                if (row >= static_cast<int>(s_filteredStrings.size())) return 0;
                const auto& str = s_filteredStrings[row];

                static wchar_t szText[1024];
                szText[0] = L'\0';

                if (col == 0) {
                    if (str.section == "OVERLAY") {
                        swprintf_s(szText, L"Offset: 0x%08llX", str.offset);
                    } else if (str.section == "HEADERS") {
                        swprintf_s(szText, L"Offset: 0x%08llX", str.offset);
                    } else {
                        swprintf_s(szText, L"RVA: 0x%08X", str.rva);
                    }
                } else if (col == 1) {
                    swprintf_s(szText, L"%S", str.section.c_str());
                } else if (col == 2) {
                    swprintf_s(szText, L"%s", str.isUnicode ? L"Unicode" : L"ASCII");
                } else if (col == 3) {
                    swprintf_s(szText, L"%S", str.value.c_str());
                } else if (col == 4) {
                    if (str.isNetwork) {
                        swprintf_s(szText, L"%S", str.networkType.c_str());
                    } else {
                        szText[0] = L'\0';
                    }
                }
                plvdi->item.pszText = szText;
            }
        }
        if (nmhdr->hwndFrom == s_hwndLV && nmhdr->code == NM_CUSTOMDRAW) {
            NMLVCUSTOMDRAW* cd = reinterpret_cast<NMLVCUSTOMDRAW*>(lParam);
            if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                int idx = static_cast<int>(cd->nmcd.dwItemSpec);
                if (idx < static_cast<int>(s_filteredStrings.size())) {
                    const auto& str = s_filteredStrings[idx];
                    if (str.isNetwork) {
                        cd->clrTextBk = RGB(55, 25, 30);
                        cd->clrText   = Theme::ACCENT_RED;
                    } else {
                        cd->clrTextBk = (idx % 2 == 0) ? Theme::BG_ROW_EVEN : Theme::BG_ROW_ODD;
                        cd->clrText   = Theme::TEXT_PRIMARY;
                    }
                }
                return CDRF_NEWFONT;
            }
        }
        break;
    }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}
