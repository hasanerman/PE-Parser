#include "GUI/Theme.h"
#include <dwmapi.h>
#include <uxtheme.h>
#include <commctrl.h>

#pragma comment(lib, "Dwmapi.lib")
#pragma comment(lib, "UxTheme.lib")

namespace Theme {
    HBRUSH brushBgPrimary   = nullptr;
    HBRUSH brushBgSecondary = nullptr;
    HBRUSH brushBgPanel     = nullptr;
    HBRUSH brushBgInput     = nullptr;
    HBRUSH brushBgToolbar   = nullptr;
    HBRUSH brushBgHeader    = nullptr;
    HBRUSH brushBorder      = nullptr;
    HBRUSH brushRowEven     = nullptr;
    HBRUSH brushRowOdd      = nullptr;

    HFONT  fontUI    = nullptr;
    HFONT  fontMono  = nullptr;
    HFONT  fontTitle = nullptr;
    HFONT  fontSmall = nullptr;
    HFONT  fontBold  = nullptr;

    void Initialize() {
        brushBgPrimary   = CreateSolidBrush(BG_PRIMARY);
        brushBgSecondary = CreateSolidBrush(BG_SECONDARY);
        brushBgPanel     = CreateSolidBrush(BG_PANEL);
        brushBgInput     = CreateSolidBrush(BG_INPUT);
        brushBgToolbar   = CreateSolidBrush(BG_TOOLBAR);
        brushBgHeader    = CreateSolidBrush(BG_HEADER);
        brushBorder      = CreateSolidBrush(BORDER);
        brushRowEven     = CreateSolidBrush(BG_ROW_EVEN);
        brushRowOdd      = CreateSolidBrush(BG_ROW_ODD);

        fontUI = CreateFont(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        fontMono = CreateFont(-13, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Cascadia Mono");

        fontTitle = CreateFont(-20, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        fontSmall = CreateFont(-12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");

        fontBold = CreateFont(-14, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    }

    void Cleanup() {
        auto delBrush = [](HBRUSH& b) { if (b) { DeleteObject(b); b = nullptr; } };
        auto delFont  = [](HFONT&  f) { if (f) { DeleteObject(f); f = nullptr; } };
        delBrush(brushBgPrimary);
        delBrush(brushBgSecondary);
        delBrush(brushBgPanel);
        delBrush(brushBgInput);
        delBrush(brushBgToolbar);
        delBrush(brushBgHeader);
        delBrush(brushBorder);
        delBrush(brushRowEven);
        delBrush(brushRowOdd);
        delFont(fontUI);
        delFont(fontMono);
        delFont(fontTitle);
        delFont(fontSmall);
        delFont(fontBold);
    }

    void ApplyDarkTitleBar(HWND hwnd) {
        BOOL dark = TRUE;
        DwmSetWindowAttribute(hwnd, 20, &dark, sizeof(dark));
        DwmSetWindowAttribute(hwnd, 19, &dark, sizeof(dark));
    }

    LRESULT CALLBACK ListViewSubclassProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uid, DWORD_PTR data) {
        if (msg == WM_NOTIFY) {
            NMHDR* hdr = reinterpret_cast<NMHDR*>(lParam);
            HWND hwndHeader = ListView_GetHeader(hwnd);
            if (hdr->hwndFrom == hwndHeader && hdr->code == NM_CUSTOMDRAW) {
                NMCUSTOMDRAW* nmcd = reinterpret_cast<NMCUSTOMDRAW*>(lParam);
                if (nmcd->dwDrawStage == CDDS_PREPAINT) {
                    return CDRF_NOTIFYITEMDRAW;
                }
                if (nmcd->dwDrawStage == CDDS_ITEMPREPAINT) {
                    FillRect(nmcd->hdc, &nmcd->rc, brushBgHeader);
                    
                    HPEN pen = CreatePen(PS_SOLID, 1, BORDER);
                    HPEN oldPen = (HPEN)SelectObject(nmcd->hdc, pen);
                    MoveToEx(nmcd->hdc, nmcd->rc.right - 1, nmcd->rc.top, nullptr);
                    LineTo(nmcd->hdc, nmcd->rc.right - 1, nmcd->rc.bottom);
                    MoveToEx(nmcd->hdc, nmcd->rc.left, nmcd->rc.bottom - 1, nullptr);
                    LineTo(nmcd->hdc, nmcd->rc.right, nmcd->rc.bottom - 1);
                    SelectObject(nmcd->hdc, oldPen);
                    DeleteObject(pen);

                    SetTextColor(nmcd->hdc, TEXT_PRIMARY);
                    SetBkMode(nmcd->hdc, TRANSPARENT);
                    
                    wchar_t szText[128] = {};
                    HDITEMW hdi = {};
                    hdi.mask = HDI_TEXT;
                    hdi.pszText = szText;
                    hdi.cchTextMax = 128;
                    Header_GetItem(hwndHeader, nmcd->dwItemSpec, &hdi);
                    
                    RECT textRect = nmcd->rc;
                    textRect.left += 8;
                    textRect.right -= 8;
                    DrawTextW(nmcd->hdc, szText, -1, &textRect, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
                    
                    return CDRF_SKIPDEFAULT;
                }
            }
        }
        return DefSubclassProc(hwnd, msg, wParam, lParam);
    }

    void ApplyDarkListView(HWND hwnd) {
        SetWindowTheme(hwnd, L"DarkMode_Explorer", nullptr);
        ListView_SetBkColor(hwnd, BG_PRIMARY);
        ListView_SetTextBkColor(hwnd, BG_PRIMARY);
        ListView_SetTextColor(hwnd, TEXT_PRIMARY);
        SetWindowSubclass(hwnd, ListViewSubclassProc, 0, 0);
    }

    void ApplyDarkTreeView(HWND hwnd) {
        SetWindowTheme(hwnd, L"DarkMode_Explorer", nullptr);
        TreeView_SetBkColor(hwnd, BG_PRIMARY);
        TreeView_SetTextColor(hwnd, TEXT_PRIMARY);
    }

    void SetListViewColors(HWND hwnd) {
        ApplyDarkListView(hwnd);
    }
}
