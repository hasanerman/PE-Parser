#pragma once
#include <windows.h>

namespace Theme {
    constexpr COLORREF BG_PRIMARY     = RGB(30,  30,  46);
    constexpr COLORREF BG_SECONDARY   = RGB(24,  24,  37);
    constexpr COLORREF BG_PANEL       = RGB(36,  36,  54);
    constexpr COLORREF BG_INPUT       = RGB(49,  50,  68);
    constexpr COLORREF BG_ROW_EVEN    = RGB(30,  30,  46);
    constexpr COLORREF BG_ROW_ODD     = RGB(36,  36,  54);
    constexpr COLORREF BG_SELECTED    = RGB(68,  71,  90);
    constexpr COLORREF BG_TOOLBAR     = RGB(17,  17,  27);
    constexpr COLORREF BG_HEADER      = RGB(49,  50,  68);

    constexpr COLORREF TEXT_PRIMARY   = RGB(205, 214, 244);
    constexpr COLORREF TEXT_SECONDARY = RGB(166, 173, 200);
    constexpr COLORREF TEXT_MUTED     = RGB(108, 112, 134);
    constexpr COLORREF TEXT_ACCENT    = RGB(203, 166, 247);
    constexpr COLORREF TEXT_ON_DARK   = RGB(205, 214, 244);

    constexpr COLORREF ACCENT_PURPLE  = RGB(203, 166, 247);
    constexpr COLORREF ACCENT_BLUE    = RGB(137, 180, 250);
    constexpr COLORREF ACCENT_CYAN    = RGB(137, 220, 235);
    constexpr COLORREF ACCENT_GREEN   = RGB(166, 227, 161);
    constexpr COLORREF ACCENT_YELLOW  = RGB(249, 226, 175);
    constexpr COLORREF ACCENT_ORANGE  = RGB(250, 179, 135);
    constexpr COLORREF ACCENT_RED     = RGB(243, 139, 168);

    constexpr COLORREF BORDER         = RGB(69,  71,  90);
    constexpr COLORREF SEPARATOR      = RGB(49,  50,  68);

    constexpr COLORREF LEVEL_INFO     = RGB(137, 220, 235);
    constexpr COLORREF LEVEL_WARNING  = RGB(249, 226, 175);
    constexpr COLORREF LEVEL_CRITICAL = RGB(243, 139, 168);

    constexpr COLORREF COL_EXECUTABLE = RGB(137, 180, 250);
    constexpr COLORREF COL_WX         = RGB(243, 139, 168);
    constexpr COLORREF COL_HIGH_ENT   = RGB(249, 226, 175);
    constexpr COLORREF COL_SUSPICIOUS = RGB(250, 179, 135);

    extern HBRUSH brushBgPrimary;
    extern HBRUSH brushBgSecondary;
    extern HBRUSH brushBgPanel;
    extern HBRUSH brushBgInput;
    extern HBRUSH brushBgToolbar;
    extern HBRUSH brushBgHeader;
    extern HBRUSH brushBorder;
    extern HBRUSH brushRowEven;
    extern HBRUSH brushRowOdd;

    extern HFONT  fontUI;
    extern HFONT  fontMono;
    extern HFONT  fontTitle;
    extern HFONT  fontSmall;
    extern HFONT  fontBold;

    void Initialize();
    void Cleanup();

    void ApplyDarkTitleBar(HWND hwnd);
    void ApplyDarkListView(HWND hwnd);
    void ApplyDarkTreeView(HWND hwnd);
    void SetListViewColors(HWND hwnd);
}
