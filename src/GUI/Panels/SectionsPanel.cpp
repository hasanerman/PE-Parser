#include "GUI/Panels/SectionsPanel.h"
#include "GUI/Theme.h"
#include "Utils/HexFormatter.h"
#include "Utils/StringUtils.h"
#include "Utils/Characteristics.h"
#include <commctrl.h>
#include <iomanip>
#include <sstream>

#define ID_LV_SECTIONS 3100

static HWND s_lvSections = nullptr;
static std::vector<SectionInfo> s_sections;

static std::wstring W(const std::string& s) { return AnsiToWide(s); }

bool SectionsPanel::Register(HINSTANCE hInstance) {
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hbrBackground = Theme::brushBgPrimary;
    wc.lpszClassName = CLASS_NAME;
    return RegisterClassExW(&wc) != 0;
}

HWND SectionsPanel::Create(HWND parent, HINSTANCE hInstance, int x, int y, int w, int h) {
    return CreateWindowExW(0, CLASS_NAME, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        x, y, w, h, parent, nullptr, hInstance, nullptr);
}

void SectionsPanel::Resize(HWND panel, int w, int h) {
    if (s_lvSections) SetWindowPos(s_lvSections, nullptr, 0, 0, w, h, SWP_NOZORDER | SWP_NOMOVE);
}

void SectionsPanel::Clear(HWND panel) {
    s_sections.clear();
    if (s_lvSections) ListView_DeleteAllItems(s_lvSections);
}

void SectionsPanel::Populate(HWND panel, const PEAnalysisResult& r) {
    if (!s_lvSections) return;
    ListView_DeleteAllItems(s_lvSections);
    s_sections = r.sections;

    for (int i = 0; i < (int)r.sections.size(); ++i) {
        const auto& s = r.sections[i];
        std::wstring name = W(s.name.empty() ? "(empty)" : s.name);
        LVITEMW item = {};
        item.mask    = LVIF_TEXT;
        item.iItem   = i;
        item.pszText = const_cast<wchar_t*>(name.c_str());
        ListView_InsertItem(s_lvSections, &item);

        ListView_SetItemText(s_lvSections, i, 1, const_cast<wchar_t*>(W(ToHex32(s.virtualAddress)).c_str()));
        ListView_SetItemText(s_lvSections, i, 2, const_cast<wchar_t*>(W(ToHex32(s.virtualSize)).c_str()));
        ListView_SetItemText(s_lvSections, i, 3, const_cast<wchar_t*>(W(ToHex32(s.pointerToRawData)).c_str()));
        ListView_SetItemText(s_lvSections, i, 4, const_cast<wchar_t*>(W(ToHex32(s.sizeOfRawData)).c_str()));

        std::wstring entropyStr = W(FormatEntropy(s.entropy));
        if (s.entropy > 7.2)   entropyStr += L" !!";
        else if (s.entropy > 6.5) entropyStr += L" !";
        ListView_SetItemText(s_lvSections, i, 5, const_cast<wchar_t*>(entropyStr.c_str()));

        std::wstring perms = W(SectionPermissionsToString(s.isReadable, s.isWritable, s.isExecutable));
        if (s.isWX) perms += L" [W+X!]";
        ListView_SetItemText(s_lvSections, i, 6, const_cast<wchar_t*>(perms.c_str()));

        ListView_SetItemText(s_lvSections, i, 7, const_cast<wchar_t*>(W(ToHex32(s.characteristics)).c_str()));
    }
}

LRESULT CALLBACK SectionsPanel::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        RECT rc; GetClientRect(hwnd, &rc);
        s_lvSections = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_NOSORTHEADER | LVS_SINGLESEL,
            0, 0, rc.right, rc.bottom, hwnd, (HMENU)ID_LV_SECTIONS,
            (HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE), nullptr);

        Theme::ApplyDarkListView(s_lvSections);
        SendMessageW(s_lvSections, WM_SETFONT, (WPARAM)Theme::fontMono, TRUE);
        ListView_SetExtendedListViewStyle(s_lvSections, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);

        struct ColDef { const wchar_t* name; int width; };
        ColDef cols[] = {
            { L"Name",         110 },
            { L"Virt Addr",    110 },
            { L"Virt Size",    110 },
            { L"Raw Offset",   110 },
            { L"Raw Size",     110 },
            { L"Entropy",      100 },
            { L"Permissions",  120 },
            { L"Characteristics", 130 },
        };
        LVCOLUMNW col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        for (int i = 0; i < 8; ++i) {
            col.pszText = const_cast<wchar_t*>(cols[i].name);
            col.cx      = cols[i].width;
            ListView_InsertColumn(s_lvSections, i, &col);
        }
        return 0;
    }
    case WM_SIZE:
        if (s_lvSections) SetWindowPos(s_lvSections, nullptr, 0, 0, LOWORD(lParam), HIWORD(lParam), SWP_NOZORDER);
        return 0;
    case WM_NOTIFY: {
        auto* hdr = reinterpret_cast<NMHDR*>(lParam);
        if (hdr->idFrom == ID_LV_SECTIONS && hdr->code == NM_CUSTOMDRAW) {
            auto* cd = reinterpret_cast<NMLVCUSTOMDRAW*>(lParam);
            if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                int idx = (int)cd->nmcd.dwItemSpec;
                if (idx >= 0 && idx < (int)s_sections.size()) {
                    const auto& s = s_sections[idx];
                    if (s.isWX) {
                        cd->clrTextBk = RGB(60, 20, 30);
                        cd->clrText   = Theme::ACCENT_RED;
                    } else if (s.entropy > 7.2) {
                        cd->clrTextBk = RGB(50, 40, 15);
                        cd->clrText   = Theme::ACCENT_YELLOW;
                    } else if (s.isExecutable) {
                        cd->clrTextBk = (idx % 2 == 0) ? Theme::BG_ROW_EVEN : Theme::BG_ROW_ODD;
                        cd->clrText   = Theme::ACCENT_BLUE;
                    } else {
                        cd->clrTextBk = (idx % 2 == 0) ? Theme::BG_ROW_EVEN : Theme::BG_ROW_ODD;
                        cd->clrText   = Theme::TEXT_PRIMARY;
                    }
                }
                return CDRF_NEWFONT;
            }
        }
        return CDRF_DODEFAULT;
    }
    case WM_ERASEBKGND: {
        RECT rc; GetClientRect(hwnd, &rc);
        FillRect((HDC)wParam, &rc, Theme::brushBgPrimary);
        return 1;
    }
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}
