#include "GUI/Panels/ResourcesPanel.h"
#include "GUI/Theme.h"
#include "Utils/StringUtils.h"
#include "Utils/HexFormatter.h"
#include <commctrl.h>
#include <map>

#define ID_LV_RESOURCES 3500

static HWND s_lvRes = nullptr;

static std::wstring W(const std::string& s) { return AnsiToWide(s); }

bool ResourcesPanel::Register(HINSTANCE hInstance) {
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hbrBackground = Theme::brushBgPrimary;
    wc.lpszClassName = CLASS_NAME;
    return RegisterClassExW(&wc) != 0;
}

HWND ResourcesPanel::Create(HWND parent, HINSTANCE hInstance, int x, int y, int w, int h) {
    return CreateWindowExW(0, CLASS_NAME, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        x, y, w, h, parent, nullptr, hInstance, nullptr);
}

void ResourcesPanel::Resize(HWND panel, int w, int h) {
    if (s_lvRes) SetWindowPos(s_lvRes, nullptr, 0, 0, w, h, SWP_NOZORDER | SWP_NOMOVE);
}

void ResourcesPanel::Clear(HWND panel) {
    if (s_lvRes) ListView_DeleteAllItems(s_lvRes);
}

void ResourcesPanel::Populate(HWND panel, const PEAnalysisResult& r) {
    if (!s_lvRes) return;
    ListView_DeleteAllItems(s_lvRes);
    if (!r.resources.hasResources) return;

    for (int i = 0; i < (int)r.resources.entries.size(); ++i) {
        const auto& e = r.resources.entries[i];
        LVITEMW item = {};
        item.mask    = LVIF_TEXT;
        item.iItem   = i;
        std::wstring type = W(e.typeName);
        item.pszText = const_cast<wchar_t*>(type.c_str());
        ListView_InsertItem(s_lvRes, &item);

        std::wstring name = e.nameHasName ? W(e.name) : W("#" + std::to_string(e.nameId));
        ListView_SetItemText(s_lvRes, i, 1, const_cast<wchar_t*>(name.c_str()));
        std::wstring lang = W(e.languageStr);
        ListView_SetItemText(s_lvRes, i, 2, const_cast<wchar_t*>(lang.c_str()));
        std::wstring size = W(FormatFileSize(e.dataSize));
        ListView_SetItemText(s_lvRes, i, 3, const_cast<wchar_t*>(size.c_str()));
        std::wstring rva = W(ToHex32(e.dataRVA));
        ListView_SetItemText(s_lvRes, i, 4, const_cast<wchar_t*>(rva.c_str()));
    }
}

LRESULT CALLBACK ResourcesPanel::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        RECT rc; GetClientRect(hwnd, &rc);
        s_lvRes = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_NOSORTHEADER,
            0, 0, rc.right, rc.bottom, hwnd, (HMENU)ID_LV_RESOURCES,
            (HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE), nullptr);

        Theme::ApplyDarkListView(s_lvRes);
        SendMessageW(s_lvRes, WM_SETFONT, (WPARAM)Theme::fontMono, TRUE);
        ListView_SetExtendedListViewStyle(s_lvRes, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);

        LVCOLUMNW col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        struct ColDef { const wchar_t* n; int w; };
        ColDef cols[] = { {L"Type",200},{L"Name / ID",180},{L"Language",130},{L"Size",150},{L"Data RVA",120} };
        for (int i = 0; i < 5; ++i) {
            col.pszText = const_cast<wchar_t*>(cols[i].n);
            col.cx      = cols[i].w;
            ListView_InsertColumn(s_lvRes, i, &col);
        }
        return 0;
    }
    case WM_SIZE:
        if (s_lvRes) SetWindowPos(s_lvRes, nullptr, 0, 0, LOWORD(lParam), HIWORD(lParam), SWP_NOZORDER);
        return 0;
    case WM_NOTIFY: {
        auto* hdr = reinterpret_cast<NMHDR*>(lParam);
        if (hdr->idFrom == ID_LV_RESOURCES && hdr->code == NM_CUSTOMDRAW) {
            auto* cd = reinterpret_cast<NMLVCUSTOMDRAW*>(lParam);
            if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                cd->clrTextBk = ((int)cd->nmcd.dwItemSpec % 2 == 0) ? Theme::BG_ROW_EVEN : Theme::BG_ROW_ODD;
                cd->clrText   = Theme::ACCENT_CYAN;
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
