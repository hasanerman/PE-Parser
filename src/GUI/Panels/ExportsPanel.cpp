#include "GUI/Panels/ExportsPanel.h"
#include "GUI/Theme.h"
#include "Utils/HexFormatter.h"
#include "Utils/StringUtils.h"
#include <commctrl.h>
#include <vector>

#define ID_LV_EXPORTS 3300

static HWND s_hwndEditSearch = nullptr;
static HWND s_lvExports = nullptr;
static std::vector<ExportedFunction> s_allExports;
static std::vector<ExportedFunction> s_filteredExports;

static std::wstring W(const std::string& s) { return AnsiToWide(s); }

static void ApplyFilter() {
    if (!s_lvExports) return;
    ListView_DeleteAllItems(s_lvExports);
    s_filteredExports.clear();

    wchar_t szSearch[256] = {};
    GetWindowTextW(s_hwndEditSearch, szSearch, 256);
    std::string searchStr = WideToAnsi(szSearch);
    for (char& c : searchStr) {
        c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    }

    for (const auto& fn : s_allExports) {
        if (!searchStr.empty()) {
            std::string lowerName = fn.name;
            for (char& c : lowerName) {
                c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
            }
            std::string ordStr = std::to_string(fn.ordinal);
            if (lowerName.find(searchStr) == std::string::npos && ordStr.find(searchStr) == std::string::npos) {
                continue;
            }
        }
        s_filteredExports.push_back(fn);
    }

    for (int i = 0; i < (int)s_filteredExports.size(); ++i) {
        const auto& fn = s_filteredExports[i];
        LVITEMW item = {};
        item.mask    = LVIF_TEXT;
        item.iItem   = i;
        std::wstring ord = W(std::to_string(fn.ordinal));
        item.pszText = const_cast<wchar_t*>(ord.c_str());
        ListView_InsertItem(s_lvExports, &item);

        std::wstring name = fn.hasName ? W(fn.name) : L"(no name)";
        ListView_SetItemText(s_lvExports, i, 1, const_cast<wchar_t*>(name.c_str()));
        std::wstring rva = W(ToHex32(fn.rva));
        ListView_SetItemText(s_lvExports, i, 2, const_cast<wchar_t*>(rva.c_str()));
        std::wstring fwd = fn.isForwarder ? W(fn.forwarderName) : L"";
        ListView_SetItemText(s_lvExports, i, 3, const_cast<wchar_t*>(fwd.c_str()));
    }
}

bool ExportsPanel::Register(HINSTANCE hInstance) {
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hbrBackground = Theme::brushBgPrimary;
    wc.lpszClassName = CLASS_NAME;
    return RegisterClassExW(&wc) != 0;
}

HWND ExportsPanel::Create(HWND parent, HINSTANCE hInstance, int x, int y, int w, int h) {
    return CreateWindowExW(0, CLASS_NAME, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        x, y, w, h, parent, nullptr, hInstance, nullptr);
}

void ExportsPanel::Resize(HWND panel, int w, int h) {
    SetWindowPos(panel, nullptr, 0, 0, w, h, SWP_NOMOVE | SWP_NOZORDER);
}

void ExportsPanel::Clear(HWND panel) {
    s_allExports.clear();
    s_filteredExports.clear();
    SetWindowTextW(s_hwndEditSearch, L"");
    if (s_lvExports) ListView_DeleteAllItems(s_lvExports);
}

void ExportsPanel::Populate(HWND panel, const PEAnalysisResult& r) {
    s_allExports = r.exports.functions;
    SetWindowTextW(s_hwndEditSearch, L"");
    ApplyFilter();
}

LRESULT CALLBACK ExportsPanel::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        HINSTANCE hInst = (HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE);

        s_hwndEditSearch = CreateWindowExW(0, WC_EDITW, L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            10, 10, 250, 26, hwnd, nullptr, hInst, nullptr);
        SendMessageW(s_hwndEditSearch, WM_SETFONT, (WPARAM)Theme::fontUI, TRUE);

        s_lvExports = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_NOSORTHEADER,
            10, 45, 100, 100, hwnd, (HMENU)ID_LV_EXPORTS, hInst, nullptr);

        Theme::ApplyDarkListView(s_lvExports);
        SendMessageW(s_lvExports, WM_SETFONT, (WPARAM)Theme::fontMono, TRUE);
        ListView_SetExtendedListViewStyle(s_lvExports, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);

        LVCOLUMNW col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        struct ColDef { const wchar_t* n; int w; };
        ColDef cols[] = { {L"Ordinal",140},{L"Name",400},{L"RVA",120},{L"Forwarder",250} };
        for (int i = 0; i < 4; ++i) {
            col.pszText = const_cast<wchar_t*>(cols[i].n);
            col.cx = cols[i].w;
            ListView_InsertColumn(s_lvExports, i, &col);
        }
        return 0;
    }
    case WM_SIZE: {
        int w = LOWORD(lParam), h = HIWORD(lParam);
        SetWindowPos(s_hwndEditSearch, nullptr, 10, 10, 250, 26, SWP_NOZORDER);
        if (s_lvExports) SetWindowPos(s_lvExports, nullptr, 10, 45, w - 20, h - 55, SWP_NOZORDER);
        return 0;
    }
    case WM_COMMAND: {
        if (HIWORD(wParam) == EN_CHANGE && reinterpret_cast<HWND>(lParam) == s_hwndEditSearch) {
            ApplyFilter();
        }
        return 0;
    }
    case WM_NOTIFY: {
        auto* hdr = reinterpret_cast<NMHDR*>(lParam);
        if (hdr->idFrom == ID_LV_EXPORTS && hdr->code == NM_CUSTOMDRAW) {
            auto* cd = reinterpret_cast<NMLVCUSTOMDRAW*>(lParam);
            if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                cd->clrTextBk = ((int)cd->nmcd.dwItemSpec % 2 == 0) ? Theme::BG_ROW_EVEN : Theme::BG_ROW_ODD;
                cd->clrText   = Theme::ACCENT_GREEN;
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
