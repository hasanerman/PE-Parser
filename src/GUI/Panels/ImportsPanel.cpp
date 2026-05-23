#include "GUI/Panels/ImportsPanel.h"
#include "GUI/Theme.h"
#include "Utils/HexFormatter.h"
#include "Utils/StringUtils.h"
#include <commctrl.h>

#define ID_LV_DLLS   3200
#define ID_LV_FUNCS  3201

static HWND s_hwndEditSearch = nullptr;
static HWND s_lvDlls  = nullptr;
static HWND s_lvFuncs = nullptr;
static std::vector<ImportLibrary> s_imports;

static std::wstring W(const std::string& s) { return AnsiToWide(s); }

void ImportsPanel::UpdateFunctionList(int dllIndex) {
    if (!s_lvFuncs || dllIndex < 0 || dllIndex >= (int)s_imports.size()) {
        if (s_lvFuncs) ListView_DeleteAllItems(s_lvFuncs);
        return;
    }
    ListView_DeleteAllItems(s_lvFuncs);

    wchar_t szSearch[256] = {};
    GetWindowTextW(s_hwndEditSearch, szSearch, 256);
    std::string searchStr = WideToAnsi(szSearch);
    for (char& c : searchStr) {
        c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    }

    const auto& lib = s_imports[dllIndex];
    int insertedCount = 0;
    for (int i = 0; i < (int)lib.functions.size(); ++i) {
        const auto& fn = lib.functions[i];
        if (!searchStr.empty()) {
            std::string lowerName = fn.name;
            for (char& c : lowerName) {
                c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
            }
            if (lowerName.find(searchStr) == std::string::npos) {
                continue;
            }
        }

        LVITEMW item = {};
        item.mask    = LVIF_TEXT | LVIF_PARAM;
        item.iItem   = insertedCount;
        item.lParam  = i;
        std::wstring name = W(fn.name);
        item.pszText = const_cast<wchar_t*>(name.c_str());
        ListView_InsertItem(s_lvFuncs, &item);

        std::wstring hint = fn.importedByOrdinal ? L"(ordinal)" : W(ToHex16(fn.hint));
        ListView_SetItemText(s_lvFuncs, insertedCount, 1, const_cast<wchar_t*>(hint.c_str()));
        std::wstring flag = fn.isSuspicious ? L"SUSPICIOUS" : L"OK";
        ListView_SetItemText(s_lvFuncs, insertedCount, 2, const_cast<wchar_t*>(flag.c_str()));

        insertedCount++;
    }
}

bool ImportsPanel::Register(HINSTANCE hInstance) {
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hbrBackground = Theme::brushBgPrimary;
    wc.lpszClassName = CLASS_NAME;
    return RegisterClassExW(&wc) != 0;
}

HWND ImportsPanel::Create(HWND parent, HINSTANCE hInstance, int x, int y, int w, int h) {
    return CreateWindowExW(0, CLASS_NAME, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        x, y, w, h, parent, nullptr, hInstance, nullptr);
}

void ImportsPanel::Resize(HWND panel, int w, int h) {
    SetWindowPos(panel, nullptr, 0, 0, w, h, SWP_NOMOVE | SWP_NOZORDER);
}

void ImportsPanel::Clear(HWND panel) {
    s_imports.clear();
    SetWindowTextW(s_hwndEditSearch, L"");
    if (s_lvDlls)  ListView_DeleteAllItems(s_lvDlls);
    if (s_lvFuncs) ListView_DeleteAllItems(s_lvFuncs);
}

void ImportsPanel::Populate(HWND panel, const PEAnalysisResult& r) {
    if (!s_lvDlls) return;
    s_imports = r.imports;
    SetWindowTextW(s_hwndEditSearch, L"");
    ListView_DeleteAllItems(s_lvDlls);
    ListView_DeleteAllItems(s_lvFuncs);

    for (int i = 0; i < (int)r.imports.size(); ++i) {
        const auto& lib = r.imports[i];
        LVITEMW item = {};
        item.mask    = LVIF_TEXT;
        item.iItem   = i;
        std::wstring name = W(lib.name);
        item.pszText = const_cast<wchar_t*>(name.c_str());
        ListView_InsertItem(s_lvDlls, &item);

        std::wstring cnt = W(std::to_string(lib.functions.size()) + " fn");
        ListView_SetItemText(s_lvDlls, i, 1, const_cast<wchar_t*>(cnt.c_str()));
        std::wstring flag = lib.hasSuspiciousFunctions ? L"SUSP!" : L"OK";
        ListView_SetItemText(s_lvDlls, i, 2, const_cast<wchar_t*>(flag.c_str()));
    }

    if (!r.imports.empty()) {
        ListView_SetItemState(s_lvDlls, 0, LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
        UpdateFunctionList(0);
    }
}

LRESULT CALLBACK ImportsPanel::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        HINSTANCE hInst = (HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE);

        s_hwndEditSearch = CreateWindowExW(0, WC_EDITW, L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            10, 10, 250, 26, hwnd, nullptr, hInst, nullptr);
        SendMessageW(s_hwndEditSearch, WM_SETFONT, (WPARAM)Theme::fontUI, TRUE);

        s_lvDlls = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
            10, 45, 100, 100, hwnd, (HMENU)ID_LV_DLLS, hInst, nullptr);

        s_lvFuncs = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
            110, 45, 100, 100, hwnd, (HMENU)ID_LV_FUNCS, hInst, nullptr);

        Theme::ApplyDarkListView(s_lvDlls);
        Theme::ApplyDarkListView(s_lvFuncs);
        SendMessageW(s_lvDlls,  WM_SETFONT, (WPARAM)Theme::fontMono, TRUE);
        SendMessageW(s_lvFuncs, WM_SETFONT, (WPARAM)Theme::fontMono, TRUE);
        ListView_SetExtendedListViewStyle(s_lvDlls,  LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
        ListView_SetExtendedListViewStyle(s_lvFuncs, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

        LVCOLUMNW col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.pszText = const_cast<wchar_t*>(L"DLL Name");  col.cx = 200; ListView_InsertColumn(s_lvDlls, 0, &col);
        col.pszText = const_cast<wchar_t*>(L"Functions"); col.cx = 70;  ListView_InsertColumn(s_lvDlls, 1, &col);
        col.pszText = const_cast<wchar_t*>(L"Flag");      col.cx = 60;  ListView_InsertColumn(s_lvDlls, 2, &col);

        col.pszText = const_cast<wchar_t*>(L"Function Name"); col.cx = 350; ListView_InsertColumn(s_lvFuncs, 0, &col);
        col.pszText = const_cast<wchar_t*>(L"Hint");          col.cx = 80;  ListView_InsertColumn(s_lvFuncs, 1, &col);
        col.pszText = const_cast<wchar_t*>(L"Status");        col.cx = 120; ListView_InsertColumn(s_lvFuncs, 2, &col);
        return 0;
    }
    case WM_SIZE: {
        int w = LOWORD(lParam), h = HIWORD(lParam);
        int half = w / 3;
        SetWindowPos(s_hwndEditSearch, nullptr, 10, 10, 250, 26, SWP_NOZORDER);
        if (s_lvDlls)  SetWindowPos(s_lvDlls,  nullptr, 10,   45, half - 15, h - 55, SWP_NOZORDER);
        if (s_lvFuncs) SetWindowPos(s_lvFuncs, nullptr, half + 5, 45, w - half - 15, h - 55, SWP_NOZORDER);
        return 0;
    }
    case WM_COMMAND: {
        if (HIWORD(wParam) == EN_CHANGE && reinterpret_cast<HWND>(lParam) == s_hwndEditSearch) {
            int selDll = ListView_GetNextItem(s_lvDlls, -1, LVNI_SELECTED);
            if (selDll >= 0) {
                UpdateFunctionList(selDll);
            }
        }
        return 0;
    }
    case WM_NOTIFY: {
        auto* hdr = reinterpret_cast<NMHDR*>(lParam);
        if (hdr->idFrom == ID_LV_DLLS && hdr->code == LVN_ITEMCHANGED) {
            auto* nmlv = reinterpret_cast<NMLISTVIEW*>(lParam);
            if ((nmlv->uChanged & LVIF_STATE) && (nmlv->uNewState & LVIS_SELECTED)) {
                UpdateFunctionList(nmlv->iItem);
            }
        }
        if ((hdr->idFrom == ID_LV_DLLS || hdr->idFrom == ID_LV_FUNCS) && hdr->code == NM_CUSTOMDRAW) {
            auto* cd = reinterpret_cast<NMLVCUSTOMDRAW*>(lParam);
            if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                int idx = (int)cd->nmcd.dwItemSpec;
                bool susp = false;
                if (hdr->idFrom == ID_LV_DLLS && idx < (int)s_imports.size()) {
                    susp = s_imports[idx].hasSuspiciousFunctions;
                }
                if (hdr->idFrom == ID_LV_FUNCS) {
                    int selDll = ListView_GetNextItem(s_lvDlls, -1, LVNI_SELECTED);
                    if (selDll >= 0 && selDll < (int)s_imports.size()) {
                        LVITEMW item = {};
                        item.mask = LVIF_PARAM;
                        item.iItem = idx;
                        if (ListView_GetItem(s_lvFuncs, &item)) {
                            int originalIdx = (int)item.lParam;
                            if (originalIdx >= 0 && originalIdx < (int)s_imports[selDll].functions.size()) {
                                susp = s_imports[selDll].functions[originalIdx].isSuspicious;
                            }
                        }
                    }
                }
                if (susp) {
                    cd->clrTextBk = RGB(50, 25, 20);
                    cd->clrText   = Theme::ACCENT_ORANGE;
                } else {
                    cd->clrTextBk = (idx % 2 == 0) ? Theme::BG_ROW_EVEN : Theme::BG_ROW_ODD;
                    cd->clrText   = Theme::TEXT_PRIMARY;
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
