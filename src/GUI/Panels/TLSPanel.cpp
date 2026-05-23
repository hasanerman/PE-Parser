#include "GUI/Panels/TLSPanel.h"
#include "GUI/Theme.h"
#include "Utils/HexFormatter.h"
#include "Utils/StringUtils.h"
#include <commctrl.h>

#define ID_LV_TLS_INFO 3400
#define ID_LV_TLS_CB   3401

static HWND s_lvTlsInfo = nullptr;
static HWND s_lvTlsCb   = nullptr;

static std::wstring W(const std::string& s) { return AnsiToWide(s); }

static void AddRow(HWND lv, const std::wstring& field, const std::wstring& value, int& idx) {
    LVITEMW item = {};
    item.mask    = LVIF_TEXT;
    item.iItem   = idx;
    item.pszText = const_cast<wchar_t*>(field.c_str());
    ListView_InsertItem(lv, &item);
    ListView_SetItemText(lv, idx, 1, const_cast<wchar_t*>(value.c_str()));
    ++idx;
}

bool TLSPanel::Register(HINSTANCE hInstance) {
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hbrBackground = Theme::brushBgPrimary;
    wc.lpszClassName = CLASS_NAME;
    return RegisterClassExW(&wc) != 0;
}

HWND TLSPanel::Create(HWND parent, HINSTANCE hInstance, int x, int y, int w, int h) {
    return CreateWindowExW(0, CLASS_NAME, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        x, y, w, h, parent, nullptr, hInstance, nullptr);
}

void TLSPanel::Resize(HWND panel, int w, int h) {
    int half = h / 2;
    if (s_lvTlsInfo) SetWindowPos(s_lvTlsInfo, nullptr, 0, 0,    w, half,     SWP_NOZORDER);
    if (s_lvTlsCb)   SetWindowPos(s_lvTlsCb,   nullptr, 0, half, w, h - half, SWP_NOZORDER);
}

void TLSPanel::Clear(HWND panel) {
    if (s_lvTlsInfo) ListView_DeleteAllItems(s_lvTlsInfo);
    if (s_lvTlsCb)   ListView_DeleteAllItems(s_lvTlsCb);
}

void TLSPanel::Populate(HWND panel, const PEAnalysisResult& r) {
    if (!s_lvTlsInfo) return;
    ListView_DeleteAllItems(s_lvTlsInfo);
    ListView_DeleteAllItems(s_lvTlsCb);

    int idx = 0;
    if (!r.tls.hasTLS) {
        AddRow(s_lvTlsInfo, L"TLS Directory", L"Not present in this PE file", idx);
        return;
    }

    AddRow(s_lvTlsInfo, L"TLS Present",             L"Yes", idx);
    AddRow(s_lvTlsInfo, L"Start of Raw Data",        W(ToHex64(r.tls.startAddressOfRawData)), idx);
    AddRow(s_lvTlsInfo, L"End of Raw Data",          W(ToHex64(r.tls.endAddressOfRawData)), idx);
    AddRow(s_lvTlsInfo, L"Address of Index",         W(ToHex64(r.tls.addressOfIndex)), idx);
    AddRow(s_lvTlsInfo, L"Address of Callbacks",     W(ToHex64(r.tls.addressOfCallbacks)), idx);
    AddRow(s_lvTlsInfo, L"Size of Zero Fill",        W(std::to_string(r.tls.sizeOfZeroFill) + " bytes"), idx);
    AddRow(s_lvTlsInfo, L"Characteristics",          W(ToHex32(r.tls.characteristics)), idx);
    AddRow(s_lvTlsInfo, L"Callback Count",           W(std::to_string(r.tls.callbacks.size())), idx);

    for (int i = 0; i < (int)r.tls.callbacks.size(); ++i) {
        LVITEMW item = {};
        item.mask    = LVIF_TEXT;
        item.iItem   = i;
        std::wstring num = W(std::to_string(i + 1));
        item.pszText = const_cast<wchar_t*>(num.c_str());
        ListView_InsertItem(s_lvTlsCb, &item);
        std::wstring addr = W(r.tls.callbacks[i].addressStr);
        ListView_SetItemText(s_lvTlsCb, i, 1, const_cast<wchar_t*>(addr.c_str()));
        std::wstring note = L"Executes BEFORE entry point!";
        ListView_SetItemText(s_lvTlsCb, i, 2, const_cast<wchar_t*>(note.c_str()));
    }
}

LRESULT CALLBACK TLSPanel::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        RECT rc; GetClientRect(hwnd, &rc);
        HINSTANCE hInst = (HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE);
        int half = rc.bottom / 2;

        s_lvTlsInfo = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_NOSORTHEADER,
            0, 0, rc.right, half, hwnd, (HMENU)ID_LV_TLS_INFO, hInst, nullptr);

        s_lvTlsCb = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_NOSORTHEADER,
            0, half, rc.right, rc.bottom - half, hwnd, (HMENU)ID_LV_TLS_CB, hInst, nullptr);

        Theme::ApplyDarkListView(s_lvTlsInfo);
        Theme::ApplyDarkListView(s_lvTlsCb);
        SendMessageW(s_lvTlsInfo, WM_SETFONT, (WPARAM)Theme::fontMono, TRUE);
        SendMessageW(s_lvTlsCb,   WM_SETFONT, (WPARAM)Theme::fontMono, TRUE);
        ListView_SetExtendedListViewStyle(s_lvTlsInfo, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);
        ListView_SetExtendedListViewStyle(s_lvTlsCb,   LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

        LVCOLUMNW col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        col.pszText = const_cast<wchar_t*>(L"Field");  col.cx = 230; ListView_InsertColumn(s_lvTlsInfo, 0, &col);
        col.pszText = const_cast<wchar_t*>(L"Value");  col.cx = 500; ListView_InsertColumn(s_lvTlsInfo, 1, &col);

        col.pszText = const_cast<wchar_t*>(L"#");       col.cx = 60;  ListView_InsertColumn(s_lvTlsCb, 0, &col);
        col.pszText = const_cast<wchar_t*>(L"Callback VA"); col.cx = 200; ListView_InsertColumn(s_lvTlsCb, 1, &col);
        col.pszText = const_cast<wchar_t*>(L"Note");    col.cx = 400; ListView_InsertColumn(s_lvTlsCb, 2, &col);
        return 0;
    }
    case WM_SIZE: {
        int w = LOWORD(lParam), h = HIWORD(lParam);
        int half = h / 2;
        if (s_lvTlsInfo) SetWindowPos(s_lvTlsInfo, nullptr, 0, 0,    w, half,     SWP_NOZORDER);
        if (s_lvTlsCb)   SetWindowPos(s_lvTlsCb,   nullptr, 0, half, w, h - half, SWP_NOZORDER);
        return 0;
    }
    case WM_NOTIFY: {
        auto* hdr = reinterpret_cast<NMHDR*>(lParam);
        if ((hdr->idFrom == ID_LV_TLS_INFO || hdr->idFrom == ID_LV_TLS_CB) && hdr->code == NM_CUSTOMDRAW) {
            auto* cd = reinterpret_cast<NMLVCUSTOMDRAW*>(lParam);
            if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                cd->clrTextBk = ((int)cd->nmcd.dwItemSpec % 2 == 0) ? Theme::BG_ROW_EVEN : Theme::BG_ROW_ODD;
                cd->clrText   = hdr->idFrom == ID_LV_TLS_CB ? Theme::LEVEL_CRITICAL : Theme::TEXT_PRIMARY;
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
