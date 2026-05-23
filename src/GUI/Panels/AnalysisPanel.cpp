#include "GUI/Panels/AnalysisPanel.h"
#include "GUI/Theme.h"
#include "Utils/StringUtils.h"
#include <commctrl.h>

#define ID_LV_ANALYSIS 3600

static HWND s_lvAnalysis = nullptr;
static std::vector<SuspiciousFlag> s_flags;

static std::wstring W(const std::string& s) { return AnsiToWide(s); }

bool AnalysisPanel::Register(HINSTANCE hInstance) {
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hbrBackground = Theme::brushBgPrimary;
    wc.lpszClassName = CLASS_NAME;
    return RegisterClassExW(&wc) != 0;
}

HWND AnalysisPanel::Create(HWND parent, HINSTANCE hInstance, int x, int y, int w, int h) {
    return CreateWindowExW(0, CLASS_NAME, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        x, y, w, h, parent, nullptr, hInstance, nullptr);
}

void AnalysisPanel::Resize(HWND panel, int w, int h) {
    if (s_lvAnalysis) SetWindowPos(s_lvAnalysis, nullptr, 0, 0, w, h, SWP_NOZORDER | SWP_NOMOVE);
}

void AnalysisPanel::Clear(HWND panel) {
    s_flags.clear();
    if (s_lvAnalysis) ListView_DeleteAllItems(s_lvAnalysis);
}

void AnalysisPanel::Populate(HWND panel, const PEAnalysisResult& r) {
    if (!s_lvAnalysis) return;
    ListView_DeleteAllItems(s_lvAnalysis);
    s_flags = r.suspiciousFlags;

    for (int i = 0; i < (int)r.suspiciousFlags.size(); ++i) {
        const auto& f = r.suspiciousFlags[i];
        std::wstring level;
        switch (f.level) {
        case SuspiciousLevel::Critical: level = L"[CRITICAL]"; break;
        case SuspiciousLevel::Warning:  level = L"[WARNING] "; break;
        default:                        level = L"[INFO]    "; break;
        }
        LVITEMW item = {};
        item.mask    = LVIF_TEXT;
        item.iItem   = i;
        item.pszText = const_cast<wchar_t*>(level.c_str());
        ListView_InsertItem(s_lvAnalysis, &item);

        std::wstring cat  = W(f.category);
        std::wstring desc = W(f.description);
        ListView_SetItemText(s_lvAnalysis, i, 1, const_cast<wchar_t*>(cat.c_str()));
        ListView_SetItemText(s_lvAnalysis, i, 2, const_cast<wchar_t*>(desc.c_str()));
    }
}

LRESULT CALLBACK AnalysisPanel::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        RECT rc; GetClientRect(hwnd, &rc);
        s_lvAnalysis = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_NOSORTHEADER,
            0, 0, rc.right, rc.bottom, hwnd, (HMENU)ID_LV_ANALYSIS,
            (HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE), nullptr);

        Theme::ApplyDarkListView(s_lvAnalysis);
        SendMessageW(s_lvAnalysis, WM_SETFONT, (WPARAM)Theme::fontUI, TRUE);
        ListView_SetExtendedListViewStyle(s_lvAnalysis, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

        LVCOLUMNW col = {};
        col.mask = LVCF_TEXT | LVCF_WIDTH;
        struct ColDef { const wchar_t* n; int w; };
        ColDef cols[] = { {L"Level",110},{L"Category",120},{L"Description",900} };
        for (int i = 0; i < 3; ++i) {
            col.pszText = const_cast<wchar_t*>(cols[i].n);
            col.cx      = cols[i].w;
            ListView_InsertColumn(s_lvAnalysis, i, &col);
        }
        return 0;
    }
    case WM_SIZE:
        if (s_lvAnalysis) SetWindowPos(s_lvAnalysis, nullptr, 0, 0, LOWORD(lParam), HIWORD(lParam), SWP_NOZORDER);
        return 0;
    case WM_NOTIFY: {
        auto* hdr = reinterpret_cast<NMHDR*>(lParam);
        if (hdr->idFrom == ID_LV_ANALYSIS && hdr->code == NM_CUSTOMDRAW) {
            auto* cd = reinterpret_cast<NMLVCUSTOMDRAW*>(lParam);
            if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                int idx = (int)cd->nmcd.dwItemSpec;
                if (idx >= 0 && idx < (int)s_flags.size()) {
                    switch (s_flags[idx].level) {
                    case SuspiciousLevel::Critical:
                        cd->clrTextBk = RGB(55, 20, 25);
                        cd->clrText   = Theme::LEVEL_CRITICAL;
                        break;
                    case SuspiciousLevel::Warning:
                        cd->clrTextBk = RGB(50, 42, 15);
                        cd->clrText   = Theme::LEVEL_WARNING;
                        break;
                    default:
                        cd->clrTextBk = (idx % 2 == 0) ? Theme::BG_ROW_EVEN : Theme::BG_ROW_ODD;
                        cd->clrText   = Theme::LEVEL_INFO;
                        break;
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
