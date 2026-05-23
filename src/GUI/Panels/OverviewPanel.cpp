#include "GUI/Panels/OverviewPanel.h"
#include "GUI/Theme.h"
#include "Utils/HexFormatter.h"
#include "Utils/StringUtils.h"
#include "Utils/Characteristics.h"
#include <commctrl.h>
#include <sstream>

#define ID_LV_OVERVIEW 3001

static HWND s_lvOverview = nullptr;

static void AddRow(HWND lv, const std::wstring& field, const std::wstring& value, int& idx) {
    LVITEMW item = {};
    item.mask    = LVIF_TEXT;
    item.iItem   = idx;
    item.pszText = const_cast<wchar_t*>(field.c_str());
    ListView_InsertItem(lv, &item);
    ListView_SetItemText(lv, idx, 1, const_cast<wchar_t*>(value.c_str()));
    ++idx;
}

static std::wstring W(const std::string& s) { return AnsiToWide(s); }

bool OverviewPanel::Register(HINSTANCE hInstance) {
    WNDCLASSEXW wc = {};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = hInstance;
    wc.hbrBackground = Theme::brushBgPrimary;
    wc.lpszClassName = CLASS_NAME;
    return RegisterClassExW(&wc) != 0;
}

HWND OverviewPanel::Create(HWND parent, HINSTANCE hInstance, int x, int y, int w, int h) {
    HWND hwnd = CreateWindowExW(0, CLASS_NAME, L"", WS_CHILD | WS_VISIBLE | WS_CLIPCHILDREN,
        x, y, w, h, parent, nullptr, hInstance, nullptr);
    return hwnd;
}

void OverviewPanel::Resize(HWND panel, int w, int h) {
    if (s_lvOverview) SetWindowPos(s_lvOverview, nullptr, 0, 0, w, h, SWP_NOZORDER | SWP_NOMOVE);
}

void OverviewPanel::Clear(HWND panel) {
    if (s_lvOverview) ListView_DeleteAllItems(s_lvOverview);
}

void OverviewPanel::Populate(HWND panel, const PEAnalysisResult& r) {
    if (!s_lvOverview) return;
    ListView_DeleteAllItems(s_lvOverview);
    int idx = 0;

    auto AddSep = [&](const std::wstring& title) {
        AddRow(s_lvOverview, L"--- " + title + L" ---", L"", idx);
    };

    AddSep(L"FILE INFO");
    AddRow(s_lvOverview, L"File Name",      W(r.fileName),  idx);
    AddRow(s_lvOverview, L"File Path",      W(r.filePath),  idx);
    AddRow(s_lvOverview, L"File Size",      W(FormatFileSize(r.fileSize)), idx);
    AddRow(s_lvOverview, L"Architecture",   W(r.is64Bit ? "PE32+ (64-bit)" : "PE32 (32-bit)"), idx);

    AddSep(L"DOS HEADER");
    AddRow(s_lvOverview, L"Magic",          W(ToHex16(r.dosHeader.magic) + " (MZ)"), idx);
    AddRow(s_lvOverview, L"PE Header Offset", W(ToHex32(r.dosHeader.peOffset)), idx);
    AddRow(s_lvOverview, L"Valid",          W(r.dosHeader.isValid ? "Yes" : "No"), idx);

    AddSep(L"FILE HEADER");
    AddRow(s_lvOverview, L"Machine",        W(r.fileHeader.machineStr), idx);
    AddRow(s_lvOverview, L"Sections",       W(std::to_string(r.fileHeader.numberOfSections)), idx);
    AddRow(s_lvOverview, L"Timestamp",      W(r.fileHeader.timestampStr), idx);
    AddRow(s_lvOverview, L"Type",           W(r.fileHeader.isDLL ? "DLL" : "EXE"), idx);
    AddRow(s_lvOverview, L"Characteristics", W(ToHex16(r.fileHeader.characteristics)), idx);

    AddSep(L"OPTIONAL HEADER");
    AddRow(s_lvOverview, L"Entry Point",    W(ToHex32(r.optionalHeader.addressOfEntryPoint)), idx);
    AddRow(s_lvOverview, L"Image Base",     W(ToHex64(r.optionalHeader.imageBase)), idx);
    AddRow(s_lvOverview, L"Subsystem",      W(r.optionalHeader.subsystemStr), idx);
    AddRow(s_lvOverview, L"Image Size",     W(FormatFileSize(r.optionalHeader.sizeOfImage)), idx);
    AddRow(s_lvOverview, L"Section Align",  W(ToHex32(r.optionalHeader.sectionAlignment)), idx);
    AddRow(s_lvOverview, L"File Align",     W(ToHex32(r.optionalHeader.fileAlignment)), idx);
    AddRow(s_lvOverview, L"Linker Version", W(std::to_string(r.optionalHeader.majorLinkerVersion) +
        "." + std::to_string(r.optionalHeader.minorLinkerVersion)), idx);
    AddRow(s_lvOverview, L"OS Version",     W(std::to_string(r.optionalHeader.majorOSVersion) +
        "." + std::to_string(r.optionalHeader.minorOSVersion)), idx);
    AddRow(s_lvOverview, L"Stack Reserve",  W(FormatFileSize(r.optionalHeader.sizeOfStackReserve)), idx);
    AddRow(s_lvOverview, L"Stack Commit",   W(FormatFileSize(r.optionalHeader.sizeOfStackCommit)), idx);
    AddRow(s_lvOverview, L"Heap Reserve",   W(FormatFileSize(r.optionalHeader.sizeOfHeapReserve)), idx);
    AddRow(s_lvOverview, L"Checksum",       W(ToHex32(r.optionalHeader.checkSum)), idx);

    AddSep(L"SECURITY MITIGATIONS");
    AddRow(s_lvOverview, L"ASLR (Dynamic Base)", W(r.optionalHeader.hasASLR ? "Enabled" : "DISABLED"), idx);
    AddRow(s_lvOverview, L"DEP (NX Compat)",     W(r.optionalHeader.hasDEP  ? "Enabled" : "DISABLED"), idx);
    AddRow(s_lvOverview, L"CFG (Control Flow)",  W(r.optionalHeader.hasCFGuard ? "Enabled" : "Not set"), idx);
    AddRow(s_lvOverview, L"High Entropy VA",     W(r.optionalHeader.hasHighEntropyVA ? "Enabled" : "Not set"), idx);
    AddRow(s_lvOverview, L"Force Integrity",     W(r.optionalHeader.hasForceIntegrity ? "Enabled" : "Not set"), idx);

    AddSep(L"VERSION INFORMATION");
    if (r.version.hasVersionInfo) {
        AddRow(s_lvOverview, L"Company Name",      W(r.version.companyName), idx);
        AddRow(s_lvOverview, L"File Description",  W(r.version.fileDescription), idx);
        AddRow(s_lvOverview, L"File Version",      W(r.version.fileVersion), idx);
        AddRow(s_lvOverview, L"Legal Copyright",   W(r.version.legalCopyright), idx);
        AddRow(s_lvOverview, L"Product Name",      W(r.version.productName), idx);
        AddRow(s_lvOverview, L"Product Version",   W(r.version.productVersion), idx);
        AddRow(s_lvOverview, L"Original Filename", W(r.version.originalFilename), idx);
    } else {
        AddRow(s_lvOverview, L"Version Information", L"Not Present / Failed to Query", idx);
    }

    AddSep(L"DEBUG SYMBOLS (PDB)");
    if (r.debug.hasDebugInfo) {
        AddRow(s_lvOverview, L"Format",            W(r.debug.format), idx);
        AddRow(s_lvOverview, L"PDB Path",          W(r.debug.pdbPath), idx);
        AddRow(s_lvOverview, L"GUID",              W(r.debug.guid), idx);
        AddRow(s_lvOverview, L"Age",               W(std::to_string(r.debug.age)), idx);
    } else {
        AddRow(s_lvOverview, L"Debug Info",        L"Not Present", idx);
    }

    AddSep(L"CHECKSUM & OVERLAY");
    std::wstring csStatus = r.isChecksumValid ? L"MATCH" : L"MISMATCH (Calculated: " + W(ToHex32(r.computedChecksum)) + L")";
    AddRow(s_lvOverview, L"PE Checksum Status", csStatus, idx);
    if (r.hasOverlay) {
        AddRow(s_lvOverview, L"Overlay Present",   L"Yes", idx);
        AddRow(s_lvOverview, L"Overlay Offset",    W(ToHex64(r.overlayOffset)), idx);
        AddRow(s_lvOverview, L"Overlay Size",      W(FormatFileSize(r.overlaySize)), idx);
    } else {
        AddRow(s_lvOverview, L"Overlay Present",   L"No", idx);
    }

    AddSep(L"DATA DIRECTORIES");
    for (const auto& dd : r.optionalHeader.dataDirectories) {
        if (dd.isPresent) {
            AddRow(s_lvOverview, W(dd.name),
                W(ToHex32(dd.virtualAddress) + "  size: " + std::to_string(dd.size) + " bytes"), idx);
        }
    }
}

LRESULT CALLBACK OverviewPanel::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        RECT rc; GetClientRect(hwnd, &rc);
        s_lvOverview = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
            WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_NOSORTHEADER | LVS_SINGLESEL,
            0, 0, rc.right, rc.bottom, hwnd, (HMENU)ID_LV_OVERVIEW,
            (HINSTANCE)GetWindowLongPtrW(hwnd, GWLP_HINSTANCE), nullptr);

        Theme::ApplyDarkListView(s_lvOverview);
        SendMessageW(s_lvOverview, WM_SETFONT, (WPARAM)Theme::fontMono, TRUE);
        ListView_SetExtendedListViewStyle(s_lvOverview,
            LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER | LVS_EX_GRIDLINES);

        LVCOLUMNW col = {};
        col.mask    = LVCF_TEXT | LVCF_WIDTH;
        col.pszText = const_cast<wchar_t*>(L"Field");
        col.cx      = 240;
        ListView_InsertColumn(s_lvOverview, 0, &col);
        col.pszText = const_cast<wchar_t*>(L"Value");
        col.cx      = 700;
        ListView_InsertColumn(s_lvOverview, 1, &col);
        return 0;
    }
    case WM_SIZE:
        if (s_lvOverview) SetWindowPos(s_lvOverview, nullptr, 0, 0, LOWORD(lParam), HIWORD(lParam), SWP_NOZORDER);
        return 0;
    case WM_NOTIFY: {
        auto* hdr = reinterpret_cast<NMHDR*>(lParam);
        if (hdr->idFrom == ID_LV_OVERVIEW && hdr->code == NM_CUSTOMDRAW) {
            auto* cd = reinterpret_cast<NMLVCUSTOMDRAW*>(lParam);
            if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                cd->clrTextBk = (cd->nmcd.dwItemSpec % 2 == 0) ? Theme::BG_ROW_EVEN : Theme::BG_ROW_ODD;
                cd->clrText   = Theme::TEXT_PRIMARY;
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
