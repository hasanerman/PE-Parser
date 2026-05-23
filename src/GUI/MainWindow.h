#pragma once
#include <windows.h>
#include <commctrl.h>
#include <string>
#include "Core/PEData.h"
#include "Core/PEFile.h"

class MainWindow {
public:
    static bool Register(HINSTANCE hInstance);
    static HWND Create(HINSTANCE hInstance);
    static int  RunMessageLoop();

private:
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK ToolbarProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uid, DWORD_PTR data);

    static void OnCreate(HWND hwnd);
    static void OnSize(HWND hwnd, int w, int h);
    static void OnCommand(HWND hwnd, WPARAM wParam);
    static void OnNotify(HWND hwnd, LPARAM lParam);
    static void OnDropFiles(HWND hwnd, HDROP hDrop);
    static void OnPaint(HWND hwnd);
    static void OnDestroy(HWND hwnd);

    static void OpenFile(HWND hwnd);
    static void ExportJSON(HWND hwnd);
    static void SaveOverlay(HWND hwnd);
    static void LoadPEFile(HWND hwnd, const std::wstring& path);
    static void UpdateAllPanels();
    static void SwitchToTab(int tabIndex);
    static void UpdateStatusBar();
    static void ShowAbout(HWND hwnd);

    static void CreateToolbarArea(HWND hwnd);
    static void CreateTabControl(HWND hwnd);
    static void CreateStatusBar(HWND hwnd);
    static void CreateAllPanels(HWND hwnd);

    static HWND  s_hwnd;
    static HWND  s_hwndTab;
    static HWND  s_hwndStatus;
    static HWND  s_hwndToolbar;
    static HWND  s_hwndBtnOpen;
    static HWND  s_hwndBtnExport;
    static HWND  s_hwndBtnSaveOverlay;
    static HWND  s_hwndFileInfo;
    static HWND  s_panels[9];

    static PEAnalysisResult s_result;
    static PEFile           s_peFile;
    static HINSTANCE        s_hInstance;
    static int              s_currentTab;
    static bool             s_hasFile;

    static constexpr wchar_t CLASS_NAME[]   = L"PEParserMainWnd";
    static constexpr int     TOOLBAR_H      = 60;
    static constexpr int     STATUS_H       = 28;
    static constexpr int     PANEL_COUNT    = 9;
};
