#include <windows.h>
#include <commctrl.h>
#include "GUI/MainWindow.h"
#include "GUI/Theme.h"

#pragma comment(lib, "Comctl32.lib")
#pragma comment(linker, "/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE, LPSTR, int nCmdShow) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);

    INITCOMMONCONTROLSEX icc = {};
    icc.dwSize = sizeof(icc);
    icc.dwICC  = ICC_WIN95_CLASSES | ICC_STANDARD_CLASSES |
                 ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES |
                 ICC_TAB_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&icc);

    Theme::Initialize();

    if (!MainWindow::Register(hInstance)) {
        MessageBoxW(nullptr, L"Failed to register window class", L"Fatal Error", MB_ICONERROR);
        return 1;
    }

    HWND hwnd = MainWindow::Create(hInstance);
    if (!hwnd) {
        MessageBoxW(nullptr, L"Failed to create main window", L"Fatal Error", MB_ICONERROR);
        return 1;
    }

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    return MainWindow::RunMessageLoop();
}
