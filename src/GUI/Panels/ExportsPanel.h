#pragma once
#include <windows.h>
#include "Core/PEData.h"

class ExportsPanel {
public:
    static bool Register(HINSTANCE hInstance);
    static HWND Create(HWND parent, HINSTANCE hInstance, int x, int y, int w, int h);
    static void Populate(HWND panel, const PEAnalysisResult& result);
    static void Resize(HWND panel, int w, int h);
    static void Clear(HWND panel);

private:
    static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static constexpr wchar_t CLASS_NAME[] = L"PEExportsPanel";
};
