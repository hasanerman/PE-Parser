#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <algorithm>

std::string WideToAnsi(const std::wstring& wide);
std::wstring AnsiToWide(const std::string& ansi);
std::string Join(const std::vector<std::string>& parts, const std::string& sep);
std::string TrimString(const std::string& str);
std::string GetFileNameFromPath(const std::string& path);
std::string GetFileNameFromPath(const std::wstring& path);
bool EndsWith(const std::string& str, const std::string& suffix);
std::string ToLower(const std::string& str);
std::string EscapeJSON(const std::string& str);
std::string BoolToStr(bool v);
