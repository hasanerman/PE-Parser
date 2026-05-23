#pragma once
#include <windows.h>
#include <string>
#include <cstdint>

class PEFile {
public:
    PEFile();
    ~PEFile();

    bool        Load(const std::string& filePath);
    bool        Load(const std::wstring& filePath);
    void        Unload();

    const BYTE* GetBase()     const;
    uint64_t    GetSize()     const;
    std::string GetPath()     const;
    bool        IsLoaded()    const;

private:
    HANDLE      m_hFile;
    HANDLE      m_hMapping;
    LPVOID      m_pView;
    uint64_t    m_fileSize;
    std::string m_filePath;
    bool        m_loaded;

    PEFile(const PEFile&) = delete;
    PEFile& operator=(const PEFile&) = delete;
};
