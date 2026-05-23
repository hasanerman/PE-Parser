#include "Core/PEFile.h"
#include "Utils/StringUtils.h"

PEFile::PEFile()
    : m_hFile(INVALID_HANDLE_VALUE)
    , m_hMapping(nullptr)
    , m_pView(nullptr)
    , m_fileSize(0)
    , m_loaded(false) {
}

PEFile::~PEFile() {
    Unload();
}

bool PEFile::Load(const std::wstring& filePath) {
    Unload();
    m_filePath = WideToAnsi(filePath);

    m_hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (m_hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER fileSize = {};
    if (!GetFileSizeEx(m_hFile, &fileSize)) {
        CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
        return false;
    }
    m_fileSize = static_cast<uint64_t>(fileSize.QuadPart);
    if (m_fileSize < sizeof(IMAGE_DOS_HEADER)) {
        CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
        return false;
    }

    m_hMapping = CreateFileMappingW(m_hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!m_hMapping) {
        CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
        return false;
    }

    m_pView = MapViewOfFile(m_hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!m_pView) {
        CloseHandle(m_hMapping);
        CloseHandle(m_hFile);
        m_hMapping = nullptr;
        m_hFile    = INVALID_HANDLE_VALUE;
        return false;
    }

    m_loaded = true;
    return true;
}

bool PEFile::Load(const std::string& filePath) {
    return Load(AnsiToWide(filePath));
}

void PEFile::Unload() {
    if (m_pView)    { UnmapViewOfFile(m_pView);    m_pView    = nullptr; }
    if (m_hMapping) { CloseHandle(m_hMapping);     m_hMapping = nullptr; }
    if (m_hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(m_hFile);
        m_hFile = INVALID_HANDLE_VALUE;
    }
    m_fileSize = 0;
    m_loaded   = false;
}

const BYTE* PEFile::GetBase()  const { return static_cast<const BYTE*>(m_pView); }
uint64_t    PEFile::GetSize()  const { return m_fileSize; }
std::string PEFile::GetPath()  const { return m_filePath; }
bool        PEFile::IsLoaded() const { return m_loaded; }
