#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <array>
#include <cstdint>

struct DOSHeaderInfo {
    WORD magic;
    WORD lastPageBytes;
    WORD pageCount;
    WORD relocCount;
    WORD headerSize;
    WORD minAlloc;
    WORD maxAlloc;
    WORD initialSS;
    WORD initialSP;
    WORD checksum;
    WORD initialIP;
    WORD initialCS;
    WORD relocTableOffset;
    WORD overlayNumber;
    WORD oemIdentifier;
    WORD oemInfo;
    DWORD peOffset;
    bool isValid;
};

struct FileHeaderInfo {
    WORD machine;
    std::string machineStr;
    WORD numberOfSections;
    DWORD timeDateStamp;
    std::string timestampStr;
    bool isValidTimestamp;
    WORD sizeOfOptionalHeader;
    WORD characteristics;
    bool isDLL;
    bool isExe;
    bool isDebug;
    bool isLargeAddressAware;
    bool is32BitMachine;
};

struct DataDirectoryEntry {
    DWORD virtualAddress;
    DWORD size;
    std::string name;
    bool isPresent;
};

struct OptionalHeaderInfo {
    WORD magic;
    bool is64Bit;
    BYTE majorLinkerVersion;
    BYTE minorLinkerVersion;
    DWORD sizeOfCode;
    DWORD sizeOfInitializedData;
    DWORD sizeOfUninitializedData;
    DWORD addressOfEntryPoint;
    DWORD baseOfCode;
    uint64_t imageBase;
    DWORD sectionAlignment;
    DWORD fileAlignment;
    WORD majorOSVersion;
    WORD minorOSVersion;
    WORD majorImageVersion;
    WORD minorImageVersion;
    WORD majorSubsystemVersion;
    WORD minorSubsystemVersion;
    DWORD sizeOfImage;
    DWORD sizeOfHeaders;
    DWORD checkSum;
    WORD subsystem;
    std::string subsystemStr;
    WORD dllCharacteristics;
    bool hasASLR;
    bool hasDEP;
    bool hasCFGuard;
    bool hasHighEntropyVA;
    bool hasForceIntegrity;
    uint64_t sizeOfStackReserve;
    uint64_t sizeOfStackCommit;
    uint64_t sizeOfHeapReserve;
    uint64_t sizeOfHeapCommit;
    DWORD numberOfRvaAndSizes;
    std::array<DataDirectoryEntry, 16> dataDirectories;
};

struct SectionInfo {
    std::string name;
    DWORD virtualSize;
    DWORD virtualAddress;
    DWORD sizeOfRawData;
    DWORD pointerToRawData;
    DWORD characteristics;
    bool isReadable;
    bool isWritable;
    bool isExecutable;
    double entropy;
    bool isWX;
};

struct ImportedFunction {
    std::string name;
    WORD hint;
    WORD ordinal;
    bool importedByOrdinal;
    bool isSuspicious;
};

struct ImportLibrary {
    std::string name;
    std::vector<ImportedFunction> functions;
    bool hasSuspiciousFunctions;
};

struct ExportedFunction {
    std::string name;
    DWORD rva;
    WORD ordinal;
    bool hasName;
    bool isForwarder;
    std::string forwarderName;
};

struct ExportInfo {
    bool hasExports;
    std::string dllName;
    DWORD base;
    DWORD numberOfFunctions;
    DWORD numberOfNames;
    DWORD timeDateStamp;
    std::vector<ExportedFunction> functions;
};

struct TLSCallbackInfo {
    uint64_t virtualAddress;
    std::string addressStr;
};

struct TLSInfo {
    bool hasTLS;
    uint64_t startAddressOfRawData;
    uint64_t endAddressOfRawData;
    uint64_t addressOfIndex;
    uint64_t addressOfCallbacks;
    DWORD sizeOfZeroFill;
    DWORD characteristics;
    std::vector<TLSCallbackInfo> callbacks;
};

struct ResourceEntry {
    std::string typeName;
    DWORD typeId;
    bool typeHasName;
    std::string name;
    DWORD nameId;
    bool nameHasName;
    WORD languageId;
    std::string languageStr;
    DWORD dataRVA;
    DWORD dataSize;
    DWORD codePage;
};

struct ResourceInfo {
    bool hasResources;
    std::vector<ResourceEntry> entries;
};

struct DebugInfo {
    bool hasDebugInfo;
    std::string pdbPath;
    std::string guid;
    DWORD age;
    std::string format;
};

struct VersionInfo {
    bool hasVersionInfo;
    std::string companyName;
    std::string fileDescription;
    std::string fileVersion;
    std::string legalCopyright;
    std::string productName;
    std::string productVersion;
    std::string originalFilename;
};

struct PEStringInfo {
    std::string value;
    uint64_t offset;
    DWORD rva;
    std::string section;
    bool isUnicode;
    bool isNetwork;
    std::string networkType;
};

enum class SuspiciousLevel {
    Info     = 0,
    Warning  = 1,
    Critical = 2
};

struct SuspiciousFlag {
    SuspiciousLevel level;
    std::string category;
    std::string description;
};

struct PEAnalysisResult {
    bool isValid;
    std::string errorMessage;
    std::string filePath;
    std::string fileName;
    uint64_t fileSize;
    bool is64Bit;
    DOSHeaderInfo     dosHeader;
    FileHeaderInfo    fileHeader;
    OptionalHeaderInfo optionalHeader;
    std::vector<SectionInfo>    sections;
    std::vector<ImportLibrary>  imports;
    ExportInfo                  exports;
    TLSInfo                     tls;
    ResourceInfo                resources;
    DebugInfo                   debug;
    VersionInfo                 version;
    std::vector<PEStringInfo>   strings;
    DWORD                       computedChecksum;
    bool                        isChecksumValid;
    uint64_t                    overlayOffset;
    uint64_t                    overlaySize;
    bool                        hasOverlay;
    std::vector<SuspiciousFlag> suspiciousFlags;
};
