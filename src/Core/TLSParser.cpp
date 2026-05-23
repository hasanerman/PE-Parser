#include "Core/TLSParser.h"
#include "Utils/RVAUtils.h"
#include "Utils/HexFormatter.h"

TLSInfo TLSParser::Parse(const BYTE* base, uint64_t fileSize,
    const OptionalHeaderInfo& optHeader, const std::vector<SectionInfo>& sections)
{
    TLSInfo info = {};
    info.hasTLS = false;

    const DataDirectoryEntry& tlsDir = optHeader.dataDirectories[IMAGE_DIRECTORY_ENTRY_TLS];
    if (!tlsDir.isPresent) return info;

    DWORD offset = RVAToOffset(tlsDir.virtualAddress, sections);
    if (offset == 0) return info;

    info.hasTLS = true;

    if (optHeader.is64Bit) {
        if (offset + sizeof(IMAGE_TLS_DIRECTORY64) > fileSize) return info;
        auto* tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY64*>(base + offset);

        info.startAddressOfRawData = tls->StartAddressOfRawData;
        info.endAddressOfRawData   = tls->EndAddressOfRawData;
        info.addressOfIndex        = tls->AddressOfIndex;
        info.addressOfCallbacks    = tls->AddressOfCallBacks;
        info.sizeOfZeroFill        = tls->SizeOfZeroFill;
        info.characteristics       = tls->Characteristics;

        if (tls->AddressOfCallBacks != 0) {
            DWORD cbOffset = RVAToOffset(
                static_cast<DWORD>(tls->AddressOfCallBacks - optHeader.imageBase), sections);
            if (cbOffset != 0) {
                auto* cb = reinterpret_cast<const ULONGLONG*>(base + cbOffset);
                while (cbOffset + sizeof(ULONGLONG) <= fileSize && *cb != 0) {
                    TLSCallbackInfo cbInfo = {};
                    cbInfo.virtualAddress = *cb;
                    cbInfo.addressStr     = ToHex64(*cb);
                    info.callbacks.push_back(cbInfo);
                    ++cb;
                    cbOffset += sizeof(ULONGLONG);
                }
            }
        }
    } else {
        if (offset + sizeof(IMAGE_TLS_DIRECTORY32) > fileSize) return info;
        auto* tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY32*>(base + offset);

        info.startAddressOfRawData = tls->StartAddressOfRawData;
        info.endAddressOfRawData   = tls->EndAddressOfRawData;
        info.addressOfIndex        = tls->AddressOfIndex;
        info.addressOfCallbacks    = tls->AddressOfCallBacks;
        info.sizeOfZeroFill        = tls->SizeOfZeroFill;
        info.characteristics       = tls->Characteristics;

        if (tls->AddressOfCallBacks != 0) {
            DWORD cbOffset = RVAToOffset(
                tls->AddressOfCallBacks - static_cast<DWORD>(optHeader.imageBase), sections);
            if (cbOffset != 0) {
                auto* cb = reinterpret_cast<const DWORD*>(base + cbOffset);
                while (cbOffset + sizeof(DWORD) <= fileSize && *cb != 0) {
                    TLSCallbackInfo cbInfo = {};
                    cbInfo.virtualAddress = *cb;
                    cbInfo.addressStr     = ToHex32(*cb);
                    info.callbacks.push_back(cbInfo);
                    ++cb;
                    cbOffset += sizeof(DWORD);
                }
            }
        }
    }

    return info;
}
