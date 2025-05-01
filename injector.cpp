// MMAP DLL Injector (0.5.5b)
// Only work 64x Dll only
// NOTE: This injector doesn't support TLS Callback or exception tables

// WARNING: THIS BUILD IS ON BETA TESTING

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>

DWORD GetRobloxPID(const wchar_t* procName = L"RobloxPlayerBeta.exe") {
    PROCESSENTRY32W entry = { sizeof(PROCESSENTRY32W) };
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, procName) == 0) {
                CloseHandle(snapshot);
                return entry.th32ProcessID;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return 0;
}


bool ReadDLL(const std::string& path, BYTE*& buffer, DWORD& size) {
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) return false;
    size = static_cast<DWORD>(file.tellg());
    buffer = new BYTE[size];
    file.seekg(0);
    file.read(reinterpret_cast<char*>(buffer), size);
    file.close();
    return true;
}

bool ManualMap(HANDLE hProc, BYTE* dllBuffer) {
    auto* dos = (PIMAGE_DOS_HEADER)dllBuffer;
    auto* nt = (PIMAGE_NT_HEADERS64)(dllBuffer + dos->e_lfanew);

    SIZE_T imageSize = nt->OptionalHeader.SizeOfImage;
    LPVOID remoteImage = VirtualAllocEx(hProc, nullptr, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteImage) return false;

    // Copy headers
    WriteProcessMemory(hProc, remoteImage, dllBuffer, nt->OptionalHeader.SizeOfHeaders, nullptr);

    // Copy sections
    auto* section = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        WriteProcessMemory(hProc,
            (BYTE*)remoteImage + section->VirtualAddress,
            dllBuffer + section->PointerToRawData,
            section->SizeOfRawData,
            nullptr);
    }

    // Relocations
    SIZE_T delta = (SIZE_T)remoteImage - nt->OptionalHeader.ImageBase;
    if (delta && nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* reloc = (PIMAGE_BASE_RELOCATION)(dllBuffer +
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        while (reloc->SizeOfBlock) {
            DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* relocData = (WORD*)(reloc + 1);

            for (DWORD i = 0; i < count; i++) {
                if ((relocData[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                    SIZE_T* patch = (SIZE_T*)(dllBuffer +
                        reloc->VirtualAddress + (relocData[i] & 0xFFF));
                    *patch += delta;
                }
            }

            reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
        }
    }

    // Entry Point
    LPTHREAD_START_ROUTINE entry = (LPTHREAD_START_ROUTINE)((BYTE*)remoteImage + nt->OptionalHeader.AddressOfEntryPoint);
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, entry, remoteImage, 0, nullptr);
    if (!hThread) return false;

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    return true;
}

int main() {
    std::string dllPath = "C:\\Path\\To\\Your64bitDLL.dll";
    DWORD pid = GetRobloxPID();

    if (!pid) {
        std::cout << "[!] Roblox not running.\n";
        return 1;
    }

    BYTE* buffer = nullptr;
    DWORD size = 0;
    if (!ReadDLL(dllPath, buffer, size)) {
        std::cout << "[!] Failed to read DLL.\n";
        return 1;
    }

    std::cout << "[*] Injecting...\n";
    if (ManualMap(hProc, buffer)) {
        std::cout << "[+] Injection success.\n";
    } else {
        std::cout << "[-] Injection failed.\n";
    }


    delete[] buffer;
    CloseHandle(hProc);
    return 0;

 
}
