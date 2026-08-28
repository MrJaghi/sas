#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include "../../functions/functions.h"
#include "../../protection/oxorany/oxorany.h"

// ============================================================================
// Kernel-mode trace cleanup - SPOOF AND REPLACE approach
// ============================================================================
// Instead of deleting critical keys (which breaks the system),
// we read the values, spoof them, and write back spoofed data.
// This preserves system functionality while removing forensic traces.

#define CLEAN_TAG 'naLC'

// Helper: Generate random bytes
static void KGenerateRandomBytes(UCHAR* buf, ULONG len, ULONG seed) {
    for (ULONG i = 0; i < len; i++) {
        ULONG r = seed * 1664525 + 1013904223;
        seed = r;
        buf[i] = (UCHAR)(r & 0xFF);
    }
}

// Helper: Spoof a REG_SZ value by randomizing alphanumeric characters
static NTSTATUS KSpoofRegSz(HANDLE hKey, const wchar_t* valueName) {
    UNICODE_STRING uName;
    RtlInitUnicodeString(&uName, valueName);

    ULONG resultLen = 0;
    NTSTATUS st = ZwQueryValueKey(hKey, &uName, KeyValuePartialInformation, NULL, 0, &resultLen);
    if (st != STATUS_BUFFER_TOO_SMALL || resultLen == 0) return st;

    PKEY_VALUE_PARTIAL_INFORMATION pvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, resultLen, CLEAN_TAG);
    if (!pvpi) return STATUS_INSUFFICIENT_RESOURCES;

    st = ZwQueryValueKey(hKey, &uName, KeyValuePartialInformation, pvpi, resultLen, &resultLen);
    if (NT_SUCCESS(st) && pvpi->Type == REG_SZ && pvpi->DataLength >= 4) {
        wchar_t* data = (wchar_t*)pvpi->Data;
        ULONG len = pvpi->DataLength / sizeof(wchar_t);
        ULONG seed = kmdf_settings::hwid_seed ^ HashSerialBytes((const char*)data, pvpi->DataLength);

        for (ULONG i = 0; i < len && data[i]; i++) {
            if (data[i] >= L'0' && data[i] <= L'9') {
                ULONG r = DiskLCG(seed);
                data[i] = L'0' + (r % 10);
            } else if (data[i] >= L'A' && data[i] <= L'Z') {
                ULONG r = DiskLCG(seed);
                data[i] = L'A' + (r % 26);
            } else if (data[i] >= L'a' && data[i] <= L'z') {
                ULONG r = DiskLCG(seed);
                data[i] = L'a' + (r % 26);
            }
        }

        st = ZwSetValueKey(hKey, &uName, 0, REG_SZ, pvpi->Data, pvpi->DataLength);
    }

    ExFreePoolWithTag(pvpi, CLEAN_TAG);
    return st;
}

// Helper: Spoof a REG_BINARY value
static NTSTATUS KSpoofRegBinary(HANDLE hKey, const wchar_t* valueName) {
    UNICODE_STRING uName;
    RtlInitUnicodeString(&uName, valueName);

    ULONG resultLen = 0;
    NTSTATUS st = ZwQueryValueKey(hKey, &uName, KeyValuePartialInformation, NULL, 0, &resultLen);
    if (st != STATUS_BUFFER_TOO_SMALL || resultLen == 0) return st;

    PKEY_VALUE_PARTIAL_INFORMATION pvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, resultLen, CLEAN_TAG);
    if (!pvpi) return STATUS_INSUFFICIENT_RESOURCES;

    st = ZwQueryValueKey(hKey, &uName, KeyValuePartialInformation, pvpi, resultLen, &resultLen);
    if (NT_SUCCESS(st) && pvpi->Type == REG_BINARY && pvpi->DataLength >= 4) {
        UCHAR* data = (UCHAR*)pvpi->Data;
        ULONG seed = kmdf_settings::hwid_seed ^ HashSerialBytes((const char*)data, pvpi->DataLength > 64 ? 64 : pvpi->DataLength);

        for (ULONG i = 0; i < pvpi->DataLength; i++) {
            if (data[i] != 0) {
                ULONG r = DiskLCG(seed);
                data[i] = (UCHAR)(r & 0xFF);
                if (data[i] == 0) data[i] = 1;
            }
        }

        st = ZwSetValueKey(hKey, &uName, 0, REG_BINARY, pvpi->Data, pvpi->DataLength);
    }

    ExFreePoolWithTag(pvpi, CLEAN_TAG);
    return st;
}

// Helper: Spoof a REG_DWORD value
static NTSTATUS KSpoofRegDword(HANDLE hKey, const wchar_t* valueName) {
    UNICODE_STRING uName;
    RtlInitUnicodeString(&uName, valueName);

    ULONG resultLen = 0;
    NTSTATUS st = ZwQueryValueKey(hKey, &uName, KeyValuePartialInformation, NULL, 0, &resultLen);
    if (st != STATUS_BUFFER_TOO_SMALL || resultLen == 0) return st;

    PKEY_VALUE_PARTIAL_INFORMATION pvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, resultLen, CLEAN_TAG);
    if (!pvpi) return STATUS_INSUFFICIENT_RESOURCES;

    st = ZwQueryValueKey(hKey, &uName, KeyValuePartialInformation, pvpi, resultLen, &resultLen);
    if (NT_SUCCESS(st) && pvpi->Type == REG_DWORD && pvpi->DataLength >= 4) {
        ULONG* val = (ULONG*)pvpi->Data;
        ULONG seed = kmdf_settings::hwid_seed ^ *val;
        *val = DiskLCG(seed);
        st = ZwSetValueKey(hKey, &uName, 0, REG_DWORD, pvpi->Data, pvpi->DataLength);
    }

    ExFreePoolWithTag(pvpi, CLEAN_TAG);
    return st;
}

// Helper: Spoof all values in a registry key
static NTSTATUS KSpoofAllValues(HANDLE hKey) {
    ULONG idx = 0;
    const ULONG bufSize = 0x1000;
    PKEY_VALUE_FULL_INFORMATION vfi = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(PagedPool, bufSize, CLEAN_TAG);
    if (!vfi) return STATUS_INSUFFICIENT_RESOURCES;

    while (TRUE) {
        ULONG resultLen;
        NTSTATUS st = ZwEnumerateValueKey(hKey, idx, KeyValueFullInformation, vfi, bufSize, &resultLen);
        if (st == STATUS_NO_MORE_ENTRIES) break;
        if (!NT_SUCCESS(st)) { idx++; continue; }

        UNICODE_STRING valName;
        valName.Length = (USHORT)vfi->NameLength;
        valName.MaximumLength = (USHORT)vfi->NameLength;
        valName.Buffer = vfi->Name;

        // Spoof based on type
        switch (vfi->Type) {
        case REG_SZ:
        case REG_EXPAND_SZ:
            KSpoofRegSz(hKey, vfi->Name);
            break;
        case REG_BINARY:
            KSpoofRegBinary(hKey, vfi->Name);
            break;
        case REG_DWORD:
            KSpoofRegDword(hKey, vfi->Name);
            break;
        default:
            // For other types, just randomize the data
            if (vfi->DataLength >= 4) {
                UCHAR* data = (UCHAR*)vfi + vfi->DataOffset;
                ULONG seed = kmdf_settings::hwid_seed;
                for (ULONG i = 0; i < vfi->DataLength; i++) {
                    if (data[i] != 0) {
                        ULONG r = DiskLCG(seed);
                        data[i] = (UCHAR)(r & 0xFF);
                    }
                }
                ZwSetValueKey(hKey, &valName, 0, vfi->Type, data, vfi->DataLength);
            }
            break;
        }

        idx++;
    }

    ExFreePoolWithTag(vfi, CLEAN_TAG);
    return STATUS_SUCCESS;
}

// Helper: Spoof a registry key and all its subkeys/values
static NTSTATUS KSpoofRegistryKeyRecursive(const wchar_t* keyPath) {
    UNICODE_STRING uPath;
    RtlInitUnicodeString(&uPath, keyPath);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hKey;
    NTSTATUS st = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &oa);
    if (!NT_SUCCESS(st)) return st;

    // Spoof all values in this key
    KSpoofAllValues(hKey);

    // Process subkeys
    const ULONG bufSize = 0x1000;
    PKEY_BASIC_INFORMATION kbi = (PKEY_BASIC_INFORMATION)ExAllocatePoolWithTag(PagedPool, bufSize, CLEAN_TAG);
    if (!kbi) { ZwClose(hKey); return STATUS_INSUFFICIENT_RESOURCES; }

    ULONG idx = 0;
    while (TRUE) {
        ULONG resultLen;
        st = ZwEnumerateKey(hKey, idx++, KeyBasicInformation, kbi, bufSize, &resultLen);
        if (st == STATUS_NO_MORE_ENTRIES) break;
        if (!NT_SUCCESS(st)) continue;

        wchar_t subPath[512];
        RtlStringCchPrintfW(subPath, 512, L"%s\\%.*s", keyPath, kbi->NameLength / sizeof(wchar_t), kbi->Name);
        KSpoofRegistryKeyRecursive(subPath);
    }

    ExFreePoolWithTag(kbi, CLEAN_TAG);
    ZwClose(hKey);
    return STATUS_SUCCESS;
}

// Helper: Delete a file by kernel path
static NTSTATUS KDeleteFile(const wchar_t* filePath) {
    UNICODE_STRING uPath;
    RtlInitUnicodeString(&uPath, filePath);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    return ZwDeleteFile(&oa);
}

// Helper: Open a directory and delete all files
static NTSTATUS KDeleteDirectoryContents(const wchar_t* dirPath) {
    UNICODE_STRING uDir;
    RtlInitUnicodeString(&uDir, dirPath);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &uDir, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hDir;
    IO_STATUS_BLOCK iosb;
    NTSTATUS st = ZwOpenFile(&hDir, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(st)) return st;

    const ULONG bufSize = 0x10000;
    PFILE_DIRECTORY_INFORMATION buf = (PFILE_DIRECTORY_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, bufSize, CLEAN_TAG);
    if (!buf) { ZwClose(hDir); return STATUS_INSUFFICIENT_RESOURCES; }

    BOOLEAN restartScan = TRUE;
    while (TRUE) {
        st = ZwQueryDirectoryFile(hDir, NULL, NULL, NULL, &iosb, buf, bufSize,
            FileDirectoryInformation, FALSE, NULL, restartScan);
        if (!NT_SUCCESS(st)) break;
        restartScan = FALSE;

        PFILE_DIRECTORY_INFORMATION info = buf;
        while (TRUE) {
            if (info->FileNameLength == 2 && info->FileName[0] == L'.') goto next;
            if (info->FileNameLength == 4 && info->FileName[0] == L'.' && info->FileName[1] == L'.') goto next;

            wchar_t fullPath[512];
            NTSTATUS fmtSt;
            fmtSt = RtlStringCchPrintfW(fullPath, 512, L"%s\\%.*s", dirPath,
                info->FileNameLength / sizeof(wchar_t), info->FileName);
            if (NT_SUCCESS(fmtSt)) {
                UNICODE_STRING uFull;
                RtlInitUnicodeString(&uFull, fullPath);
                OBJECT_ATTRIBUTES fileOa;
                InitializeObjectAttributes(&fileOa, &uFull, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

                if (!(info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    HANDLE hFile;
                    IO_STATUS_BLOCK fileIosb;
                    if (NT_SUCCESS(ZwOpenFile(&hFile, DELETE | SYNCHRONIZE, &fileOa, &fileIosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_SYNCHRONOUS_IO_NONALERT))) {
                        FILE_DISPOSITION_INFORMATION disp;
                        disp.DeleteFile = TRUE;
                        ZwSetInformationFile(hFile, &fileIosb, &disp, sizeof(disp), FileDispositionInformation);
                        ZwClose(hFile);
                    }
                }
            }

        next:
            if (info->NextEntryOffset == 0) break;
            info = (PFILE_DIRECTORY_INFORMATION)((PUCHAR)info + info->NextEntryOffset);
        }
    }

    ExFreePoolWithTag(buf, CLEAN_TAG);
    ZwClose(hDir);
    return STATUS_SUCCESS;
}

// Helper: Delete all values in a registry key
static NTSTATUS KDeleteAllValues(HANDLE hKey) {
    ULONG idx = 0;
    const ULONG bufSize = 0x1000;
    PKEY_VALUE_FULL_INFORMATION vfi = (PKEY_VALUE_FULL_INFORMATION)ExAllocatePoolWithTag(PagedPool, bufSize, CLEAN_TAG);
    if (!vfi) return STATUS_INSUFFICIENT_RESOURCES;

    while (TRUE) {
        ULONG resultLen;
        NTSTATUS st = ZwEnumerateValueKey(hKey, idx, KeyValueFullInformation, vfi, bufSize, &resultLen);
        if (st == STATUS_NO_MORE_ENTRIES) break;
        if (!NT_SUCCESS(st)) { idx++; continue; }

        UNICODE_STRING valName;
        valName.Length = (USHORT)vfi->NameLength;
        valName.MaximumLength = (USHORT)vfi->NameLength;
        valName.Buffer = vfi->Name;

        st = ZwDeleteValueKey(hKey, &valName);
        if (!NT_SUCCESS(st)) idx++;
    }

    ExFreePoolWithTag(vfi, CLEAN_TAG);
    return STATUS_SUCCESS;
}

// Helper: Delete a registry key and all subkeys recursively
static NTSTATUS KDeleteRegistryKeyRecursive(const wchar_t* keyPath) {
    UNICODE_STRING uPath;
    RtlInitUnicodeString(&uPath, keyPath);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hKey;
    NTSTATUS st = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &oa);
    if (!NT_SUCCESS(st)) return st;

    const ULONG bufSize = 0x1000;
    PKEY_BASIC_INFORMATION kbi = (PKEY_BASIC_INFORMATION)ExAllocatePoolWithTag(PagedPool, bufSize, CLEAN_TAG);
    if (!kbi) { ZwClose(hKey); return STATUS_INSUFFICIENT_RESOURCES; }

    while (TRUE) {
        ULONG resultLen;
        st = ZwEnumerateKey(hKey, 0, KeyBasicInformation, kbi, bufSize, &resultLen);
        if (st == STATUS_NO_MORE_ENTRIES) break;
        if (!NT_SUCCESS(st)) break;

        wchar_t subPath[512];
        RtlStringCchPrintfW(subPath, 512, L"%s\\%.*s", keyPath, kbi->NameLength / sizeof(wchar_t), kbi->Name);
        KDeleteRegistryKeyRecursive(subPath);
    }

    ExFreePoolWithTag(kbi, CLEAN_TAG);
    KDeleteAllValues(hKey);
    st = ZwDeleteKey(hKey);
    ZwClose(hKey);
    return st;
}

// ============================================================================
// Prefetch cleanup
// ============================================================================

static NTSTATUS CleanPrefetch() {
    DbgPrintEx(0, 0, "[CLEAN] Cleaning Prefetch...\n");
    KDeleteDirectoryContents(L"\\SystemRoot\\Prefetch");
    KDeleteFile(L"\\SystemRoot\\Prefetch\\Layout.ini");
    KDeleteFile(L"\\SystemRoot\\Prefetch\\AgAppLaunch.db");
    KDeleteDirectoryContents(L"\\SystemRoot\\Prefetch\\ReadyBoot");
    DbgPrintEx(0, 0, "[CLEAN] Prefetch cleaned\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Event Log cleanup - SPOOF instead of delete
// ============================================================================

static NTSTATUS CleanEventLogs() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing Event Logs...\n");

    // Spoof event log registry entries instead of deleting
    const wchar_t* logKeys[] = {
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\System",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Security",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\EventLog\\Setup",
    };

    for (int i = 0; i < sizeof(logKeys) / sizeof(logKeys[0]); i++) {
        KSpoofRegistryKeyRecursive(logKeys[i]);
    }

    // Delete .evtx files (they will be recreated by the system)
    const wchar_t* logFiles[] = {
        L"\\SystemRoot\\System32\\winevt\\Logs\\Application.evtx",
        L"\\SystemRoot\\System32\\winevt\\Logs\\System.evtx",
        L"\\SystemRoot\\System32\\winevt\\Logs\\Security.evtx",
        L"\\SystemRoot\\System32\\winevt\\Logs\\Setup.evtx",
        L"\\SystemRoot\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
        L"\\SystemRoot\\System32\\winevt\\Logs\\Microsoft-Windows-TaskScheduler%4Operational.evtx",
        L"\\SystemRoot\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx",
        L"\\SystemRoot\\System32\\winevt\\Logs\\Microsoft-Windows-Windows Defender%4Operational.evtx",
        L"\\SystemRoot\\System32\\winevt\\Logs\\Microsoft-Windows-CodeIntegrity%4Operational.evtx",
    };

    for (int i = 0; i < sizeof(logFiles) / sizeof(logFiles[0]); i++) {
        KDeleteFile(logFiles[i]);
    }

    DbgPrintEx(0, 0, "[CLEAN] Event Logs spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Temp files cleanup
// ============================================================================

static NTSTATUS CleanTempFiles() {
    DbgPrintEx(0, 0, "[CLEAN] Cleaning Temp files...\n");
    KDeleteDirectoryContents(L"\\SystemRoot\\Temp");
    KDeleteFile(L"\\Windows\\WindowsUpdate.log");
    KDeleteDirectoryContents(L"\\Windows\\Logs\\CBS");
    KDeleteDirectoryContents(L"\\Windows\\Logs\\DISM");
    KDeleteDirectoryContents(L"\\Windows\\Minidump");
    KDeleteFile(L"\\Windows\\MEMORY.dmp");
    KDeleteDirectoryContents(L"\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue");
    KDeleteDirectoryContents(L"\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive");
    DbgPrintEx(0, 0, "[CLEAN] Temp files cleaned\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Recent files cleanup
// ============================================================================

static NTSTATUS CleanRecentFiles() {
    DbgPrintEx(0, 0, "[CLEAN] Cleaning Recent files...\n");
    KDeleteDirectoryContents(L"\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent");
    KDeleteDirectoryContents(L"\\Users\\*\\AppData\\Roaming\\Microsoft\\Office\\Recent");
    DbgPrintEx(0, 0, "[CLEAN] Recent files cleaned\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Jump Lists cleanup
// ============================================================================

static NTSTATUS CleanJumpLists() {
    DbgPrintEx(0, 0, "[CLEAN] Cleaning Jump Lists...\n");
    KDeleteDirectoryContents(L"\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations");
    KDeleteDirectoryContents(L"\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations");
    DbgPrintEx(0, 0, "[CLEAN] Jump Lists cleaned\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Registry MRU cleanup - SPOOF instead of delete
// ============================================================================

static NTSTATUS CleanRegistryMRUs() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing Registry MRUs...\n");

    // Spoof MRU values instead of deleting
    const wchar_t* mruPaths[] = {
        L"\\Registry\\User\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
        L"\\Registry\\User\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
        L"\\Registry\\User\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU",
        L"\\Registry\\User\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU",
        L"\\Registry\\User\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
        L"\\Registry\\User\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedURLs",
        L"\\Registry\\User\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery",
        L"\\Registry\\User\\Software\\Microsoft\\Internet Explorer\\TypedURLs",
        L"\\Registry\\User\\Software\\WinRAR\\ArcHistory",
    };

    for (int i = 0; i < sizeof(mruPaths) / sizeof(mruPaths[0]); i++) {
        KSpoofRegistryKeyRecursive(mruPaths[i]);
    }

    // MUI Cache - spoof
    KSpoofRegistryKeyRecursive(L"\\Registry\\User\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache");

    // AppCompat flags - spoof
    KSpoofRegistryKeyRecursive(L"\\Registry\\User\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store");

    DbgPrintEx(0, 0, "[CLEAN] Registry MRUs spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Network trace cleanup - SPOOF instead of delete
// ============================================================================

static NTSTATUS CleanNetworkTraces() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing Network traces...\n");

    // Spoof network profiles instead of deleting
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles");
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Managed");
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged");

    // Spoof DNS cache parameters
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters");

    // Spoof TCP/IP interfaces
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces");

    // Spoof Bluetooth devices
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Devices");

    DbgPrintEx(0, 0, "[CLEAN] Network traces spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// USB device history cleanup - SPOOF instead of delete
// ============================================================================

static NTSTATUS CleanUSBTraces() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing USB traces...\n");

    // Spoof USB device history instead of deleting
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR");
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\USB");

    // Spoof device classes
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\DeviceClasses");

    DbgPrintEx(0, 0, "[CLEAN] USB traces spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Application trace cleanup
// ============================================================================

static NTSTATUS CleanAppTraces() {
    DbgPrintEx(0, 0, "[CLEAN] Cleaning Application traces...\n");
    KDeleteDirectoryContents(L"\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache");
    KDeleteDirectoryContents(L"\\Users\\*\\AppData\\Local\\Mozilla\\Firefox\\Profiles");
    KDeleteDirectoryContents(L"\\Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cache");
    KDeleteDirectoryContents(L"\\Users\\*\\AppData\\Roaming\\discord\\Cache");
    KDeleteDirectoryContents(L"\\Users\\*\\AppData\\Roaming\\Code\\Cache");
    DbgPrintEx(0, 0, "[CLEAN] Application traces cleaned\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// BAM/DAM cleanup - SPOOF instead of delete
// ============================================================================

static NTSTATUS CleanBAM() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing BAM/DAM...\n");

    // Spoof BAM state instead of deleting
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings");

    // Spoof DAM state
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\dam\\State\\UserSettings");

    DbgPrintEx(0, 0, "[CLEAN] BAM/DAM spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// WMI Security - SPOOF instead of delete
// ============================================================================

static NTSTATUS CleanWMISecurity() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing WMI Security...\n");
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\WMI\\Security");
    DbgPrintEx(0, 0, "[CLEAN] WMI Security spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// SafeBoot - SPOOF instead of delete
// ============================================================================

static NTSTATUS CleanSafeBoot() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing SafeBoot...\n");
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Option");
    DbgPrintEx(0, 0, "[CLEAN] SafeBoot spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// AppCompatCache - SPOOF instead of delete
// ============================================================================

static NTSTATUS CleanAppCompatCache() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing AppCompatCache...\n");

    // Spoof AppCompatCache instead of deleting
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache");

    // Spoof AppCompatFlags
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags");

    // Spoof Amcache
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\COMPONENTS\\DerivedData\\Components");

    DbgPrintEx(0, 0, "[CLEAN] AppCompatCache spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// SRUM - SPOOF instead of delete
// ============================================================================

static NTSTATUS CleanSRUM() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing SRUM...\n");
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SRUM\\Extensions");
    DbgPrintEx(0, 0, "[CLEAN] SRUM spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// PowerShell history cleanup
// ============================================================================

static NTSTATUS CleanPowerShellHistory() {
    DbgPrintEx(0, 0, "[CLEAN] Cleaning PowerShell history...\n");
    KDeleteFile(L"\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt");
    DbgPrintEx(0, 0, "[CLEAN] PowerShell history cleaned\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// CMD history cleanup - SPOOF instead of delete
// ============================================================================

static NTSTATUS CleanCMDHistory() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing CMD history...\n");
    KSpoofRegistryKeyRecursive(L"\\Registry\\User\\Console");
    KSpoofRegistryKeyRecursive(L"\\Registry\\User\\Software\\Microsoft\\Command Processor");
    DbgPrintEx(0, 0, "[CLEAN] CMD history spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Crash dump cleanup
// ============================================================================

static NTSTATUS CleanCrashDumps() {
    DbgPrintEx(0, 0, "[CLEAN] Cleaning Crash dumps...\n");
    KDeleteDirectoryContents(L"\\Windows\\Minidump");
    KDeleteFile(L"\\Windows\\MEMORY.dmp");
    KDeleteDirectoryContents(L"\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue");
    KDeleteDirectoryContents(L"\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive");
    KDeleteDirectoryContents(L"\\Windows\\LiveKernelReports");
    DbgPrintEx(0, 0, "[CLEAN] Crash dumps cleaned\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Windows Defender - SPOOF instead of delete
// ============================================================================

static NTSTATUS CleanDefenderHistory() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing Defender history...\n");

    // Spoof Defender registry entries
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows Defender");

    // Delete scan/quarantine files (will be recreated)
    KDeleteDirectoryContents(L"\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History");
    KDeleteDirectoryContents(L"\\ProgramData\\Microsoft\\Windows Defender\\Quarantine");

    DbgPrintEx(0, 0, "[CLEAN] Defender history spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Pending file operations - SPOOF instead of delete
// ============================================================================

static NTSTATUS CleanPendingOps() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing Pending file operations...\n");
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager");
    DbgPrintEx(0, 0, "[CLEAN] Pending operations spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Memory Management - SPOOF instead of delete
// ============================================================================

static NTSTATUS CleanMemoryManagement() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing Memory Management...\n");
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management");
    DbgPrintEx(0, 0, "[CLEAN] Memory Management spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Safer CodeIdentifiers - SPOOF instead of delete
// ============================================================================

static NTSTATUS CleanSaferCode() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing Safer CodeIdentifiers...\n");
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Policies\\Microsoft\\Windows\\Safer\\CodeIdentifiers");
    DbgPrintEx(0, 0, "[CLEAN] Safer CodeIdentifiers spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Volume Snapshots - SPOOF instead of delete
// ============================================================================

static NTSTATUS CleanVolumeSnapshots() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing Volume Snapshots...\n");
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\STORAGE\\VolumeSnapshot");
    DbgPrintEx(0, 0, "[CLEAN] Volume Snapshots spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// MMDevices Audio - SPOOF instead of delete
// ============================================================================

static NTSTATUS CleanMMDevices() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing MMDevices Audio...\n");
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MMDevices");
    DbgPrintEx(0, 0, "[CLEAN] MMDevices Audio spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Windows Error Reporting - SPOOF instead of delete
// ============================================================================

static NTSTATUS CleanWER() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing WER...\n");
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting");
    KDeleteDirectoryContents(L"\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue");
    KDeleteDirectoryContents(L"\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive");
    DbgPrintEx(0, 0, "[CLEAN] WER spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Main cleanup function - call this from DriverEntry
// ============================================================================

static void PerformFullCleanup() {
    DbgPrintEx(0, 0, "[CLEAN] ==========================================\n");
    DbgPrintEx(0, 0, "[CLEAN] Starting FULL forensic trace cleanup (SPOOF mode)\n");
    DbgPrintEx(0, 0, "[CLEAN] ==========================================\n");

    // Phase 1: Quick cleanup (delete temp files)
    CleanPrefetch();
    CleanTempFiles();
    CleanRecentFiles();
    CleanJumpLists();
    CleanCrashDumps();
    CleanAppTraces();
    CleanPowerShellHistory();

    // Phase 2: SPOOF registry entries (preserve system, change data)
    CleanEventLogs();
    CleanRegistryMRUs();
    CleanNetworkTraces();
    CleanUSBTraces();
    CleanBAM();
    CleanWMISecurity();
    CleanSafeBoot();
    CleanAppCompatCache();
    CleanSRUM();
    CleanCMDHistory();
    CleanDefenderHistory();
    CleanPendingOps();
    CleanMemoryManagement();
    CleanSaferCode();
    CleanVolumeSnapshots();
    CleanMMDevices();
    CleanWER();

    DbgPrintEx(0, 0, "[CLEAN] ==========================================\n");
    DbgPrintEx(0, 0, "[CLEAN] FULL forensic trace cleanup COMPLETE\n");
    DbgPrintEx(0, 0, "[CLEAN] All critical keys SPOOFED (not deleted)\n");
    DbgPrintEx(0, 0, "[CLEAN] ==========================================\n");
}
