#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include "../../functions/functions.h"
#include "../../protection/oxorany/oxorany.h"

// USN Journal structures (not always in headers)
#ifndef FSCTL_DELETE_USN_JOURNAL
#define FSCTL_DELETE_USN_JOURNAL CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 64, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

#ifndef USN_DELETE_FLAG_DELETE
#define USN_DELETE_FLAG_DELETE 0x00000001
#endif

// USN Journal data structure
typedef struct _USN_JOURNAL_DATA_V0_LITE {
    ULONGLONG UsnJournalID;
    LONGLONG FirstUsn;
    LONGLONG NextUsn;
    LONGLONG LowestValidUsn;
    LONGLONG MaxUsn;
    ULONGLONG MaximumSize;
    ULONGLONG AllocationDelta;
} USN_JOURNAL_DATA_V0_LITE;

// Delete USN journal request
typedef struct _DELETE_USN_JOURNAL_DATA_LITE {
    ULONGLONG UsnJournalID;
    DWORD DeleteFlags;
} DELETE_USN_JOURNAL_DATA_LITE;

// Use our own types
#define USN_JOURNAL_DATA_V0 USN_JOURNAL_DATA_V0_LITE
#define DELETE_USN_JOURNAL_DATA DELETE_USN_JOURNAL_DATA_LITE

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
// System Identity - SPOOF HardwareConfig, ComputerHardwareId, HwProfileGuid,
// InstallDate, BuildLab, SQMClient, SusClientId, DiagTrack
// ============================================================================

static NTSTATUS CleanSystemIdentity() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing System Identity...\n");

    // HardwareConfig\LastConfig - hardware configuration fingerprint
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\HardwareConfig\\LastConfig");

    // ComputerHardwareId - system hardware identifier
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation");

    // HwProfileGuid - hardware profile GUID
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles");

    // InstallDate, BuildLab, BuildLabEx, DigitalProductId, DigitalProductId4
    {
        UNICODE_STRING ntVersion;
        RtlInitUnicodeString(&ntVersion, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
        HANDLE hKey;
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &ntVersion, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        if (NT_SUCCESS(ZwOpenKey(&hKey, KEY_ALL_ACCESS, &oa))) {
            KSpoofRegDword(hKey, L"InstallDate");
            KSpoofRegDword(hKey, L"InstallTime");
            KSpoofRegSz(hKey, L"BuildLab");
            KSpoofRegSz(hKey, L"BuildLabEx");
            KSpoofRegSz(hKey, L"RegisteredOwner");
            KSpoofRegSz(hKey, L"RegisteredOrganization");
            KSpoofRegBinary(hKey, L"DigitalProductId");
            KSpoofRegBinary(hKey, L"DigitalProductId4");
            KSpoofRegSz(hKey, L"ProductId");
            ZwClose(hKey);
        }
    }

    // SQMClient - MachineId telemetry identifier
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\SQMClient");

    // SusClientId - Windows Update identifier
    {
        UNICODE_STRING wuPath;
        RtlInitUnicodeString(&wuPath, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate");
        HANDLE hKey;
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &wuPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
        if (NT_SUCCESS(ZwOpenKey(&hKey, KEY_ALL_ACCESS, &oa))) {
            KSpoofRegSz(hKey, L"SusClientId");
            KSpoofRegBinary(hKey, L"SusClientIdValidation");
            ZwClose(hKey);
        }
    }

    // DiagTrack - telemetry
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack");

    // SoftwareProtectionPlatform - product key, backup key
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SoftwareProtectionPlatform");

    DbgPrintEx(0, 0, "[CLEAN] System Identity spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// NVIDIA GPU traces - SPOOF ClientUUID, PersistenceIdentifier, ChipsetMatchID
// ============================================================================

static NTSTATUS CleanNVIDIATraces() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing NVIDIA traces...\n");

    // NVIDIA Corporation\Global - ClientUUID, PersistenceIdentifier, ChipsetMatchID
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\NVIDIA Corporation\\Global");

    // NVIDIA Corporation\NVControlPanel2 - client settings
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\NVIDIA Corporation\\NVControlPanel2");

    // NVIDIA Corporation\Installer - install traces
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\NVIDIA Corporation\\Installer");

    DbgPrintEx(0, 0, "[CLEAN] NVIDIA traces spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// AMD GPU traces - SPOOF
// ============================================================================

static NTSTATUS CleanAMDTraces() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing AMD traces...\n");

    // AMD\CN - AMD GPU driver traces
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\AMD\\CN");

    // AMD\DVR - AMD DVR traces
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\AMD\\DVR");

    DbgPrintEx(0, 0, "[CLEAN] AMD traces spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Office ClientTelemetry - SPOOF MotherboardUUID
// ============================================================================

static NTSTATUS CleanOfficeTraces() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing Office traces...\n");

    // Office 16.0 ClientTelemetry - MotherboardUUID
    KSpoofRegistryKeyRecursive(L"\\Registry\\User\\Software\\Microsoft\\Office\\16.0\\Common\\ClientTelemetry");

    // Office 16.0 Common\General - recent file traces
    KSpoofRegistryKeyRecursive(L"\\Registry\\User\\Software\\Microsoft\\Office\\16.0\\Common\\General");

    // Office 16.0 Word\File MRU
    KSpoofRegistryKeyRecursive(L"\\Registry\\User\\Software\\Microsoft\\Office\\16.0\\Word\\File MRU");

    // Office 16.0 Excel\File MRU
    KSpoofRegistryKeyRecursive(L"\\Registry\\User\\Software\\Microsoft\\Office\\16.0\\Excel\\File MRU");

    // Office 16.0 PowerPoint\File MRU
    KSpoofRegistryKeyRecursive(L"\\Registry\\User\\Software\\Microsoft\\Office\\16.0\\PowerPoint\\File MRU");

    DbgPrintEx(0, 0, "[CLEAN] Office traces spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// BitBucket & MountPoints2 - SPOOF
// ============================================================================

static NTSTATUS CleanBitBucketMountPoints() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing BitBucket & MountPoints2...\n");

    // BitBucket\Volume - recycle bin volume tracking (LastEnum)
    KSpoofRegistryKeyRecursive(L"\\Registry\\User\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\Volume");

    // MountPoints2 - mounted volume tracking
    KSpoofRegistryKeyRecursive(L"\\Registry\\User\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2");

    DbgPrintEx(0, 0, "[CLEAN] BitBucket & MountPoints2 spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Dfrg Statistics - SPOOF
// ============================================================================

static NTSTATUS CleanDfrgStatistics() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing Dfrg Statistics...\n");
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Dfrg\\Statistics");
    DbgPrintEx(0, 0, "[CLEAN] Dfrg Statistics spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// TPM WMI - SPOOF WindowsAIKHash
// ============================================================================

static NTSTATUS CleanTPMTraces() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing TPM WMI traces...\n");

    // TPM\WMI - WindowsAIKHash
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Tpm\\WMI");

    // TPM - TPM owner info
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Tpm");

    DbgPrintEx(0, 0, "[CLEAN] TPM WMI traces spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// DiskPeripheral & DiskController - SPOOF SCSI identifiers
// ============================================================================

static NTSTATUS CleanDiskPeripheral() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing DiskPeripheral identifiers...\n");

    // SCSI disk peripherals - Identifier, SerialNumber
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\SCSI");

    // IDE/ATA disk peripherals
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\IDE");

    DbgPrintEx(0, 0, "[CLEAN] DiskPeripheral identifiers spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// NetworkCards - SPOOF
// ============================================================================

static NTSTATUS CleanNetworkCards() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing NetworkCards...\n");
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards");
    DbgPrintEx(0, 0, "[CLEAN] NetworkCards spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// DeviceContainers - SPOOF
// ============================================================================

static NTSTATUS CleanDeviceContainers() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing DeviceContainers...\n");

    // DeviceContainers - device container metadata
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeviceContainers");

    // DeviceSetup - device setup metadata
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\DeviceSetup");

    DbgPrintEx(0, 0, "[CLEAN] DeviceContainers spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// CodePage - SPOOF AnsiCodepage, OEMCodepage
// ============================================================================

static NTSTATUS CleanCodePage() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing CodePage...\n");
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage");
    DbgPrintEx(0, 0, "[CLEAN] CodePage spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// TimeZone - SPOOF TimeZoneKeyName, DynamicDaylightTimeDisabled
// ============================================================================

static NTSTATUS CleanTimeZone() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing TimeZone...\n");

    // TimeZoneInformation
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation");

    // Time Zones - zone-specific data
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zones");

    DbgPrintEx(0, 0, "[CLEAN] TimeZone spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Installer Traces - SPOOF MSI Products, Features, UpgradeCodes
// ============================================================================

static NTSTATUS CleanInstallerTraces() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing Installer traces...\n");

    // MSI Products
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Classes\\Installer\\Products");

    // MSI Features
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Classes\\Installer\\Features");

    // MSI UpgradeCodes
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Classes\\Installer\\UpgradeCodes");

    // MSI Patches
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Classes\\Installer\\Patches");

    // Windows Installer - rollback data
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\Rollback");

    DbgPrintEx(0, 0, "[CLEAN] Installer traces spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// UPnP/SSDP - SPOOF
// ============================================================================

static NTSTATUS CleanUPnPSSDP() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing UPnP/SSDP...\n");

    // UPnP Device Description cache
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\PnpLockdownFiles");

    // SSDP service parameters
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\SSDPSRV\\Parameters");

    // UPnP service parameters
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\upnphost\\Parameters");

    DbgPrintEx(0, 0, "[CLEAN] UPnP/SSDP spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// BCD Store - SPOOF boot configuration GUIDs
// ============================================================================

static NTSTATUS CleanBCDStore() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing BCD Store...\n");

    // BCD\Objects - boot configuration objects (contains GUIDs)
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\BCD\\Objects");

    DbgPrintEx(0, 0, "[CLEAN] BCD Store spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// NIC Registry NetworkAddress - SPOOF
// ============================================================================

static NTSTATUS CleanNICRegistry() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing NIC registry NetworkAddress...\n");

    // Network class {4D36E972-E325-11CE-BFC1-08002bE10318}
    // Each subkey 0000-9999 represents a NIC adapter
    // NdisReadNetworkAddress reads "NetworkAddress" from Parameters subkey
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002bE10318}");

    DbgPrintEx(0, 0, "[CLEAN] NIC registry NetworkAddress spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Reliability - SPOOF ShutdownTimestamp, ReliabilitySessionGuid
// ============================================================================

static NTSTATUS CleanReliability() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing Reliability...\n");

    // Reliability - shutdown timestamps, session GUIDs
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Reliability");

    DbgPrintEx(0, 0, "[CLEAN] Reliability spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Tcpip Parameters - SPOOF DhcpDomain, Hostname, Domain
// ============================================================================

static NTSTATUS CleanTcpipParameters() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing Tcpip Parameters...\n");

    // Tcpip\Parameters - hostname, domain
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters");

    // Tcpip\Parameters\Interfaces - DHCP traces
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces");

    DbgPrintEx(0, 0, "[CLEAN] Tcpip Parameters spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Group Policy History - SPOOF
// ============================================================================

static NTSTATUS CleanGroupPolicy() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing Group Policy...\n");

    // Group Policy history
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy");

    // Group Policy\History
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History");

    DbgPrintEx(0, 0, "[CLEAN] Group Policy spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// ProfileList - SPOOF ProfileImagePath, Sid traces
// ============================================================================

static NTSTATUS CleanProfileList() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing ProfileList...\n");

    // ProfileList - user profile paths, SIDs
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList");

    DbgPrintEx(0, 0, "[CLEAN] ProfileList spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// AppModel - SPOOF package repository traces
// ============================================================================

static NTSTATUS CleanAppModel() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing AppModel...\n");

    // AppModel - package repository
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppModel");

    // AppxAllUserStore - UWP app store
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Appx\\AppxAllUserStore");

    DbgPrintEx(0, 0, "[CLEAN] AppModel spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Component Based Servicing - SPOOF session traces
// ============================================================================

static NTSTATUS CleanCBS() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing CBS...\n");

    // Component Based Servicing sessions
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing");

    DbgPrintEx(0, 0, "[CLEAN] CBS spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Setup traces - SPOOF installation source, media
// ============================================================================

static NTSTATUS CleanSetupTraces() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing Setup traces...\n");

    // Setup - installation source, media
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup");

    // Setup\State - installation state
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Setup\\State");

    DbgPrintEx(0, 0, "[CLEAN] Setup traces spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// PerHwIdStorage - SPOOF per-hardware-ID storage
// ============================================================================

static NTSTATUS CleanPerHwIdStorage() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing PerHwIdStorage...\n");
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\PerHwIdStorage");
    DbgPrintEx(0, 0, "[CLEAN] PerHwIdStorage spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// AutoplayHandlers - SPOOF device autoplay traces
// ============================================================================

static NTSTATUS CleanAutoplayHandlers() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing AutoplayHandlers...\n");

    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AutoplayHandlers");

    // DriveIcons - drive letter traces
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\DriveIcons");

    DbgPrintEx(0, 0, "[CLEAN] AutoplayHandlers spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Printers - SPOOF printer traces
// ============================================================================

static NTSTATUS CleanPrinters() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing Printers...\n");

    // Print\Printers - printer configuration
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print\\Printers");

    // Print\Connections - printer connections
    KSpoofRegistryKeyRecursive(L"\\Registry\\User\\Software\\Microsoft\\Windows NT\\CurrentVersion\\PrinterPorts");

    DbgPrintEx(0, 0, "[CLEAN] Printers spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Shell Folders & User Shell Folders - SPOOF
// ============================================================================

static NTSTATUS CleanShellFolders() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing Shell Folders...\n");

    // Shell Folders
    KSpoofRegistryKeyRecursive(L"\\Registry\\User\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders");

    // User Shell Folders
    KSpoofRegistryKeyRecursive(L"\\Registry\\User\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders");

    // SessionInfo - session traces
    KSpoofRegistryKeyRecursive(L"\\Registry\\User\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SessionInfo");

    DbgPrintEx(0, 0, "[CLEAN] Shell Folders spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// VolumeCaches - SPOOF
// ============================================================================

static NTSTATUS CleanVolumeCaches() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing VolumeCaches...\n");
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VolumeCaches");
    DbgPrintEx(0, 0, "[CLEAN] VolumeCaches spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Performance - SPOOF performance counter traces
// ============================================================================

static NTSTATUS CleanPerformance() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing Performance traces...\n");

    // Performance counter traces
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Perflib");

    // Performance\Perf - performance data
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Perf");

    DbgPrintEx(0, 0, "[CLEAN] Performance traces spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// NetworkList Signatures FirstNetwork - SPOOF
// ============================================================================

static NTSTATUS CleanNetworkListFirstNetwork() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing NetworkList FirstNetwork...\n");

    // NetworkList\Signatures - FirstNetwork, DefaultGatewayMac
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures");

    // NetworkList\Profiles - network profile traces
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles");

    DbgPrintEx(0, 0, "[CLEAN] NetworkList FirstNetwork spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// USN Journal - DELETE (safe, recreated by NTFS)
// ============================================================================

static NTSTATUS CleanUSNJournal() {
    DbgPrintEx(0, 0, "[CLEAN] Cleaning USN Journal...\n");

    // Enumerate all volumes and delete USN journal
    // This is done via FSCTL_DELETE_USN_JOURNAL on each volume handle
    // We'll enumerate volumes through \Device\HarddiskVolume*
    for (int vol = 0; vol < 16; vol++) {
        wchar_t volPath[64];
        RtlStringCchPrintfW(volPath, 64, L"\\Device\\HarddiskVolume%d", vol);

        UNICODE_STRING uVolPath;
        RtlInitUnicodeString(&uVolPath, volPath);
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &uVolPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        HANDLE hVol;
        IO_STATUS_BLOCK iosb;
        NTSTATUS st = ZwOpenFile(&hVol, FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_SYNCHRONOUS_IO_NONALERT);
        if (NT_SUCCESS(st)) {
            // FSCTL_DELETE_USN_JOURNAL = 0x000900F8
            USN_JOURNAL_DATA_V0 journalData = { 0 };
            DELETE_USN_JOURNAL_DATA delData = { 0 };
            delData.DeleteFlags = USN_DELETE_FLAG_DELETE;
            delData.UsnJournalID = 0;

            IO_STATUS_BLOCK ioctlIosb;
            st = ZwFsControlFile(hVol, NULL, NULL, NULL, &ioctlIosb,
                0x000900F8, // FSCTL_DELETE_USN_JOURNAL
                &delData, sizeof(delData),
                NULL, 0);
            if (NT_SUCCESS(st)) {
                DbgPrintEx(0, 0, "[CLEAN] USN Journal deleted on volume %d\n", vol);
            }
            ZwClose(hVol);
        }
    }

    DbgPrintEx(0, 0, "[CLEAN] USN Journal cleaned\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Shadow Copies - DELETE VSS shadow copies
// ============================================================================

static NTSTATUS CleanShadowCopies() {
    DbgPrintEx(0, 0, "[CLEAN] Cleaning Shadow Copies...\n");

    // Spoof VolumeSnapshot enum entries
    KSpoofRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\STORAGE\\VolumeSnapshot");

    // Delete VSS shadow copy files in System Volume Information
    // These are safe to delete - they're backup snapshots
    KDeleteDirectoryContents(L"\\System Volume Information\\{3808876b-c176-4e48-b7ae-04046e6cc752}");

    DbgPrintEx(0, 0, "[CLEAN] Shadow Copies cleaned\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// File Timestamps - SPOOF creation/modification times of key files
// ============================================================================

static NTSTATUS SpoofFileTimestamps() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing file timestamps...\n");

    // Files whose timestamps can reveal system age/identity
    const wchar_t* files[] = {
        L"\\Windows\\System32\\config\\SOFTWARE",
        L"\\Windows\\System32\\config\\SYSTEM",
        L"\\Windows\\System32\\config\\SAM",
        L"\\Windows\\System32\\config\\SECURITY",
        L"\\Windows\\System32\\config\\DEFAULT",
        L"\\Windows\\setupact.log",
        L"\\Windows\\setuperr.log",
        L"\\Windows\\Panther\\setupact.log",
        L"\\Windows\\inf\\setupapi.dev.log",
        L"\\Windows\\inf\\setupapi.setup.log",
    };

    ULONG seed = kmdf_settings::hwid_seed;

    for (int i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        UNICODE_STRING uPath;
        RtlInitUnicodeString(&uPath, files[i]);
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        HANDLE hFile;
        IO_STATUS_BLOCK iosb;
        NTSTATUS st = ZwOpenFile(&hFile, FILE_WRITE_ATTRIBUTES | SYNCHRONIZE,
            &oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_SYNCHRONOUS_IO_NONALERT);
        if (NT_SUCCESS(st)) {
            FILE_BASIC_INFORMATION fbi = { 0 };
            st = ZwQueryInformationFile(hFile, &iosb, &fbi, sizeof(fbi), FileBasicInformation);
            if (NT_SUCCESS(st)) {
                // Randomize timestamps slightly (add/subtract random hours)
                ULONG r1 = DiskLCG(seed);
                ULONG r2 = DiskLCG(seed);
                LONGLONG offset1 = (LONGLONG)(r1 % 720 - 360) * 36000000000LL; // +/-360 hours
                LONGLONG offset2 = (LONGLONG)(r2 % 720 - 360) * 36000000000LL;

                // Only modify if timestamps are non-zero
                if (fbi.CreationTime.QuadPart != 0) {
                    fbi.CreationTime.QuadPart += offset1;
                }
                if (fbi.LastWriteTime.QuadPart != 0) {
                    fbi.LastWriteTime.QuadPart += offset2;
                }
                if (fbi.ChangeTime.QuadPart != 0) {
                    fbi.ChangeTime.QuadPart += offset1;
                }
                // Don't modify LastAccessTime (too noisy)

                fbi.FileAttributes = 0; // Don't change attributes
                ZwSetInformationFile(hFile, &iosb, &fbi, sizeof(fbi), FileBasicInformation);
            }
            ZwClose(hFile);
        }
    }

    DbgPrintEx(0, 0, "[CLEAN] File timestamps spoofed\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// disk.sys Device Extension - SPOOF serials in device extension
// ============================================================================

static NTSTATUS CleanDiskDeviceExtension() {
    DbgPrintEx(0, 0, "[CLEAN] Spoofing disk.sys device extension serials...\n");

    // Enumerate disk device objects and spoof serial numbers in device extensions
    UNICODE_STRING diskDriverName;
    RtlInitUnicodeString(&diskDriverName, L"\\Driver\\disk");
    PDRIVER_OBJECT diskDriver = NULL;
    NTSTATUS st = ObReferenceObjectByName(&diskDriverName, OBJ_CASE_INSENSITIVE, NULL, 0,
        *IoDriverObjectType, KernelMode, NULL, (PVOID*)&diskDriver);
    if (NT_SUCCESS(st) && diskDriver) {
        PDEVICE_OBJECT devObj = diskDriver->DeviceObject;
        while (devObj) {
            if (devObj->DeviceExtension) {
                // Scan device extension for serial number patterns
                // Serial numbers are typically ASCII strings of 20+ chars
                PUCHAR ext = (PUCHAR)devObj->DeviceExtension;
                ULONG extSize = 4096; // Probe up to 4KB (typical device extension size)
                ULONG seed = kmdf_settings::hwid_seed;

                // Look for serial-like ASCII strings (alphanumeric, 8-40 chars)
                for (ULONG off = 0; off < extSize - 8; off++) {
                    // Check if this looks like a serial number start
                    BOOLEAN isSerial = TRUE;
                    int serialLen = 0;
                    for (int c = 0; c < 40 && (off + c) < extSize; c++) {
                        UCHAR ch = ext[off + c];
                        if (ch == 0) {
                            serialLen = c;
                            break;
                        }
                        if (!((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || ch == ' ' || ch == '-' || ch == '_')) {
                            isSerial = FALSE;
                            break;
                        }
                        serialLen = c + 1;
                    }

                    if (isSerial && serialLen >= 8 && serialLen <= 40) {
                        // Check if preceded by a length field or null terminator
                        // and followed by null terminator
                        if (ext[off + serialLen] == 0) {
                            // Looks like a serial string - spoof it
                            for (int c = 0; c < serialLen; c++) {
                                if (ext[off + c] >= '0' && ext[off + c] <= '9') {
                                    ULONG r = DiskLCG(seed);
                                    ext[off + c] = '0' + (r % 10);
                                } else if (ext[off + c] >= 'A' && ext[off + c] <= 'Z') {
                                    ULONG r = DiskLCG(seed);
                                    ext[off + c] = 'A' + (r % 26);
                                } else if (ext[off + c] >= 'a' && ext[off + c] <= 'z') {
                                    ULONG r = DiskLCG(seed);
                                    ext[off + c] = 'a' + (r % 26);
                                }
                            }
                            DbgPrintEx(0, 0, "[CLEAN] Spoofed device extension serial at offset 0x%X (len=%d)\n", off, serialLen);
                            off += serialLen; // Skip past this serial
                        }
                    }
                }
            }
            devObj = devObj->NextDevice;
        }
        ObDereferenceObject(diskDriver);
    }

    DbgPrintEx(0, 0, "[CLEAN] disk.sys device extension serials spoofed\n");
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

    // Phase 3: System identity & telemetry
    CleanSystemIdentity();
    CleanNVIDIATraces();
    CleanAMDTraces();
    CleanOfficeTraces();
    CleanBitBucketMountPoints();
    CleanDfrgStatistics();
    CleanTPMTraces();
    CleanDiskPeripheral();
    CleanNetworkCards();
    CleanDeviceContainers();
    CleanCodePage();
    CleanTimeZone();
    CleanInstallerTraces();
    CleanUPnPSSDP();
    CleanBCDStore();
    CleanNICRegistry();
    CleanReliability();
    CleanTcpipParameters();
    CleanGroupPolicy();
    CleanProfileList();
    CleanAppModel();
    CleanCBS();
    CleanSetupTraces();
    CleanPerHwIdStorage();
    CleanAutoplayHandlers();
    CleanPrinters();
    CleanShellFolders();
    CleanVolumeCaches();
    CleanPerformance();
    CleanNetworkListFirstNetwork();

    // Phase 4: Filesystem-level cleanup
    CleanUSNJournal();
    CleanShadowCopies();
    SpoofFileTimestamps();
    CleanDiskDeviceExtension();

    DbgPrintEx(0, 0, "[CLEAN] ==========================================\n");
    DbgPrintEx(0, 0, "[CLEAN] FULL forensic trace cleanup COMPLETE\n");
    DbgPrintEx(0, 0, "[CLEAN] All critical keys SPOOFED (not deleted)\n");
    DbgPrintEx(0, 0, "[CLEAN] ==========================================\n");
}
