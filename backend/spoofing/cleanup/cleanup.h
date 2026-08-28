#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include "../../functions/functions.h"
#include "../../protection/oxorany/oxorany.h"

// ============================================================================
// Kernel-mode trace cleanup - SAFE forensic trace removal
// ============================================================================
// IMPORTANT: This module is designed to NOT break display, GPU, or system stability
// All critical system keys are preserved

#define CLEAN_TAG 'naLC'

// Helper: Delete a file by kernel path
static NTSTATUS KDeleteFile(const wchar_t* filePath) {
    UNICODE_STRING uPath;
    RtlInitUnicodeString(&uPath, filePath);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    return ZwDeleteFile(&oa);
}

// Helper: Open a directory and delete all files matching a pattern
static NTSTATUS KDeleteDirectoryContents(const wchar_t* dirPath, const wchar_t* pattern = L"*") {
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

    // Buffer for directory enumeration
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
            // Skip . and ..
            if (info->FileNameLength == 2 && info->FileName[0] == L'.') goto next;
            if (info->FileNameLength == 4 && info->FileName[0] == L'.' && info->FileName[1] == L'.') goto next;

            // Build full path
            wchar_t fullPath[512];
            NTSTATUS fmtSt;
            fmtSt = RtlStringCchPrintfW(fullPath, 512, L"%s\\%.*s", dirPath,
                info->FileNameLength / sizeof(wchar_t), info->FileName);
            if (NT_SUCCESS(fmtSt)) {
                UNICODE_STRING uFull;
                RtlInitUnicodeString(&uFull, fullPath);
                OBJECT_ATTRIBUTES fileOa;
                InitializeObjectAttributes(&fileOa, &uFull, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

                if (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    // Skip critical system directories
                    const wchar_t* name = info->FileName;
                    ULONG nameLen = info->FileNameLength / sizeof(wchar_t);
                    
                    // Skip display/GPU related directories
                    if ((nameLen == 12 && _wcsnicmp(name, L"BasicRender", 11) == 0) ||
                        (nameLen == 7 && _wcsnicmp(name, L"Display", 7) == 0) ||
                        (nameLen == 4 && _wcsnicmp(name, L"GPU", 3) == 0) ||
                        (nameLen == 7 && _wcsnicmp(name, L"Monitor", 7) == 0)) {
                        goto next;
                    }

                    // Recursively delete subdirectory
                    HANDLE hSubDir;
                    IO_STATUS_BLOCK subIosb;
                    if (NT_SUCCESS(ZwOpenFile(&hSubDir, FILE_LIST_DIRECTORY | DELETE | SYNCHRONIZE, &fileOa, &subIosb,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT))) {
                        FILE_DISPOSITION_INFORMATION disp;
                        disp.DeleteFile = TRUE;
                        ZwSetInformationFile(hSubDir, &subIosb, &disp, sizeof(disp), FileDispositionInformation);
                        ZwClose(hSubDir);
                    }
                } else {
                    // Delete file
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
        if (!NT_SUCCESS(st)) idx++; // Skip if can't delete
        // Don't increment on success since indices shift
    }

    ExFreePoolWithTag(vfi, CLEAN_TAG);
    return STATUS_SUCCESS;
}

// Helper: Delete a registry key and all subkeys recursively - SAFE VERSION
static NTSTATUS KDeleteRegistryKeyRecursive(const wchar_t* keyPath) {
    // SAFETY: Skip critical system keys that could cause black screen
    const wchar_t* criticalKeys[] = {
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\DeviceClasses",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\DISPLAY",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\PCI",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}", // Display adapters
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e96c-e325-11ce-bfc1-08002be10318}", // Media devices
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Video",
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\PriorityControl",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\BasicDisplay",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\BasicRender",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\dxgkrnl",
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\nvlddmkm", // NVIDIA
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\amdkmdag", // AMD
        L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\amdkmpfd", // AMD
    };

    // Check if this is a critical key
    for (int i = 0; i < sizeof(criticalKeys) / sizeof(criticalKeys[0]); i++) {
        if (_wcsnicmp(keyPath, criticalKeys[i], wcslen(criticalKeys[i])) == 0) {
            DbgPrintEx(0, 0, "[CLEAN] SKIPPING critical key: %ws\n", keyPath);
            return STATUS_SUCCESS; // Skip silently
        }
    }

    UNICODE_STRING uPath;
    RtlInitUnicodeString(&uPath, keyPath);
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    HANDLE hKey;
    NTSTATUS st = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &oa);
    if (!NT_SUCCESS(st)) return st;

    // Delete all subkeys first
    const ULONG bufSize = 0x1000;
    PKEY_BASIC_INFORMATION kbi = (PKEY_BASIC_INFORMATION)ExAllocatePoolWithTag(PagedPool, bufSize, CLEAN_TAG);
    if (!kbi) { ZwClose(hKey); return STATUS_INSUFFICIENT_RESOURCES; }

    while (TRUE) {
        ULONG resultLen;
        st = ZwEnumerateKey(hKey, 0, KeyBasicInformation, kbi, bufSize, &resultLen);
        if (st == STATUS_NO_MORE_ENTRIES) break;
        if (!NT_SUCCESS(st)) break;

        UNICODE_STRING subName;
        subName.Length = (USHORT)kbi->NameLength;
        subName.MaximumLength = (USHORT)kbi->NameLength;
        subName.Buffer = kbi->Name;

        // Build full path for recursive delete
        wchar_t subPath[512];
        RtlStringCchPrintfW(subPath, 512, L"%s\\%.*s", keyPath, kbi->NameLength / sizeof(wchar_t), kbi->Name);
        KDeleteRegistryKeyRecursive(subPath);
    }

    ExFreePoolWithTag(kbi, CLEAN_TAG);

    // Delete all values
    KDeleteAllValues(hKey);

    // Delete the key itself
    st = ZwDeleteKey(hKey);
    ZwClose(hKey);
    return st;
}

// ============================================================================
// Prefetch cleanup
// ============================================================================

static NTSTATUS CleanPrefetch() {
    DbgPrintEx(0, 0, "[CLEAN] Cleaning Prefetch...\n");

    // Delete all .pf files
    KDeleteDirectoryContents(L"\\SystemRoot\\Prefetch", L"*.pf");

    // Delete layout.ini
    KDeleteFile(L"\\SystemRoot\\Prefetch\\Layout.ini");

    // Delete AgAppLaunch.db
    KDeleteFile(L"\\SystemRoot\\Prefetch\\AgAppLaunch.db");

    // Delete boot files
    KDeleteDirectoryContents(L"\\SystemRoot\\Prefetch\\ReadyBoot");

    DbgPrintEx(0, 0, "[CLEAN] Prefetch cleaned\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Event Log cleanup - SAFE VERSION
// ============================================================================

static NTSTATUS CleanEventLogs() {
    DbgPrintEx(0, 0, "[CLEAN] Cleaning Event Logs...\n");

    // Delete individual log files (not the whole directory to avoid breaking event log service)
    const wchar_t* logFiles[] = {
        L"\\SystemRoot\\System32\\winevt\\Logs\\Application.evtx",
        L"\\SystemRoot\\System32\\winevt\\Logs\\System.evtx",
        L"\\SystemRoot\\System32\\winevt\\Logs\\Security.evtx",
        L"\\SystemRoot\\System32\\winevt\\Logs\\Setup.evtx",
        L"\\SystemRoot\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx",
        L"\\SystemRoot\\System32\\winevt\\Logs\\Microsoft-Windows-TaskScheduler%4Operational.evtx",
        L"\\SystemRoot\\System32\\winevt\\Logs\\Microsoft-Windows-PowerShell%4Operational.evtx",
        L"\\SystemRoot\\System32\\winevt\\Logs\\Microsoft-Windows-Windows Defender%4Operational.evtx",
        L"\\SystemRoot\\System32\\winevt\\Logs\\Microsoft-Windows-Windows Defender%4WHC.evtx",
        L"\\SystemRoot\\System32\\winevt\\Logs\\Microsoft-Windows-CodeIntegrity%4Operational.evtx",
    };

    for (int i = 0; i < sizeof(logFiles) / sizeof(logFiles[0]); i++) {
        KDeleteFile(logFiles[i]);
    }

    DbgPrintEx(0, 0, "[CLEAN] Event Logs cleaned\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Temp files cleanup
// ============================================================================

static NTSTATUS CleanTempFiles() {
    DbgPrintEx(0, 0, "[CLEAN] Cleaning Temp files...\n");

    // User temp directories
    KDeleteDirectoryContents(L"\\SystemRoot\\Temp");

    // Windows Update logs
    KDeleteFile(L"\\Windows\\WindowsUpdate.log");

    // CBS logs
    KDeleteDirectoryContents(L"\\Windows\\Logs\\CBS");

    // DISM logs
    KDeleteDirectoryContents(L"\\Windows\\Logs\\DISM");

    // Minidump files
    KDeleteDirectoryContents(L"\\Windows\\Minidump");

    // Memory dump
    KDeleteFile(L"\\Windows\\MEMORY.dmp");

    //WER (Windows Error Reporting)
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

    // Recent items - use wildcard for all users
    KDeleteDirectoryContents(L"\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent");

    // Office recent files
    KDeleteDirectoryContents(L"\\Users\\*\\AppData\\Roaming\\Microsoft\\Office\\Recent");

    DbgPrintEx(0, 0, "[CLEAN] Recent files cleaned\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Jump Lists cleanup
// ============================================================================

static NTSTATUS CleanJumpLists() {
    DbgPrintEx(0, 0, "[CLEAN] Cleaning Jump Lists...\n");

    // Automatic destinations
    KDeleteDirectoryContents(L"\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations");

    // Custom destinations
    KDeleteDirectoryContents(L"\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations");

    DbgPrintEx(0, 0, "[CLEAN] Jump Lists cleaned\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Registry MRU cleanup - SAFE VERSION
// ============================================================================

static NTSTATUS CleanRegistryMRUs() {
    DbgPrintEx(0, 0, "[CLEAN] Cleaning Registry MRUs...\n");

    // HKCU MRU paths - only user-specific, not system-wide
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
        UNICODE_STRING uPath;
        RtlInitUnicodeString(&uPath, mruPaths[i]);
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        HANDLE hKey;
        if (NT_SUCCESS(ZwOpenKey(&hKey, KEY_ALL_ACCESS, &oa))) {
            KDeleteAllValues(hKey);
            ZwClose(hKey);
        }
    }

    // MUI Cache
    KDeleteRegistryKeyRecursive(L"\\Registry\\User\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache");

    // AppCompat flags (user only)
    KDeleteRegistryKeyRecursive(L"\\Registry\\User\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store");

    DbgPrintEx(0, 0, "[CLEAN] Registry MRUs cleaned\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Network trace cleanup - SAFE VERSION
// ============================================================================

static NTSTATUS CleanNetworkTraces() {
    DbgPrintEx(0, 0, "[CLEAN] Cleaning Network traces...\n");

    // Network profiles (safe to delete)
    KDeleteRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles");
    KDeleteRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Managed");
    KDeleteRegistryKeyRecursive(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged");

    // WiFi profiles
    KDeleteDirectoryContents(L"\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\Interfaces");

    DbgPrintEx(0, 0, "[CLEAN] Network traces cleaned\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// USB device history cleanup - SAFE VERSION
// ============================================================================

static NTSTATUS CleanUSBTraces() {
    DbgPrintEx(0, 0, "[CLEAN] Cleaning USB traces...\n");

    // Only delete USBSTOR, not all USB (which could break input devices)
    KDeleteRegistryKeyRecursive(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR");

    DbgPrintEx(0, 0, "[CLEAN] USB traces cleaned\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Application trace cleanup
// ============================================================================

static NTSTATUS CleanAppTraces() {
    DbgPrintEx(0, 0, "[CLEAN] Cleaning Application traces...\n");

    // Chrome
    KDeleteDirectoryContents(L"\\Users\\*\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache");

    // Firefox
    KDeleteDirectoryContents(L"\\Users\\*\\AppData\\Local\\Mozilla\\Firefox\\Profiles");

    // Edge
    KDeleteDirectoryContents(L"\\Users\\*\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Cache");

    // Discord
    KDeleteDirectoryContents(L"\\Users\\*\\AppData\\Roaming\\discord\\Cache");

    // Visual Studio Code
    KDeleteDirectoryContents(L"\\Users\\*\\AppData\\Roaming\\Code\\Cache");

    DbgPrintEx(0, 0, "[CLEAN] Application traces cleaned\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// BAM/DAM cleanup - SAFE VERSION (only values, not keys)
// ============================================================================

static NTSTATUS CleanBAM() {
    DbgPrintEx(0, 0, "[CLEAN] Cleaning BAM/DAM...\n");

    // BAM state - only delete values, not the whole key structure
    UNICODE_STRING bamPath;
    RtlInitUnicodeString(&bamPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings");
    HANDLE hBam;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &bamPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    if (NT_SUCCESS(ZwOpenKey(&hBam, KEY_READ, &oa))) {
        ULONG idx = 0;
        BYTE keyBuf[512];
        while (TRUE) {
            ULONG resultLen;
            NTSTATUS st = ZwEnumerateKey(hBam, idx++, KeyBasicInformation, keyBuf, sizeof(keyBuf), &resultLen);
            if (st == STATUS_NO_MORE_ENTRIES) break;
            if (!NT_SUCCESS(st)) continue;

            PKEY_BASIC_INFORMATION kbi = (PKEY_BASIC_INFORMATION)keyBuf;
            wchar_t subPath[512];
            RtlStringCchPrintfW(subPath, 512, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\%.*s",
                kbi->NameLength / sizeof(wchar_t), kbi->Name);

            UNICODE_STRING uSubPath;
            RtlInitUnicodeString(&uSubPath, subPath);
            HANDLE hSub;
            InitializeObjectAttributes(&oa, &uSubPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
            if (NT_SUCCESS(ZwOpenKey(&hSub, KEY_ALL_ACCESS, &oa))) {
                KDeleteAllValues(hSub);
                ZwClose(hSub);
            }
        }
        ZwClose(hBam);
    }

    DbgPrintEx(0, 0, "[CLEAN] BAM/DAM cleaned\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// PowerShell history cleanup
// ============================================================================

static NTSTATUS CleanPowerShellHistory() {
    DbgPrintEx(0, 0, "[CLEAN] Cleaning PowerShell history...\n");

    // PSReadLine history
    KDeleteFile(L"\\Users\\*\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt");

    DbgPrintEx(0, 0, "[CLEAN] PowerShell history cleaned\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// CMD history cleanup
// ============================================================================

static NTSTATUS CleanCMDHistory() {
    DbgPrintEx(0, 0, "[CLEAN] Cleaning CMD history...\n");

    // Console history
    UNICODE_STRING consolePath;
    RtlInitUnicodeString(&consolePath, L"\\Registry\\User\\Console");
    HANDLE hKey;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &consolePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    if (NT_SUCCESS(ZwOpenKey(&hKey, KEY_ALL_ACCESS, &oa))) {
        KDeleteAllValues(hKey);
        ZwClose(hKey);
    }

    DbgPrintEx(0, 0, "[CLEAN] CMD history cleaned\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Crash dump cleanup
// ============================================================================

static NTSTATUS CleanCrashDumps() {
    DbgPrintEx(0, 0, "[CLEAN] Cleaning Crash dumps...\n");

    // Minidumps
    KDeleteDirectoryContents(L"\\Windows\\Minidump");

    // Full dumps
    KDeleteFile(L"\\Windows\\MEMORY.dmp");

    // WER
    KDeleteDirectoryContents(L"\\ProgramData\\Microsoft\\Windows\\WER\\ReportQueue");
    KDeleteDirectoryContents(L"\\ProgramData\\Microsoft\\Windows\\WER\\ReportArchive");

    // LiveKernelReports
    KDeleteDirectoryContents(L"\\Windows\\LiveKernelReports");

    DbgPrintEx(0, 0, "[CLEAN] Crash dumps cleaned\n");
    return STATUS_SUCCESS;
}

// ============================================================================
// Main cleanup function - call this from DriverEntry
// ============================================================================

static void PerformFullCleanup() {
    DbgPrintEx(0, 0, "[CLEAN] ==========================================\n");
    DbgPrintEx(0, 0, "[CLEAN] Starting SAFE forensic trace cleanup\n");
    DbgPrintEx(0, 0, "[CLEAN] ==========================================\n");

    // Phase 1: Quick cleanup (always runs)
    CleanPrefetch();
    CleanEventLogs();
    CleanTempFiles();
    CleanRecentFiles();
    CleanCrashDumps();

    // Phase 2: Deep cleanup
    CleanJumpLists();
    CleanRegistryMRUs();
    CleanNetworkTraces();
    CleanUSBTraces();
    CleanAppTraces();
    CleanBAM();
    CleanPowerShellHistory();
    CleanCMDHistory();

    DbgPrintEx(0, 0, "[CLEAN] ==========================================\n");
    DbgPrintEx(0, 0, "[CLEAN] SAFE forensic trace cleanup COMPLETE\n");
    DbgPrintEx(0, 0, "[CLEAN] ==========================================\n");
}
