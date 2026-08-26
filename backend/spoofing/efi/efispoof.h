#pragma once
#include "../../functions/functions.h"

#define VARIABLE_ATTRIBUTE_NON_VOLATILE 1

static bool SpoofFirmwareEntry(const wchar_t* entryName) {
	UNICODE_STRING uEntryName;
	RtlInitUnicodeString(&uEntryName, entryName);

	// {eaec226f-c9a3-477a-a826-ddc716cdc0e3}
	UNICODE_STRING guidStr;
	RtlInitUnicodeString(&guidStr, L"{eaec226f-c9a3-477a-a826-ddc716cdc0e3}");
	GUID guid = { 0 };
	NTSTATUS ntStatus = RtlGUIDFromString(&guidStr, &guid);
	if (!NT_SUCCESS(ntStatus)) {
		DbgPrintEx(0, 0, "[EFI] RtlGUIDFromString failed: 0x%x\n", ntStatus);
		return false;
	}

	char buffer[0x100] = { 0 };
	char bufferCheck[0x100] = { 0 };
	ULONG length = 0xff;
	ULONG attributes = 0;

	ntStatus = ExGetFirmwareEnvironmentVariable(&uEntryName, &guid, buffer, &length, &attributes);
	if (!NT_SUCCESS(ntStatus)) {
		DbgPrintEx(0, 0, "[EFI] Could not get firmware env variable: 0x%x\n", ntStatus);
		return false;
	}

	RtlCopyMemory(bufferCheck, buffer, length);

	// Generate random data using DiskLCG
	ULONG seed = kmdf_settings::hwid_seed ^ 0xEF15DEAD;
	for (ULONG i = 0; i < length; i++) {
		seed = 1664525 * seed + 1013904223;
		buffer[i] = (char)(seed >> 16);
	}

	if (!memcmp(buffer, bufferCheck, length)) {
		DbgPrintEx(0, 0, "[EFI] All %d bytes are equal, failed to generate spoofed value\n", length);
		return false;
	}

	attributes |= VARIABLE_ATTRIBUTE_NON_VOLATILE;
	ntStatus = ExSetFirmwareEnvironmentVariable(&uEntryName, &guid, buffer, length, attributes);
	if (!NT_SUCCESS(ntStatus)) {
		DbgPrintEx(0, 0, "[EFI] Could not set firmware env variable: 0x%x\n", ntStatus);
		return false;
	}

	// Verify
	length = 0xff;
	ntStatus = ExGetFirmwareEnvironmentVariable(&uEntryName, &guid, buffer, &length, NULL);
	if (!NT_SUCCESS(ntStatus)) {
		return false;
	}

	if (!memcmp(buffer, bufferCheck, length)) {
		return false;
	}

	DbgPrintEx(0, 0, "[EFI] Spoofed entry %wZ\n", &uEntryName);
	return true;
}

static void efi_spoof() {
	if (!SpoofFirmwareEntry(L"UnlockIDCopy"))
		DbgPrintEx(0, 0, "[EFI] Failed spoofing UnlockIDCopy\n");
	if (!SpoofFirmwareEntry(L"OfflineUniqueIDRandomSeed"))
		DbgPrintEx(0, 0, "[EFI] Failed spoofing OfflineUniqueIDRandomSeed\n");
	if (!SpoofFirmwareEntry(L"OfflineUniqueIDRandomSeedCRC"))
		DbgPrintEx(0, 0, "[EFI] Failed spoofing OfflineUniqueIDRandomSeedCRC\n");
	if (!SpoofFirmwareEntry(L"OfflineUniqueIDEKPub"))
		DbgPrintEx(0, 0, "[EFI] Failed spoofing OfflineUniqueIDEKPub\n");
	if (!SpoofFirmwareEntry(L"OfflineUniqueIDEKPubCRC"))
		DbgPrintEx(0, 0, "[EFI] Failed spoofing OfflineUniqueIDEKPubCRC\n");
	if (!SpoofFirmwareEntry(L"PlatformModuleData"))
		DbgPrintEx(0, 0, "[EFI] Failed spoofing PlatformModuleData\n");
}
