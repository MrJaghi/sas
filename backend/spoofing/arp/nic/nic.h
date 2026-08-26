
#pragma once
#include <ifdef.h>
#include <ntddndis.h>
#include <bcrypt.h>
#include <stddef.h>
#include "../../../../tpm/tpm12.h"
#include "../../../../tpm/tpm20.h"
#include <cstdint>
#include <usbioctl.h>

#define RELATIVE_ADDRESS(address, size) ((VOID*)((UINT8*)(address) + *(INT32*)((UINT8*)(address) + ((size) - (INT32)sizeof(INT32))) + (size)))

#define IOCTL_NSI_PROXY_ARP (0x0012001B)

PDRIVER_DISPATCH g_OriginalNsiDispatch = nullptr;

extern "C" NTSTATUS NTAPI NtAllocateUuids(
	PULARGE_INTEGER Time,
	PULONG Range,
	PULONG Sequence,
	PCHAR Seed
);

// ============================================================================
// NDIS struct definitions
// ============================================================================

typedef struct _NDIS_M_DRIVER_BLOCK
{
	union
	{
		struct
		{
			VOID* Header;
			VOID* NextDriver;
		};
		struct
		{
			char Space[0x028];
			PDRIVER_OBJECT DriverObject;
		};
	};
} NDIS_M_DRIVER_BLOCK, *PNDIS_M_DRIVER_BLOCK;

// NDIS_IF_BLOCK: offsets resolved dynamically from PDB (no hardcoded padding)
// ifPhysAddress and PermanentPhysAddress offsets read from registry at runtime

typedef struct _KSTRING {
	char _padding_0[0x10];
	WCHAR Buffer[1]; // 0x10 at least
} KSTRING, *PKSTRING;

// NDIS_FILTER_BLOCK: offsets resolved dynamically from PDB (no hardcoded padding)

typedef struct _NIC_ARRAY
{
	PDRIVER_OBJECT driver_object;
	PDRIVER_DISPATCH original_function;
} NIC_ARRAY, *PNIC_ARRAY;

// ============================================================================
// NIC adapter tracking
// ============================================================================

const int max_array_size = 20;
int array_size = 0;
NIC_ARRAY g_nic_array[max_array_size] = { 0 };
KSPIN_LOCK g_lock;

// ============================================================================
// MAC Cache and FindFakeNicMac (per-MAC deterministic spoofing)
// ============================================================================

#define MAX_MAC_CACHE 32

struct MacCacheEntry {
	char orig[6];
	char spoofed[6];
};

static MacCacheEntry g_macCache[MAX_MAC_CACHE] = {};
static int g_macCount = 0;

static ULONG MacLCG(ULONG& seed) {
	seed = 1664525 * seed + 1013904223;
	return seed;
}

bool FindFakeNicMac(char* pOriginal) {
	if (!pOriginal) return false;

	// Check cache for original
	for (int i = 0; i < g_macCount; i++) {
		if (!memcmp(g_macCache[i].orig, pOriginal, 6)) {
			RtlCopyMemory(pOriginal, g_macCache[i].spoofed, 6);
			return true;
		}
	}

	// Check if already spoofed (in case init code modified in-place)
	for (int i = 0; i < g_macCount; i++) {
		if (!memcmp(g_macCache[i].spoofed, pOriginal, 6)) {
			return true;
		}
	}

	// New MAC - create cache entry
	if (g_macCount >= MAX_MAC_CACHE) return false;

	MacCacheEntry* entry = &g_macCache[g_macCount];
	RtlCopyMemory(entry->orig, pOriginal, 6);
	RtlCopyMemory(entry->spoofed, pOriginal, 6);

	// Derive per-MAC seed from hwid_seed + original MAC bytes
	ULONG seed = kmdf_settings::hwid_seed;
	for (int i = 0; i < 6; i++)
		seed ^= ((UCHAR)pOriginal[i]) << ((i % 4) * 8);

	// Randomize bytes 3-5 (keep OUI prefix bytes 0-2 for consistency)
	// Character class preservation: digit nibbles stay digits, letter nibbles stay letters
	for (int b = 3; b < 6; b++) {
		unsigned char orig = (unsigned char)entry->orig[b];
		unsigned char r = (unsigned char)MacLCG(seed);
		unsigned char result = 0;

		// High nibble
		unsigned char oh = (orig >> 4) & 0xF;
		unsigned char rh = (r >> 4) & 0xF;
		result = (oh >= 0xA) ? ((0xA + (rh % 6)) << 4) : ((rh % 10) << 4);

		// Low nibble
		unsigned char ol = orig & 0xF;
		unsigned char rl = r & 0xF;
		result |= (ol >= 0xA) ? (0xA + (rl % 6)) : (rl % 10);

		entry->spoofed[b] = (char)result;
	}

	DbgPrintEx(0, 0, "[NIC] MAC cached [%d]: %02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X\n",
		g_macCount,
		(UCHAR)entry->orig[0], (UCHAR)entry->orig[1], (UCHAR)entry->orig[2],
		(UCHAR)entry->orig[3], (UCHAR)entry->orig[4], (UCHAR)entry->orig[5],
		(UCHAR)entry->spoofed[0], (UCHAR)entry->spoofed[1], (UCHAR)entry->spoofed[2],
		(UCHAR)entry->spoofed[3], (UCHAR)entry->spoofed[4], (UCHAR)entry->spoofed[5]);

	g_macCount++;
	RtlCopyMemory(pOriginal, entry->spoofed, 6);
	return true;
}

// ============================================================================
// NIC IOCTL completion routines (NDIS_QUERY_GLOBAL_STATS)
// ============================================================================

NTSTATUS my_nic_ioc_handle(PDEVICE_OBJECT device, PIRP irp, PVOID context)
{
	if (context)
	{
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (NT_SUCCESS(irp->IoStatus.Status) && irp->MdlAddress) {
			PVOID systemAddress = MmGetSystemAddressForMdl(irp->MdlAddress);
			if (systemAddress) {
				FindFakeNicMac((char*)systemAddress);
			}
		}

		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}

	return STATUS_SUCCESS;
}

// ============================================================================
// NIC adapter dispatch handler
// ============================================================================

NTSTATUS my_mac_handle_control(PDEVICE_OBJECT device, PIRP irp)
{
	KIRQL irql;
	KeAcquireSpinLock(&g_lock, &irql);

	for (int i = 0; i < array_size; i++) {
		NIC_ARRAY& item = g_nic_array[i];
		if (item.driver_object != device->DriverObject) continue;

		PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
		unsigned long code = ioc->Parameters.DeviceIoControl.IoControlCode;

		if (code == IOCTL_NDIS_QUERY_GLOBAL_STATS) {
			DWORD type = *(PDWORD)irp->AssociatedIrp.SystemBuffer;
			if (type == OID_802_3_PERMANENT_ADDRESS || type == OID_802_5_PERMANENT_ADDRESS
				|| type == OID_802_3_CURRENT_ADDRESS || type == OID_802_5_CURRENT_ADDRESS) {
				kmdf_utils::change_ioc(ioc, irp, my_nic_ioc_handle);
			}
		}

		SPOOF_CALL(void, KeReleaseSpinLock)(&g_lock, irql);
		return item.original_function(device, irp);
	}

	SPOOF_CALL(void, KeReleaseSpinLock)(&g_lock, irql);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// ============================================================================
// NDIS filter block walking: spoof NIC MACs at NDIS level
// ============================================================================

wchar_t* paste_guid(wchar_t* str, size_t len)
{
	if (str == 0) return 0;
	if (len == 0) len = wcslen(str);

	size_t index = 0;
	for (size_t i = 0; i < len; i++)
	{
		if (str[i] == L'{') index = i;
		else if (str[i] == L'}')
		{
			str[i + 1] = 0;
			break;
		}
	}

	return str + index;
}

struct mac_
{
	auto spoof() -> bool
	{
		SPOOF_FUNC;

		(KeInitializeSpinLock)(&g_lock);

		// Read encrypted NDIS offsets from registry (resolved from ndis.pdb by loader)
		UNICODE_STRING RegPath = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\SPOOFER");
		ULONG64 seed64 = (ULONG64)kmdf_communication::ReadRegistry<LONG64>(RegPath, RTL_CONSTANT_STRING(L"P"));
		ULONG64 xkey = seed64 ^ 0xA3B7C9D1E5F20846ULL;

		ULONG64 offGlobalFilterList = (ULONG64)kmdf_communication::ReadRegistry<LONG64>(RegPath, RTL_CONSTANT_STRING(L"N1")) ^ xkey;
		ULONG64 offNextFilter       = (ULONG64)kmdf_communication::ReadRegistry<LONG64>(RegPath, RTL_CONSTANT_STRING(L"N2")) ^ xkey;
		ULONG64 offInstanceName     = (ULONG64)kmdf_communication::ReadRegistry<LONG64>(RegPath, RTL_CONSTANT_STRING(L"N3")) ^ xkey;
		ULONG64 offIfBlock          = (ULONG64)kmdf_communication::ReadRegistry<LONG64>(RegPath, RTL_CONSTANT_STRING(L"N4")) ^ xkey;
		ULONG64 offIfPhy            = (ULONG64)kmdf_communication::ReadRegistry<LONG64>(RegPath, RTL_CONSTANT_STRING(L"N5")) ^ xkey;
		ULONG64 offIfPermPhy        = (ULONG64)kmdf_communication::ReadRegistry<LONG64>(RegPath, RTL_CONSTANT_STRING(L"N6")) ^ xkey;

		if (!offGlobalFilterList || !offNextFilter || !offIfBlock || !offIfPhy || !offIfPermPhy) {
			DbgPrintEx(0, 0, "[NIC] FAIL: NDIS offsets not in registry (loader too old?)\n");
			return false;
		}
		DbgPrintEx(0, 0, "[NIC] PDB offsets: GFL=0x%llX NF=0x%llX IN=0x%llX IFB=0x%llX Phy=0x%llX PPhy=0x%llX\n",
			offGlobalFilterList, offNextFilter, offInstanceName, offIfBlock, offIfPhy, offIfPermPhy);

		DWORD64 ndisBase = DWORD64(kmdf_utils::GetModuleBase(oxorany("ndis.sys")));
		if (!ndisBase) {
			DbgPrintEx(0, 0, "[NIC] FAIL: ndis.sys base not found\n");
			return false;
		}
		DbgPrintEx(0, 0, "[NIC] ndis.sys base: %p\n", (PVOID)ndisBase);

		// Read ndisGlobalFilterList using PDB RVA (no pattern scan needed)
		PVOID pFilterHead = *(PVOID*)(ndisBase + offGlobalFilterList);
		if (!pFilterHead || !MmIsAddressValid(pFilterHead)) {
			DbgPrintEx(0, 0, "[NIC] FAIL: ndisGlobalFilterList is NULL or invalid\n");
			return false;
		}

		// Walk filter chain using dynamic offsets
		for (PBYTE filter = (PBYTE)pFilterHead; filter; ) {
			if (!MmIsAddressValid(filter)) break;

			PVOID ifBlock = *(PVOID*)(filter + offIfBlock);

			if (ifBlock && MmIsAddressValid(ifBlock)) {
				// Spoof ifPhysAddress (IF_PHYSICAL_ADDRESS_LH: USHORT Length + UCHAR Address[32])
				PBYTE phyBase = (PBYTE)ifBlock + offIfPhy;
				if (MmIsAddressValid(phyBase)) {
					USHORT phyLen = *(USHORT*)phyBase;
					PUCHAR phyAddr = phyBase + sizeof(USHORT);
					if (phyLen >= 6)
						FindFakeNicMac((char*)phyAddr);
				}

				// Spoof PermanentPhysAddress
				PBYTE permBase = (PBYTE)ifBlock + offIfPermPhy;
				if (MmIsAddressValid(permBase)) {
					USHORT permLen = *(USHORT*)permBase;
					PUCHAR permAddr = permBase + sizeof(USHORT);
					if (permLen >= 6)
						FindFakeNicMac((char*)permAddr);
				}
			}

			// Hook NIC adapter dispatch via FilterInstanceName
			if (offInstanceName) {
				PKSTRING instanceName = *(PKSTRING*)(filter + offInstanceName);
				if (instanceName && MmIsAddressValid(instanceName) && instanceName->Buffer) {
					size_t length = wcslen(instanceName->Buffer);
					wchar_t* buffer = (wchar_t*)ExAllocatePoolWithTag(NonPagedPool, length, 'mnml');
					if (buffer) {
						MM_COPY_ADDRESS addr{ 0 };
						addr.VirtualAddress = instanceName->Buffer;
						SIZE_T read_size = 0;
						NTSTATUS status = MmCopyMemory(buffer, addr, length, MM_COPY_MEMORY_VIRTUAL, &read_size);
						if (status == STATUS_SUCCESS && read_size == length) {
							wchar_t* memory = (wchar_t*)ExAllocatePoolWithTag(NonPagedPool, length * 2, 'mnml');
							if (memory) {
								RtlStringCbPrintfW(memory, length * 2, oxorany(L"\\Device\\%ws"), paste_guid(buffer, length));
								UNICODE_STRING adapter;
								RtlInitUnicodeString(&adapter, memory);
								PFILE_OBJECT file_object = 0;
								PDEVICE_OBJECT device_object = 0;
								status = IoGetDeviceObjectPointer(&adapter, FILE_READ_DATA, &file_object, &device_object);
								if (NT_SUCCESS(status)) {
									PDRIVER_OBJECT driver_object = device_object->DriverObject;
									bool exists = false;
									for (int i = 0; i < array_size; i++) {
										if (g_nic_array[i].driver_object == driver_object) { exists = true; break; }
									}
									if (!exists && array_size < max_array_size) {
										g_nic_array[array_size].driver_object = driver_object;
										g_nic_array[array_size].original_function = driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL];
										driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = my_mac_handle_control;
										array_size++;
									}
									ObDereferenceObject(file_object);
								}
								ExFreePoolWithTag(memory, 'mnml');
							}
						}
						ExFreePoolWithTag(buffer, 'mnml');
					}
				}
			}

			// Advance to next filter
			PVOID next = *(PVOID*)(filter + offNextFilter);
			filter = (PBYTE)next;
		}

		// Hook ndiswan explicitly (WAN miniport, not in NDIS filter list)
		{
			UNICODE_STRING ndisWanName;
			RtlInitUnicodeString(&ndisWanName, L"\\Driver\\ndiswan");
			PDRIVER_OBJECT ndisWanObj = nullptr;
			NTSTATUS status = ObReferenceObjectByName(&ndisWanName, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, (PVOID*)&ndisWanObj);
			if (NT_SUCCESS(status) && ndisWanObj) {
				bool exists = false;
				for (int i = 0; i < array_size; i++) {
					if (g_nic_array[i].driver_object == ndisWanObj) {
						exists = true;
						break;
					}
				}
				if (!exists && array_size < max_array_size) {
					g_nic_array[array_size].driver_object = ndisWanObj;
					g_nic_array[array_size].original_function = ndisWanObj->MajorFunction[IRP_MJ_DEVICE_CONTROL];
					ndisWanObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = my_mac_handle_control;
					array_size++;
					DbgPrintEx(0, 0, "[NIC] Hooked ndiswan\n");
				}
				ObDereferenceObject(ndisWanObj);
			}
		}

		// Enumerate GUID_DEVINTERFACE_NET and hook each net adapter
		{
			PWCHAR pNetDevNames = nullptr;
			const GUID GUID_DEVINTERFACE_NET = { 0xcac88484, 0x7515, 0x4c03, { 0x82, 0xe6, 0x71, 0xa8, 0x7a, 0xba, 0xc3, 0x61 } };
			NTSTATUS status = IoGetDeviceInterfaces(&GUID_DEVINTERFACE_NET, nullptr, DEVICE_INTERFACE_INCLUDE_NONACTIVE, &pNetDevNames);
			if (NT_SUCCESS(status) && pNetDevNames) {
				PWCHAR cur = pNetDevNames;
				while (*cur) {
					UNICODE_STRING uName;
					RtlInitUnicodeString(&uName, cur);

					PFILE_OBJECT fileObj = nullptr;
					PDEVICE_OBJECT devObj = nullptr;
					NTSTATUS s = IoGetDeviceObjectPointer(&uName, FILE_READ_DATA, &fileObj, &devObj);
					if (NT_SUCCESS(s) && devObj && devObj->DriverObject) {
						PDRIVER_OBJECT drv = devObj->DriverObject;

						bool exists = false;
						for (int i = 0; i < array_size; i++) {
							if (g_nic_array[i].driver_object == drv) {
								exists = true;
								break;
							}
						}

						if (!exists && array_size < max_array_size) {
							g_nic_array[array_size].driver_object = drv;
							g_nic_array[array_size].original_function = drv->MajorFunction[IRP_MJ_DEVICE_CONTROL];
							drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = my_mac_handle_control;
							array_size++;
							DbgPrintEx(0, 0, "[NIC] Hooked net interface adapter\n");
						}

						ObDereferenceObject(fileObj);
					}

					cur += (wcslen(cur) + 1);
				}

				ExFreePool(pNetDevNames);
			}
		}

		DbgPrintEx(0, 0, "[NIC] Total NIC hooks: %d, MAC cache entries: %d\n", array_size, g_macCount);
		return true;
	}

	auto handle_adapters() -> void {
		spoof();
	}
};

mac_ mac;

// ============================================================================
// USB hooks (unchanged - zero USB serial numbers)
// ============================================================================

typedef struct _USB_DRIVER {
	PDRIVER_OBJECT DriverObject;
	PDRIVER_DISPATCH Original;
} USB_DRIVER, *PUSB_DRIVER;

struct USBS {
	DWORD Length;
	USB_DRIVER Drivers[0xFF];
} USBs = { 0 };

NTSTATUS UsbHubCompletion(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp,
	PVOID Context
)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(Context);

	if (NT_SUCCESS(Irp->IoStatus.Status))
	{
		PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(Irp);

		if (ioc && Irp->AssociatedIrp.SystemBuffer)
		{
			switch (ioc->Parameters.DeviceIoControl.IoControlCode)
			{
			case IOCTL_USB_GET_NODE_CONNECTION_INFORMATION:
			{
				auto pInfo = (PUSB_NODE_CONNECTION_INFORMATION)Irp->AssociatedIrp.SystemBuffer;
				pInfo->DeviceDescriptor.iSerialNumber = 0;
				break;
			}
			case IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX:
			{
				auto pInfoEx = (PUSB_NODE_CONNECTION_INFORMATION_EX)Irp->AssociatedIrp.SystemBuffer;
				pInfoEx->DeviceDescriptor.iSerialNumber = 0;
				break;
			}
			}
		}
	}

	return STATUS_CONTINUE_COMPLETION;
}

NTSTATUS UsbHubControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PDRIVER_DISPATCH orig = nullptr;
	for (DWORD i = 0; i < USBs.Length; ++i)
	{
		if (USBs.Drivers[i].DriverObject == DeviceObject->DriverObject)
		{
			orig = USBs.Drivers[i].Original;
			break;
		}
	}

	if (!orig)
		return STATUS_INVALID_DEVICE_REQUEST;

	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(Irp);

	if (!ioc)
		return orig(DeviceObject, Irp);

	ULONG code = ioc->Parameters.DeviceIoControl.IoControlCode;

	switch (code)
	{
	case IOCTL_USB_GET_NODE_CONNECTION_INFORMATION:
	case IOCTL_USB_GET_NODE_CONNECTION_INFORMATION_EX:
		IoCopyCurrentIrpStackLocationToNext(Irp);
		IoSetCompletionRoutine(Irp, UsbHubCompletion, nullptr, TRUE, TRUE, TRUE);
		return orig(DeviceObject, Irp);

	default:
		break;
	}

	return orig(DeviceObject, Irp);
}

struct usb_ {
	NTSTATUS spoof()
	{
		PWCHAR pDeviceNames = nullptr;
		const GUID GUID_USB_HUB = { 0xf18a0e88, 0xc30c, 0x11d0, { 0x88, 0x15, 0x00, 0xa0, 0xc9, 0x06, 0xbe, 0xd8 } };

		NTSTATUS ntStatus = IoGetDeviceInterfaces(&GUID_USB_HUB, nullptr, DEVICE_INTERFACE_INCLUDE_NONACTIVE, &pDeviceNames);
		if (!NT_SUCCESS(ntStatus) || !pDeviceNames) {
			return STATUS_UNSUCCESSFUL;
		}

		PWCHAR cur = pDeviceNames;
		while (*cur) {
			UNICODE_STRING uName;
			RtlInitUnicodeString(&uName, cur);

			PFILE_OBJECT fileObject = nullptr;
			PDEVICE_OBJECT deviceObject = nullptr;

			NTSTATUS s = IoGetDeviceObjectPointer(&uName, FILE_READ_DATA, &fileObject, &deviceObject);
			if (NT_SUCCESS(s) && deviceObject && deviceObject->DriverObject) {
				PDRIVER_OBJECT drv = deviceObject->DriverObject;

				bool found = false;
				for (DWORD i = 0; i < USBs.Length; ++i) {
					if (USBs.Drivers[i].DriverObject == drv) {
						found = true;
						break;
					}
				}

				if (!found && USBs.Length < _countof(USBs.Drivers)) {
					PDRIVER_DISPATCH old = drv->MajorFunction[IRP_MJ_DEVICE_CONTROL];

					drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = UsbHubControl;

					USBs.Drivers[USBs.Length].DriverObject = drv;
					USBs.Drivers[USBs.Length].Original = old;
					++USBs.Length;
				}

				ObDereferenceObject(fileObject);
			}

			cur += (wcslen(cur) + 1);
		}

		ExFreePool(pDeviceNames);
		return STATUS_SUCCESS;
	}
};

usb_ usb;

// ============================================================================
// NSI/ARP completion routine: pattern-scan for Win10+Win11 compatibility
// ============================================================================
//
// Instead of using hardcoded NSI_PARAMS struct offsets (which vary between
// Windows versions), we pattern-scan the NSI response buffer for table group
// descriptors: QWORD user-mode pointer + DWORD entry size pairs.
//
// Table group order: AddrTable, NeighborTable(Rw), StateTable(Rod), OwnerTable(Ros)
// We spoof the NeighborTable (2nd group) which contains ARP MAC addresses.
//

NTSTATUS NsiCompletion(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
	if (!Context)
		return STATUS_SUCCESS;

	kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)Context;
	ExFreePool(Context);

	if (NT_SUCCESS(Irp->IoStatus.Status))
	{
		__try
		{
			char* buf = (char*)Irp->UserBuffer;
			if (buf && MmIsAddressValid(buf))
			{
				// Check Type field at offset 0x18 (NSI_GET_IP_NET_TABLE = 11 = ARP)
				int type = *(int*)(buf + 0x18);

				if (type == NSI_GET_IP_NET_TABLE) {
					// Pattern scan: find pointer+entrySize table group descriptors
					// Each group: QWORD user-mode pointer + DWORD entry size (+ DWORD pad) = 16 bytes
					DWORD64 tblPtrs[4] = {};
					int tblSizes[4] = {};
					int tblOffsets[4] = {};
					int tblCount = 0;

					for (int off = 0x20; off <= 0x80 && tblCount < 4; off += 8) {
						DWORD64 val = *(DWORD64*)(buf + off);
						if (val > 0x10000 && val < 0x7FFFFFFFFFFF) {
							int sz = *(int*)(buf + off + 8);
							if (sz >= 0x10 && sz <= 0x200) {
								tblPtrs[tblCount] = val;
								tblSizes[tblCount] = sz;
								tblOffsets[tblCount] = off;
								tblCount++;
								off += 8; // Skip size DWORD (next iteration adds 8 more = 16 total)
							}
						}
					}

					if (tblCount >= 2) {
						// Find Count after last table group
						int count = 0;
						int searchStart = tblOffsets[tblCount - 1] + 16;
						for (int coff = searchStart; coff <= searchStart + 16; coff += 4) {
							int val = *(int*)(buf + coff);
							if (val > 0 && val <= 256) {
								count = val;
								break;
							}
						}

						if (count > 0) {
							// NeighborTable = 2nd table group (index 1)
							// MAC is at offset 0x00 in each Rw neighbor entry
							char* neighborTable = (char*)tblPtrs[1];
							int entrySize = tblSizes[1];

							for (int arpIdx = 0; arpIdx < count; arpIdx++) {
								char* mac = neighborTable + ((SIZE_T)arpIdx * entrySize);
								unsigned char* um = (unsigned char*)mac;

								// Skip all-zero (incomplete ARP entries)
								if ((um[0] | um[1] | um[2] | um[3] | um[4] | um[5]) == 0)
									continue;

								// Use local kernel stack buffer: FindFakeNicMac must not
								// operate on user-mode pages (would crash if page fault occurs)
								char localMac[6];
								RtlCopyMemory(localMac, mac, 6);
								FindFakeNicMac(localMac);
								RtlCopyMemory(mac, localMac, 6);
							}
						}
					}
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}
	}

	if (request.OldRoutine)
		return request.OldRoutine(DeviceObject, Irp, request.OldContext);

	return STATUS_SUCCESS;
}

// ============================================================================
// NSI dispatch hook: intercepts nsiproxy ARP IOCTLs, adds completion routine
// Uses change_ioc on the CURRENT stack location (not IoCopyCurrentIrpStackLocationToNext)
// because nsiproxy is a leaf driver with StackSize=1 — writing to the "next"
// stack location would go out of bounds and corrupt adjacent pool memory.
// ============================================================================

NTSTATUS NsiDispatchHook(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
)
{
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(Irp);

	if (ioc->Parameters.DeviceIoControl.IoControlCode == IOCTL_NSI_PROXY_ARP)
	{
		kmdf_utils::change_ioc(ioc, Irp, NsiCompletion);
		// Must invoke on all paths to ensure IOC_REQUEST is always freed
		ioc->Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
	}

	return g_OriginalNsiDispatch(DeviceObject, Irp);
}

// ============================================================================
// NSI dispatch hook (for \Driver\nsi, in addition to nsiproxy)
// ============================================================================

PDRIVER_DISPATCH g_OriginalNsiDispatch2 = nullptr;

NTSTATUS NsiDispatchHook2(
	PDEVICE_OBJECT DeviceObject,
	PIRP Irp
)
{
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(Irp);

	if (ioc->Parameters.DeviceIoControl.IoControlCode == IOCTL_NSI_PROXY_ARP)
	{
		kmdf_utils::change_ioc(ioc, Irp, NsiCompletion);
		ioc->Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
	}

	return g_OriginalNsiDispatch2(DeviceObject, Irp);
}

// ============================================================================
// TCP Query Information hook (IFEntry MAC spoofing)
// Ported from HV nicspoof.cpp TcpControl
// ============================================================================

#define IOCTL_TCP_QUERY_INFORMATION_EX 0x00120003
#define MAX_PHYSADDR_SIZE 8

typedef struct _IFEntry {
	ULONG if_index;
	ULONG if_type;
	ULONG if_mtu;
	ULONG if_speed;
	ULONG if_physaddrlen;
	UCHAR if_physaddr[MAX_PHYSADDR_SIZE];
	ULONG if_adminstatus;
	ULONG if_operstatus;
	ULONG if_lastchange;
	ULONG if_inoctets;
	ULONG if_inucastpkts;
	ULONG if_innucastpkts;
	ULONG if_indiscards;
	ULONG if_inerrors;
	ULONG if_inunknownprotos;
	ULONG if_outoctets;
	ULONG if_outucastpkts;
	ULONG if_outnucastpkts;
	ULONG if_outdiscards;
	ULONG if_outerrors;
	ULONG if_outqlen;
	ULONG if_descrlen;
	UCHAR if_descr[1];
} IFEntry;

PDRIVER_DISPATCH g_OriginalTcpDispatch = nullptr;

NTSTATUS TcpDispatchHook(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(Irp);

	if (ioc->Parameters.DeviceIoControl.IoControlCode == IOCTL_TCP_QUERY_INFORMATION_EX)
	{
		NTSTATUS ntStatus = g_OriginalTcpDispatch(DeviceObject, Irp);
		if (NT_SUCCESS(ntStatus)) {
			__try {
				IFEntry* ifEntry = (IFEntry*)Irp->UserBuffer;
				if (ifEntry && MmIsAddressValid(ifEntry) && ifEntry->if_physaddrlen >= 6) {
					unsigned char* um = (unsigned char*)ifEntry->if_physaddr;
					if ((um[0] | um[1] | um[2] | um[3] | um[4] | um[5]) != 0) {
						char localMac[6];
						RtlCopyMemory(localMac, ifEntry->if_physaddr, 6);
						FindFakeNicMac(localMac);
						RtlCopyMemory(ifEntry->if_physaddr, localMac, 6);
					}
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {}
		}
		return ntStatus;
	}

	return g_OriginalTcpDispatch(DeviceObject, Irp);
}
