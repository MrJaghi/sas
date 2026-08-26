#include "start/point.h"

inline bool admin = true;

typedef struct _SWAP {
	UNICODE_STRING Name;
	PVOID* Swap;
	PDRIVER_DISPATCH Original;
} SWAP, * PSWAP;

static struct _SWAPS {
	SWAP Buffer[0xFF];
	ULONG Length;
};

_SWAPS SWAPS = { 0 };

NTSTATUS AppendSwap(UNICODE_STRING name, PDRIVER_DISPATCH* swap, NTSTATUS(*hook)(PDEVICE_OBJECT device, PIRP irp), PDRIVER_DISPATCH* original) {

	PSWAP entry = &SWAPS.Buffer[SWAPS.Length++];

	entry->Swap = (PVOID*)swap;
	entry->Original = (PDRIVER_DISPATCH)InterlockedExchangePointer(entry->Swap, hook);
	entry->Name = name;

	*original = entry->Original;


	return STATUS_SUCCESS;
}
NTSTATUS SwapControl(UNICODE_STRING driver, NTSTATUS(*hook)(PDEVICE_OBJECT device, PIRP irp), PDRIVER_DISPATCH* original) {
	UNICODE_STRING str = driver;
	PDRIVER_OBJECT object = 0;
	NTSTATUS _status = ObReferenceObjectByName(&str, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType, KernelMode, 0, (PVOID*)&object);
	if (NT_SUCCESS(_status)) {
		AppendSwap(str, &object->MajorFunction[IRP_MJ_DEVICE_CONTROL], hook, original);
		ObDereferenceObject(object);
	}
	else {

		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry ( PDRIVER_OBJECT DriverObject , PUNICODE_STRING Driverregistry )
{
	UNREFERENCED_PARAMETER ( DriverObject );
	UNREFERENCED_PARAMETER ( Driverregistry );

	if ( !admin ) {
		startup.run_checks ( );
	}

	///Grab Seed
    UNICODE_STRING RegPath = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SOFTWARE\\SPOOFER");
	kmdf_settings::hwid_seed = (ULONG)kmdf_communication::ReadRegistry<LONG64>(RegPath, RTL_CONSTANT_STRING(L"P"));
    DbgPrintEx(0, 0, "[+] Seed From Registry : %i\n", kmdf_settings::hwid_seed);
	///Set Seed
	srand(kmdf_settings::hwid_seed);

	disk.spoof ( );

	motherboard.spoof ( );

	gpu.spoof ( );

	registry.spoof ( );

	mac.spoof();

	monitor.spoof_reg ( );

	monitor.spoof_graphics ( );

	usb.spoof();

	tpm.spoof ( );

	//// EFI variable spoofing
	efi_spoof();

	// ARP - uses completion routine with pattern-scan for Win10+Win11 compat
	SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\nsiproxy"), NsiDispatchHook, &g_OriginalNsiDispatch);

	// Hook nsi (in addition to nsiproxy) for broader ARP coverage
	SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\nsi"), NsiDispatchHook2, &g_OriginalNsiDispatch2);

	// Hook Tcp for IOCTL_TCP_QUERY_INFORMATION_EX (IFEntry.if_physaddr spoofing)
	SwapControl(RTL_CONSTANT_STRING(L"\\Driver\\Tcp"), TcpDispatchHook, &g_OriginalTcpDispatch);

	return STATUS_SUCCESS;
}

