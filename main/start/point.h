#pragma once

#include "../../backend/protection/callstack.h"
#include "../../backend/protection/oxorany/oxorany.h"
#include "../../backend/spoofing/arp/arp.h"
#include "../../backend/functions/pages/ia32/definitions/definitions.h"
#include "../../backend/functions/functions.h"
#include "../../backend/spoofing/disk/disk.h"
#include "../../backend/spoofing/arp/nic/nic.h"
#include "../../backend/spoofing/smbios/base_board.h"
#include "../../backend/spoofing/gpu/gpu.h"
#include "../../backend/spoofing/efi/efispoof.h"

UNICODE_STRING link;


inline static bool found_authentucation = false;
inline static bool psloaded_module_list = false;
inline static bool m_windows_version = false;
bool found_files = false;

extern "C" NTSTATUS NTAPI IoCreateDriver ( PUNICODE_STRING DriverName , PDRIVER_INITIALIZE InitializationFunction );




struct cleaning_ {

	uintptr_t dereference ( uintptr_t address , unsigned int offset ) {
		if ( address == 0 )
			return 0;

		return address + ( int ) ( ( *( int* ) ( address + offset ) + offset ) + sizeof ( int ) );
	}


	uintptr_t get_kernel_address ( const char* name , size_t& size ) {
		NTSTATUS status = STATUS_SUCCESS;
		ULONG neededSize = 0;

		ZwQuerySystemInformation (
			SystemModuleInformation ,
			&neededSize ,
			0 ,
			&neededSize
		);

		PSYSTEM_MODULE_INFORMATION pModuleList;

		pModuleList = ( PSYSTEM_MODULE_INFORMATION ) ExAllocatePool ( NonPagedPool , neededSize );

		if ( !pModuleList ) {
			return 0;
		}

		status = ZwQuerySystemInformation ( SystemModuleInformation ,
			pModuleList ,
			neededSize ,
			0
		);

		ULONG i = 0;
		uintptr_t address = 0;

		for ( i = 0; i < pModuleList->ulModuleCount; i++ )
		{
			SYSTEM_MODULE mod = pModuleList->Modules [ i ];

			address = uintptr_t ( pModuleList->Modules [ i ].Base );
			size = uintptr_t ( pModuleList->Modules [ i ].Size );
			if ( strstr ( mod.ImageName , name ) != NULL )
				break;
		}

		ExFreePool ( pModuleList );

		return address;
	}





};

cleaning_ cleaning;

void GenerateRandomSeed ( unsigned int& seed )
{
	SPOOF_FUNC;
	ULONG randomSeed = static_cast< ULONG >( seed );

	ULONG64 upperPart = RtlRandomEx ( &randomSeed ) % 1000000000;
	ULONG64 lowerPart = RtlRandomEx ( &randomSeed ) % 1000000000;

	unsigned long long combinedSeed = ( upperPart * 1000000ULL ) + ( lowerPart % 1000000ULL );

	seed = static_cast< unsigned int >( combinedSeed % UINT_MAX );

	if ( seed == 0 ) {
		seed = 1;
	}
}

BOOLEAN windows_11 ( )
{

	ULONG major , minor , build;
	PsGetVersion ( &major , &minor , &build , NULL );

	
	return ( major == 10 && build >= 22631 );
}

NTSTATUS bsod ( )
{
	KeBugCheckEx ( 0xDEADDEAD , 0 , 0 , 0 , 0 );
	return STATUS_SUCCESS;
}

struct startup_ {

	bool find_file ( ) {
		UNICODE_STRING file_path;
		const wchar_t* dec = oxorany ( L"\\??\\C:\\Windows\\bcastdvr\\file_verificaiton.txt" );
		RtlInitUnicodeString ( &file_path , dec );
		OBJECT_ATTRIBUTES object_attrs;
		IO_STATUS_BLOCK io_status;
		HANDLE file_handle;

		InitializeObjectAttributes ( &object_attrs , &file_path , OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE , NULL , NULL );

		NTSTATUS status = ZwCreateFile ( &file_handle ,
			FILE_READ_ATTRIBUTES ,
			&object_attrs ,
			&io_status ,
			NULL ,
			FILE_ATTRIBUTE_NORMAL ,
			FILE_SHARE_READ ,
			FILE_OPEN ,
			FILE_SYNCHRONOUS_IO_NONALERT ,
			NULL ,
			0 );

		bool exists = NT_SUCCESS ( status );

		if ( NT_SUCCESS ( status ) ) {
			ZwClose ( file_handle );
		}

		return exists;
	}

	bool delete_file ( ) {
		const wchar_t* decrypted = oxorany ( L"\\??\\C:\\Windows\\bcastdvr\\file_verificaiton.txt" );

		UNICODE_STRING file_path;
		RtlInitUnicodeString ( &file_path , decrypted );
		OBJECT_ATTRIBUTES object_attrs;
		IO_STATUS_BLOCK io_status;

		InitializeObjectAttributes ( &object_attrs , &file_path , OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE , NULL , NULL );

		NTSTATUS status = ZwDeleteFile ( &object_attrs );
		return NT_SUCCESS ( status );
	}

	bool delete_registry_value ( PUNICODE_STRING key_path , PUNICODE_STRING value_name )
	{
		HANDLE key_handle;
		OBJECT_ATTRIBUTES object_attrs;

		InitializeObjectAttributes (
			&object_attrs ,
			key_path ,
			OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE ,
			NULL ,
			NULL
		);

		NTSTATUS status = ZwOpenKey ( &key_handle , KEY_WRITE , &object_attrs );
		if ( !NT_SUCCESS ( status ) ) {
			return false;
		}

		status = ZwDeleteValueKey ( key_handle , value_name );
		ZwClose ( key_handle );

		return NT_SUCCESS ( status );
	}

	void batch_delete ( ) {
		delete_file ( );
		UNICODE_STRING RegPath;

		RtlInitUnicodeString ( &RegPath ,
			oxorany ( L"\\Registry\\Machine\\SOFTWARE\\Spoofer" ) );

		UNICODE_STRING spoofer_starting;
		RtlInitUnicodeString ( &spoofer_starting , oxorany ( L"spoofer_starting" ) );

		UNICODE_STRING logged_in;
		RtlInitUnicodeString ( &logged_in , oxorany ( L"logged_in" ) );

		delete_registry_value ( &RegPath , &spoofer_starting );
		delete_registry_value ( &RegPath , &logged_in );
	}

	NTSTATUS run_checks ( ) {
		UNICODE_STRING RegPath;
		RtlInitUnicodeString ( &RegPath , oxorany ( L"\\Registry\\Machine\\SOFTWARE\\Spoofer" ) );
		UNICODE_STRING value_starting;
		RtlInitUnicodeString ( &value_starting , oxorany ( L"spoofer_starting" ) );
		UNICODE_STRING value_logged;
		RtlInitUnicodeString ( &value_logged , oxorany ( L"logged_in" ) );


		bool auth_success = ( ULONG ) kmdf_communication::ReadRegistry<LONG64> ( RegPath , value_starting );
		bool auth_logged = ( ULONG ) kmdf_communication::ReadRegistry<LONG64> ( RegPath , value_logged );

		if ( !auth_success || !auth_logged )
		{
			bsod ( );
			DbgPrint ( oxorany ( "auth registry check failed" ) );
			return STATUS_ACCESS_DENIED;
		}

		if ( !find_file ( ) )
		{
			bsod ( );
			DbgPrint ( oxorany ( "required file missing" ) );
			return STATUS_ACCESS_DENIED;
		}

		batch_delete ( );

	}
};

startup_ startup;


PDRIVER_DISPATCH originalDispatch = nullptr;
NTSTATUS Dispatch ( PDEVICE_OBJECT device , PIRP irp )
{

	const PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation ( irp );
	if ( ioc->Parameters.DeviceIoControl.IoControlCode == IOCTL_TPM_SUBMIT_COMMAND )
	{
		const TPM2_COMMAND_HEADER* header = static_cast< TPM2_COMMAND_HEADER* >( irp->AssociatedIrp.SystemBuffer );
		const TPM_CC command = BigEndianToLittleEndian32 ( header->commandCode );
		if ( command == TPM_CC_ReadPublic )
			tpm_change_ioc ( ioc , irp , &HandleReadPublic );
	}

	return originalDispatch ( device , irp );
}

struct tpm_ {


	NTSTATUS delete_endorsement ( )
	{
		UNICODE_STRING keyName;

		RtlInitUnicodeString ( &keyName , oxorany ( L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\TPM\\WMI\\Endorsement") );
		kmdf_utils::DeleteRegistryKey ( &keyName );
		kmdf_utils::DeleteSubKeys ( &keyName );
		kmdf_utils::DeleteRegistryKeyRecursively ( &keyName );

		return STATUS_SUCCESS;
	}

	auto spoof( ) -> NTSTATUS {
	delete_endorsement ( );
	NTSTATUS status = GenerateRandomKey ( &generatedKey );
	if ( !NT_SUCCESS ( status ) )
	{
		return status;
	}

	UNICODE_STRING driverName;
	RtlInitUnicodeString ( &driverName,  oxorany( L"\\Driver\\TPM") );

	PDRIVER_OBJECT driverObject;
	status = ObReferenceObjectByName ( &driverName, OBJ_CASE_INSENSITIVE, nullptr, 0,
		*IoDriverObjectType, KernelMode, nullptr,
		reinterpret_cast< PVOID* >( &driverObject ) );
	if ( !NT_SUCCESS ( status ) )
		return status;

	originalDispatch = driverObject->MajorFunction [ 0 ];

	for ( DWORD i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++ )
		driverObject->MajorFunction [ i ] = &Dispatch;

	}
};
tpm_ tpm;

struct seed_ {


	auto start ( ) -> NTSTATUS {
		UNICODE_STRING seed;
		UNICODE_STRING reg_path;
		RtlInitUnicodeString ( &reg_path , hide_string ( L"\\Registry\\Machine\\SOFTWARE\\Spoofer" ) );
		RtlInitUnicodeString ( &seed , hide_string ( L"Seed" ) ); 
		kmdf_settings::hwid_seed = ( ULONG ) kmdf_communication::ReadRegistry<ULONG> ( reg_path , seed );
		if ( kmdf_settings::hwid_seed != 0 ) {
			srand ( kmdf_settings::hwid_seed );
			DbgPrintEx ( 0 , 0 , oxorany ( "[KDW11S] seed: %u" ) , kmdf_settings::hwid_seed );
		}
		else {
			GenerateRandomSeed ( kmdf_settings::hwid_seed );
			DbgPrintEx ( 0 , 0 , oxorany ( "[KDW11S] random generated seed : %i\n" ) , kmdf_settings::hwid_seed );
		}
		
		return STATUS_SUCCESS;
	}
};



seed_ seed;





