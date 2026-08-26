#pragma once
#include <minwindef.h>
#include "../functions/pages/pages.h"
namespace kmdf_utils
{
	typedef struct _IOC_REQUEST {
		PVOID Buffer;
		ULONG BufferLength;
		PVOID OldContext;
		PIO_COMPLETION_ROUTINE OldRoutine;
		PMDL DataMdl;
	} IOC_REQUEST , * PIOC_REQUEST;

	bool get_module_base_address ( const char* name , DWORD64& addr , DWORD32& size )
	{
		unsigned long need_size = 0;
		ZwQuerySystemInformation ( 11 , &need_size , 0 , &need_size );
		if ( need_size == 0 ) return false;

		const unsigned long tag = 'Util';
		PSYSTEM_MODULE_INFORMATION sys_mods = ( PSYSTEM_MODULE_INFORMATION ) ExAllocatePoolWithTag ( NonPagedPool , need_size , tag );
		if ( sys_mods == 0 ) return false;

		NTSTATUS status = ZwQuerySystemInformation ( 11 , sys_mods , need_size , 0 );
		if ( !NT_SUCCESS ( status ) )
		{
			ExFreePoolWithTag ( sys_mods , tag );
			return false;
		}

		for ( unsigned long long i = 0; i < sys_mods->ulModuleCount; i++ )
		{
			PSYSTEM_MODULE mod = &sys_mods->Modules [ i ];
			if ( strstr ( mod->ImageName , name ) )
			{
				addr = ( DWORD64 ) mod->Base;
				size = ( DWORD32 ) mod->Size;
				break;
			}
		}

		ExFreePoolWithTag ( sys_mods , tag );

		return true;
	}

	bool pattern_check ( const char* data , const char* pattern , const char* mask )
	{
		size_t len = strlen ( mask );

		for ( size_t i = 0; i < len; i++ )
		{
			if ( data [ i ] == pattern [ i ] || mask [ i ] == '?' )
				continue;
			else
				return false;
		}

		return true;
	}

	DWORD64 find_pattern ( DWORD64 addr , DWORD32 size , const char* pattern , const char* mask )
	{
		size -= ( DWORD32 ) strlen ( mask );

		for ( DWORD32 i = 0; i < size; i++ )
		{
			if ( pattern_check ( ( const char* ) addr + i , pattern , mask ) )
				return addr + i;
		}

		return 0;
	}

	PVOID FindPattern ( PVOID base , int length , const char* pattern , const char* mask )
	{
		length -= static_cast< int >( SPOOF_CALL ( size_t __cdecl , strlen )( mask ) );
		for ( auto i = 0; i <= length; ++i ) {
			const auto* data = static_cast< char* >( base );
			const auto* address = &data [ i ];
			if ( pattern_check ( address , pattern , mask ) )
				return PVOID ( address );
		}
		return nullptr;
	}

	PVOID FindPatternImage ( PVOID base , const char* pattern , const char* mask )
	{
		PVOID match = nullptr;

		auto* headers = reinterpret_cast< PIMAGE_NT_HEADERS >( static_cast< char* >( base ) + static_cast< PIMAGE_DOS_HEADER >( base )->e_lfanew );
		auto* sections = IMAGE_FIRST_SECTION ( headers );

		for ( auto i = 0; i < headers->FileHeader.NumberOfSections; ++i ) {
			auto* section = &sections [ i ];
			if ( 'EGAP' == *reinterpret_cast< PINT > ( section->Name ) || SPOOF_CALL ( int __cdecl , memcmp )( section->Name , ".text" , 5 ) == 0 ) {
				match = FindPattern ( static_cast< char* > ( base ) + section->VirtualAddress , section->Misc.VirtualSize , pattern , mask );
				if ( match )
					break;
			}
		}
		return match;
	}


	BOOLEAN IsAlpha ( CHAR c ) {
		return ( c >= 'a' && c <= 'z' ) || ( c >= 'A' && c <= 'Z' );
	}

	VOID ModifyString ( PCHAR str ) {
		if ( str == NULL ) {
			return;
		}
		size_t len = strlen ( str );
		for ( size_t i = 0; i < len; i += 2 ) {
			char newChar;
			if ( IsAlpha ( str [ i ] ) ) {

				if ( isupper ( str [ i ] ) ) {
					newChar = toupper ( 'a' + rand ( ) % 26 );
					str [ i ] = newChar;
				}
				else {
					newChar = 'a' + rand ( ) % 26;
					str [ i ] = newChar;
				}
			}
			else if ( isdigit ( str [ i ] ) ) {
				char newChar = '0' + rand ( ) % 10;
				str [ i ] = newChar;
			}
		}
	}


	PVOID GetModuleBase ( const char* moduleName )
	{

		PVOID address = nullptr;
		ULONG size = 0;

		auto status = ( ZwQuerySystemInformation ) ( SystemModuleInformation , &size , 0 , &size );
		if ( status != STATUS_INFO_LENGTH_MISMATCH )
			return nullptr;

		auto* moduleList = static_cast< PSYSTEM_MODULE_INFORMATION >( SPOOF_CALL ( PVOID __stdcall , ExAllocatePoolWithTag )( NonPagedPool , ( size * 2 ) , 'MNML' ) );
		if ( !moduleList )
			return nullptr;

		status = ( ZwQuerySystemInformation ) ( SystemModuleInformation , moduleList , size , nullptr );
		if ( !NT_SUCCESS ( status ) )
			goto end;

		for ( auto i = 0; i < moduleList->ulModuleCount; i++ ) {
			auto module = moduleList->Modules [ i ];
			if ( strstr ( module.ImageName , moduleName ) ) {
				address = module.Base;
				break;
			}
		}

	end:
		SPOOF_CALL ( void , ExFreePoolWithTag )( moduleList , 'MNML' );
		return address;
	}


	ULONG GetModuleSize ( const char* moduleName )
	{

		ULONG address = 0;
		ULONG size = 0;

		auto status = ( ZwQuerySystemInformation ) ( SystemModuleInformation , &size , 0 , &size );
		if ( status != STATUS_INFO_LENGTH_MISMATCH )
			return 0;

		auto* moduleList = static_cast< PSYSTEM_MODULE_INFORMATION >( SPOOF_CALL ( PVOID __stdcall , ExAllocatePoolWithTag )( NonPagedPool , ( size * 2 ) , 'MNML' ) );
		if ( !moduleList )
			return 0;

		status = ( ZwQuerySystemInformation ) ( SystemModuleInformation , moduleList , size , nullptr );
		if ( !NT_SUCCESS ( status ) )
			goto end;

		for ( auto i = 0; i < moduleList->ulModuleCount; i++ ) {
			auto module = moduleList->Modules [ i ];
			if ( strstr ( module.ImageName , moduleName ) ) {
				address = module.Size;
				break;
			}
		}

	end:
		SPOOF_CALL ( void , ExFreePoolWithTag )( moduleList , 'MNML' );
		return address;
	}


	PDRIVER_DISPATCH add_irp_hook ( const wchar_t* name , PDRIVER_DISPATCH new_func )
	{
		UNICODE_STRING str;
		RtlInitUnicodeString ( &str , name );

		PDRIVER_OBJECT driver_object = 0;
		NTSTATUS status = ObReferenceObjectByName ( &str , OBJ_CASE_INSENSITIVE , 0 , 0 , *IoDriverObjectType , KernelMode , 0 , ( void** ) &driver_object );
		if ( !NT_SUCCESS ( status ) ) return 0;

		PDRIVER_DISPATCH old_func = driver_object->MajorFunction [ IRP_MJ_DEVICE_CONTROL ];
		driver_object->MajorFunction [ IRP_MJ_DEVICE_CONTROL ] = new_func;

		ObDereferenceObject ( driver_object );

		return old_func;
	}

	PDRIVER_DISPATCH add_irp_hook_ex ( const wchar_t* name , UCHAR majorFunction , PDRIVER_DISPATCH new_func )
	{
		UNICODE_STRING str;
		RtlInitUnicodeString ( &str , name );

		PDRIVER_OBJECT driver_object = 0;
		NTSTATUS status = ObReferenceObjectByName ( &str , OBJ_CASE_INSENSITIVE , 0 , 0 , *IoDriverObjectType , KernelMode , 0 , ( void** ) &driver_object );
		if ( !NT_SUCCESS ( status ) ) return 0;

		PDRIVER_DISPATCH old_func = driver_object->MajorFunction [ majorFunction ];
		driver_object->MajorFunction [ majorFunction ] = new_func;

		ObDereferenceObject ( driver_object );

		return old_func;
	}

	bool del_irp_hook ( const wchar_t* name , PDRIVER_DISPATCH old_func )
	{
		UNICODE_STRING str;
		RtlInitUnicodeString ( &str , name );

		PDRIVER_OBJECT driver_object = 0;
		NTSTATUS status = ObReferenceObjectByName ( &str , OBJ_CASE_INSENSITIVE , 0 , 0 , *IoDriverObjectType , KernelMode , 0 , ( void** ) &driver_object );
		if ( !NT_SUCCESS ( status ) ) return false;

		if ( old_func )
		{
			driver_object->MajorFunction [ IRP_MJ_DEVICE_CONTROL ] = old_func;
		}

		ObDereferenceObject ( driver_object );

		return true;
	}

	bool change_ioc ( PIO_STACK_LOCATION ioc , PIRP irp , PIO_COMPLETION_ROUTINE routine )
	{
		PIOC_REQUEST request = ( PIOC_REQUEST ) ExAllocatePool ( NonPagedPool , sizeof ( IOC_REQUEST ) );
		if ( request == 0 ) return false;

		request->Buffer = irp->AssociatedIrp.SystemBuffer;
		request->BufferLength = ioc->Parameters.DeviceIoControl.OutputBufferLength;
		request->OldContext = ioc->Context;

		// Only save the old completion routine if it was actually active
		// (Control flags indicate it should be invoked). Otherwise the
		// CompletionRoutine pointer may be stale/garbage and calling it
		// causes MULTIPLE_IRP_COMPLETE_REQUESTS (bugcheck 0x44).
		if ( ioc->Control & ( SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL ) )
			request->OldRoutine = ioc->CompletionRoutine;
		else
			request->OldRoutine = nullptr;

		request->DataMdl = nullptr;

		// Invoke on all outcomes so we always free IOC_REQUEST and DataMdl
		ioc->Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
		ioc->Context = request;
		ioc->CompletionRoutine = routine;

		return true;
	}


	ULONG KeMessageBox ( PCWSTR title , PCWSTR text , ULONG_PTR type )
	{
		UNICODE_STRING uTitle = { 0 };
		UNICODE_STRING uText = { 0 };

		RtlInitUnicodeString ( &uTitle , title );
		RtlInitUnicodeString ( &uText , text );

		ULONG_PTR args [ ] = { ( ULONG_PTR ) &uText, ( ULONG_PTR ) &uTitle, type };
		ULONG response = 0;

		ExRaiseHardError ( STATUS_SERVICE_NOTIFICATION , 3 , 3 , args , 2 , &response );
		return response;
	}

	NTSTATUS DeleteKeyValues ( HANDLE KeyHandle ) {
		NTSTATUS status;
		PVOID buffer;
		ULONG bufferSize = 0x1000;
		ULONG index = 0;

		buffer = ExAllocatePoolWithTag ( PagedPool , bufferSize , 'kTag' );
		if ( buffer == NULL ) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		while ( TRUE ) {
			PKEY_VALUE_BASIC_INFORMATION valueInfo = ( PKEY_VALUE_BASIC_INFORMATION ) buffer;
			ULONG resultLength;

			status = ZwEnumerateValueKey ( KeyHandle , index , KeyValueBasicInformation , valueInfo , bufferSize , &resultLength );
			if ( status == STATUS_NO_MORE_ENTRIES ) {
				break;
			}
			else if ( !NT_SUCCESS ( status ) ) {
				ExFreePoolWithTag ( buffer , 'kTag' );
				return status;
			}

			UNICODE_STRING valueName;
			valueName.Length = valueInfo->NameLength;
			valueName.MaximumLength = valueInfo->NameLength;
			valueName.Buffer = valueInfo->Name;

			status = ZwDeleteValueKey ( KeyHandle , &valueName );
			if ( !NT_SUCCESS ( status ) ) {
				ExFreePoolWithTag ( buffer , 'kTag' );
				return status;
			}

			index++;
		}

		ExFreePoolWithTag ( buffer , 'kTag' );
		return STATUS_SUCCESS;
	}

	NTSTATUS DeleteRegistryKeyRecursively ( HANDLE KeyHandle ) {
		NTSTATUS status;
		PVOID buffer;
		ULONG bufferSize = 0x1000;
		ULONG index = 0;

		buffer = ExAllocatePoolWithTag ( PagedPool , bufferSize , 'kTag' );
		if ( buffer == NULL ) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		while ( TRUE ) {
			PKEY_BASIC_INFORMATION keyInfo = ( PKEY_BASIC_INFORMATION ) buffer;
			ULONG resultLength;

			status = ZwEnumerateKey ( KeyHandle , 0 , KeyBasicInformation , keyInfo , bufferSize , &resultLength );
			if ( status == STATUS_NO_MORE_ENTRIES ) {
				break;
			}
			else if ( !NT_SUCCESS ( status ) ) {
				ExFreePoolWithTag ( buffer , 'kTag' );
				return status;
			}

			UNICODE_STRING subKeyPath;
			subKeyPath.Length = keyInfo->NameLength;
			subKeyPath.MaximumLength = keyInfo->NameLength + sizeof ( WCHAR );
			subKeyPath.Buffer = ( PWCHAR ) ExAllocatePoolWithTag ( PagedPool , subKeyPath.MaximumLength , 'kTag' );
			if ( subKeyPath.Buffer == NULL ) {
				ExFreePoolWithTag ( buffer , 'kTag' );
				return STATUS_INSUFFICIENT_RESOURCES;
			}

			RtlCopyMemory ( subKeyPath.Buffer , keyInfo->Name , keyInfo->NameLength );
			subKeyPath.Buffer [ subKeyPath.Length / sizeof ( WCHAR ) ] = L'\0';

			OBJECT_ATTRIBUTES objectAttributes;
			HANDLE subKeyHandle;
			InitializeObjectAttributes ( &objectAttributes , &subKeyPath , OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE , KeyHandle , NULL );
			//Utils::ChadPrint("Attempting to open subkey: %wZ\n", &subKeyPath);

			status = ZwOpenKey ( &subKeyHandle , KEY_ALL_ACCESS , &objectAttributes );
			if ( NT_SUCCESS ( status ) ) {
				status = DeleteRegistryKeyRecursively ( subKeyHandle );
				ZwClose ( subKeyHandle );
			}
			else {
			}

			ExFreePoolWithTag ( subKeyPath.Buffer , 'kTag' );
			if ( !NT_SUCCESS ( status ) ) {
				ExFreePoolWithTag ( buffer , 'kTag' );
				return status;
			}
		}

		status = DeleteKeyValues ( KeyHandle );
		if ( !NT_SUCCESS ( status ) ) {
			ExFreePoolWithTag ( buffer , 'kTag' );
			return status;
		}

		status = ZwDeleteKey ( KeyHandle );
		if ( !NT_SUCCESS ( status ) ) {
		}
		else {
		}

		ExFreePoolWithTag ( buffer , 'kTag' );
		return status;
	}

	NTSTATUS DeleteRegistryKey ( PUNICODE_STRING KeyPath ) {
		OBJECT_ATTRIBUTES objectAttributes;
		HANDLE keyHandle;
		NTSTATUS status;

		InitializeObjectAttributes ( &objectAttributes , KeyPath , OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE , NULL , NULL );

		status = ZwOpenKey ( &keyHandle , KEY_ALL_ACCESS , &objectAttributes );
		if ( !NT_SUCCESS ( status ) ) {
			return status;
		}


		status = DeleteRegistryKeyRecursively ( keyHandle );
		ZwClose ( keyHandle );

		return status;
	}

	void DeleteSubKeys ( PUNICODE_STRING ParentKeyPath ) {
		OBJECT_ATTRIBUTES objectAttributes;
		HANDLE parentKeyHandle;
		NTSTATUS status;

		InitializeObjectAttributes ( &objectAttributes , ParentKeyPath , OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE , NULL , NULL );

		status = ZwOpenKey ( &parentKeyHandle , KEY_ALL_ACCESS , &objectAttributes );
		if ( !NT_SUCCESS ( status ) ) {
			return;
		}


		status = DeleteRegistryKeyRecursively ( parentKeyHandle );
		ZwClose ( parentKeyHandle );
	}


}



namespace kmdf_communication
{
	ULONG GetKeyInfoSize ( HANDLE hKey , PUNICODE_STRING Key )
	{
		NTSTATUS Status;
		ULONG KeySize;

		Status = ZwQueryValueKey ( hKey , Key , KeyValueFullInformation , 0 , 0 , &KeySize );

		if ( Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW )
			return KeySize;

		return 0;
	}

	template <typename type> type ReadRegistry ( UNICODE_STRING RegPath , UNICODE_STRING Key )
	{
		HANDLE hKey;
		OBJECT_ATTRIBUTES ObjAttr;
		NTSTATUS Status = STATUS_UNSUCCESSFUL;

		InitializeObjectAttributes ( &ObjAttr , &RegPath , OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE , NULL , NULL );

		Status = ZwOpenKey ( &hKey , KEY_ALL_ACCESS , &ObjAttr );

		if ( NT_SUCCESS ( Status ) )
		{
			ULONG KeyInfoSize = GetKeyInfoSize ( hKey , &Key );
			ULONG KeyInfoSizeNeeded;

			if ( KeyInfoSize == NULL )
			{
				ZwClose ( hKey );
				return 0;
			}

			PKEY_VALUE_FULL_INFORMATION pKeyInfo = ( PKEY_VALUE_FULL_INFORMATION ) ExAllocatePool ( NonPagedPool , KeyInfoSize );
			RtlZeroMemory ( pKeyInfo , KeyInfoSize );

			Status = ZwQueryValueKey ( hKey , &Key , KeyValueFullInformation , pKeyInfo , KeyInfoSize , &KeyInfoSizeNeeded );

			if ( !NT_SUCCESS ( Status ) || ( KeyInfoSize != KeyInfoSizeNeeded ) )
			{
				ZwClose ( hKey );
				ExFreePoolWithTag ( pKeyInfo , 0 );
				return 0;
			}

			ZwClose ( hKey );
			ExFreePoolWithTag ( pKeyInfo , 0 );

			return *( type* ) ( ( LONG64 ) pKeyInfo + pKeyInfo->DataOffset );
		}

		return 0;
	}

	bool WriteRegistry ( UNICODE_STRING RegPath , UNICODE_STRING Key , PVOID Address , ULONG Type , ULONG Size )
	{
		bool Success = false;
		HANDLE hKey;
		OBJECT_ATTRIBUTES ObjAttr;
		NTSTATUS Status = STATUS_UNSUCCESSFUL;

		InitializeObjectAttributes ( &ObjAttr , &RegPath , OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE , NULL , NULL );

		Status = ZwOpenKey ( &hKey , KEY_ALL_ACCESS , &ObjAttr );

		if ( NT_SUCCESS ( Status ) )
		{
			Status = ZwSetValueKey ( hKey , &Key , NULL , Type , Address , Size );

			if ( NT_SUCCESS ( Status ) )
				Success = true;

			ZwClose ( hKey );
		}

		return Success;
	}
}