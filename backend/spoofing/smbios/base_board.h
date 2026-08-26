
#pragma once
#include "table_defines.h"
#include <stdlib.h>

// Local deterministic PRNG for SMBIOS — isolated from global rand() state
// Uses same LCG constants as MSVC CRT but with its own state variable
static ULONG g_smbiosRandState = 1;

static void smbios_srand(ULONG seed) {
	g_smbiosRandState = seed;
}

static int smbios_rand() {
	g_smbiosRandState = g_smbiosRandState * 214013 + 2531011;
	return (int)((g_smbiosRandState >> 16) & 0x7FFF);
}

void RandomText1 ( char* text , const int length )
{
	if ( !text || length <= 0 )
		return;

	static const char alphanum [ ] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	srand ( static_cast< unsigned int >( reinterpret_cast< uintptr_t >( &length ) ) );

	for ( int n = 0; n < length; ++n )
	{
		if ( text [ n ] == '_' || text [ n ] == '.' ) { 
			continue;
		}
		int key = rand ( ) % ( sizeof ( alphanum ) - 1 );
		text [ n ] = alphanum [ key ];
	}
}

void RandomizeStringa ( char* string )
{
	if ( !string )
		return;

	const auto length = static_cast< int >( strlen ( string ) );

	auto* buffer = static_cast< char* >( ExAllocatePoolWithTag ( NonPagedPool , length + 1 , POOL_TAG ) );
	if ( !buffer )
		return;

	RandomText1 ( buffer , length );

	for ( int i = 0; i < length; ++i ) {
		if ( ( string [ i ] >= 'A' && string [ i ] <= 'Z' ) || ( string [ i ] >= '0' && string [ i ] <= '9' ) ) {
			if ( isupper ( string [ i ] ) ) {
				buffer [ i ] = toupper ( buffer [ i ] );
			}
			else if ( isdigit ( string [ i ] ) ) {
				buffer [ i ] = '0' + ( buffer [ i ] % 10 );
			}
		}
		else {
			auto seed = KeQueryTimeIncrement ( );
			auto key = RtlRandomEx ( &seed ) % 36; 
			if ( key < 26 ) {
				buffer [ i ] = 'A' + key; 
			}
			else {
				buffer [ i ] = '0' + ( key - 26 ); 
			}
		}
	}

	memcpy ( string , buffer , length );
	string [ length ] = '\0';

	ExFreePool ( buffer );
}

char* GetString ( SMBIOS_HEADER* header , SMBIOS_STRING string )
{
	const auto* start = reinterpret_cast< const char* >( header ) + header->Length;

	if ( !string || *start == 0 )
		return nullptr;

	while ( --string ) {

		start += SPOOF_CALL ( size_t __cdecl , strlen )( start ) + 1;
	}

	return const_cast< char* >( start );
}

char* GetArray ( SMBIOS_HEADER* header , UINT8* array , size_t arraySize )
{
	const auto* start = reinterpret_cast< const char* >( header ) + header->Length;

	if ( !array || arraySize == 0 || *start == 0 )
		return nullptr;

	size_t currentIndex = 0;

	while ( currentIndex < arraySize - 1 ) {
		start += SPOOF_CALL ( size_t __cdecl , strlen )( start ) + 1;
		currentIndex++;

		if ( *start == 0 )
			return nullptr;
	}
	return const_cast< char* > ( start );
}

char* GetUInt16 ( SMBIOS_HEADER* header , UINT16& value )
{
	const auto* start = reinterpret_cast< const char* >( header ) + header->Length;

	if ( !start || *start == 0 )
		return nullptr;

	const UINT16* uint16Value = reinterpret_cast< const UINT16* >( start );

	value = *uint16Value;

	return const_cast< char* >( start );
}

char* GetUInt8 ( SMBIOS_HEADER* header , UINT8& value )
{
	const auto* start = reinterpret_cast< const char* >( header ) + header->Length;

	if ( !start || *start == 0 )
		return nullptr;

	const UINT8* uint16Value = reinterpret_cast< const UINT8* >( start );

	value = *uint16Value;

	return const_cast< char* >( start );
}

char* GetUInt32 ( SMBIOS_HEADER* header , UINT32& value )
{
	const auto* start = reinterpret_cast< const char* >( header ) + header->Length;

	if ( !start || *start == 0 )
		return nullptr;

	const UINT32* uint32Value = reinterpret_cast< const UINT32* >( start );

	value = *uint32Value;

	return const_cast< char* >( start );
}






void RandomText ( char* text , const int length ) {
	if ( !text )
		return;

	static const char alphanum [ ] = "0123456789ABCDEF";

	for ( int n = 0; n < length; n++ ) {
		int key = smbios_rand ( ) % ( sizeof ( alphanum ) - 1 );
		text [ n ] = alphanum [ key ];
	}

	text [ length ] = '\0';
}




void RandomizeString(char* string)
{
	if (string == NULL) { // fixed comparison
		return;
	}

	const int length = static_cast<int>(strlen(string));
	if (length <= 3) {
		return;
	}

	auto* buffer = static_cast<char*>(
		SPOOF_CALL(PVOID __stdcall, ExAllocatePoolWithTag)(
			NonPagedPool,
			length,
			'mnml'
			)
		);

	if (!buffer) {
		return;
	}

	for (int i = 0; i < 3; ++i) {
		buffer[i] = string[i];
	}

	// Find the end of meaningful content (trim trailing spaces)
	int trimLen = length;
	while (trimLen > 3 && string[trimLen - 1] == ' ') trimLen--;

	static const char alphanum[] = "0123456789ABCDEF";
	for (int i = 3; i < length; ++i) {
		// Preserve special characters and trailing spaces
		if (string[i] == '_' || string[i] == '-' || string[i] == '.' || string[i] == ' ' || i >= trimLen) {
			buffer[i] = string[i];
		}
		else {
			int key = smbios_rand() % (sizeof(alphanum) - 1);
			buffer[i] = alphanum[key];
		}
	}

	MemoryCopySafe(string, buffer, length);
	BYTE* Bytes = reinterpret_cast<BYTE*>(buffer);
	WriteToProtectedMem(string, Bytes, length);

	SPOOF_CALL(void, ExFreePoolWithTag)(buffer, 'mnml');
}



void RandomizeGuid(GUID& guid)
{
	for (size_t i = 8; i < sizeof(GUID); ++i) {
		reinterpret_cast<BYTE*>(&guid)[i] = static_cast<BYTE>(smbios_rand());
	}
}

void RandomizeArray ( UINT8* array , size_t size )
{
	if ( !array )
		return;

	for ( size_t i = 0; i < size; ++i ) {
		array [ i ] = static_cast< UINT8 > ( smbios_rand ( ) % 256 );
	}
}

void RandomizeUInt32 ( UINT32& value )
{
	value = (UINT32)smbios_rand();
}

void RandomizeUInt16 ( UINT16& value ) {
	value = static_cast< UINT16 >( smbios_rand ( ) );
}

void RandomizeUInt8 ( UINT8& value ) {
	value = static_cast< UINT8 >( smbios_rand ( ) );
}

char* GetGuid ( SMBIOS_HEADER* header , GUID& value ) {
	if ( !header )
		return nullptr;

	size_t guidOffset = sizeof ( SMBIOS_HEADER );

	const auto* start = reinterpret_cast< const char* >( header ) + guidOffset;

	if ( guidOffset + sizeof ( GUID ) <= header->Length ) {
		const GUID* guidValue = reinterpret_cast< const GUID* >( start );

		value = *guidValue;

		return const_cast< char* >( start );
	}

	return nullptr;
}


void spoof_boot_uuid ( )
{

	NTSTATUS status = STATUS_SUCCESS;
	ULONG neededSize = 0;

	neededSize = 8 * 1024 * 1024;

	PSYSTEM_BOOT_ENVIRONMENT_INFORMATION pBootInfo;

	if ( pBootInfo = ( decltype( pBootInfo ) ) ExAllocatePoolWithTag ( NonPagedPool , neededSize , POOL_TAG ) ) {

		NTSTATUS r;
		SystemBootEnvironmentInformation;
		if ( NT_SUCCESS ( r = ZwQuerySystemInformation ( SystemBootEnvironmentInformation , pBootInfo , neededSize , 0 ) ) ) {
			DbgPrint ( "boot GUID: %08X-%04X-%04X-%02X%02X%02X%02X%02X%02X%02X%02X\n" , pBootInfo->BootIdentifier.Data1 , pBootInfo->BootIdentifier.Data2 , pBootInfo->BootIdentifier.Data3 , pBootInfo->BootIdentifier.Data4 [ 0 ] , pBootInfo->BootIdentifier.Data4 [ 1 ] , pBootInfo->BootIdentifier.Data4 [ 2 ] , pBootInfo->BootIdentifier.Data4 [ 3 ] , pBootInfo->BootIdentifier.Data4 [ 4 ] , pBootInfo->BootIdentifier.Data4 [ 5 ] , pBootInfo->BootIdentifier.Data4 [ 6 ] , pBootInfo->BootIdentifier.Data4 [ 7 ] );

			GUID newGuid;
			ExUuidCreate ( &newGuid );
			pBootInfo->BootIdentifier = newGuid;
			ExFreePoolWithTag ( pBootInfo , POOL_TAG );
		}
		else
			DbgPrint ( "r = %x\n" , r );
	}
}


NTSTATUS ProcessTable ( SMBIOS_HEADER* header )
{
	if ( !header->Length )
	{
		DbgPrintEx ( 0 , 0 , oxorany ( "INVALID SMBIOS LENGTH!\n") );
		return STATUS_UNSUCCESSFUL;
	}
	if ( header->Type == 1 )
	{
		DbgPrintEx ( 0 , 0 , oxorany ( "[KDW11S] Found Smbios Table : 1\n") );

		auto* type1 = reinterpret_cast< SMBIOS_TYPE1* >( header );

		auto* SerialNumber = GetString ( header , type1->SerialNumber );
		if ( SerialNumber != NULL )
		{
			if ( strcmp ( SerialNumber , oxorany  ( "Default string" ) ) != 0 && strcmp ( SerialNumber , oxorany("To Be Filled By O.E.M." ) ) != 0 && strcmp ( SerialNumber , oxorany ( "System Serial Number" ) ) != 0 )
			{
				RandomizeString ( SerialNumber );
			}
		}

		auto* Uuid = GetGuid ( header , type1->Uuid );
		if ( Uuid != NULL )
		{
			RandomizeGuid ( type1->Uuid );
		}
	}
	if ( header->Type == 2 )
	{
		DbgPrintEx ( 0 , 0 , oxorany ( "[KDW11S] Found Smbios Table : 2\n") );

		auto* type2 = reinterpret_cast< SMBIOS_TYPE2* >( header );

		auto* SerialNumber = GetString ( header , type2->SerialNumber );

		if ( SerialNumber != NULL )
		{
			DbgPrintEx ( 0 , 0 , oxorany ( "[KDW11S] Motherboard Serial Before : %s\n" ) , SerialNumber );
			if ( strcmp ( SerialNumber , oxorany ( "Default string" ) ) != 0 && strcmp ( SerialNumber , oxorany ( "To Be Filled By O.E.M." ) ) != 0 && strcmp ( SerialNumber , oxorany ( "System Serial Number" ) ) != 0 )
			{
				RandomizeString ( SerialNumber );
			}
			DbgPrintEx ( 0 , 0 , oxorany ( "[KDW11S] Motherboard Serial After  : %s\n" ) , SerialNumber );
		}
	}
	if ( header->Type == 3 )
	{
		DbgPrintEx ( 0 , 0 , oxorany ( "[KDW11S] Found Smbios Table : 3\n" ));

		auto* type3 = reinterpret_cast< SMBIOS_TYPE3* >( header );

		auto* SerialNumber = GetString ( header , type3->SerialNumber );
		if ( SerialNumber != NULL )
		{
			if ( strcmp ( SerialNumber , oxorany ( "Default string") ) != 0 && strcmp ( SerialNumber , oxorany ( "To Be Filled By O.E.M.") ) != 0 && strcmp ( SerialNumber , oxorany ( "System Serial Number") ) != 0 )
			{
				RandomizeString ( SerialNumber );
			}
		}
	}
	if ( header->Type == 17 )
	{

		DbgPrintEx(0, 0, "[KDW11S] Found Smbios Table : 17\n");

		auto* type17 = reinterpret_cast<SMBIOS_TYPE17*>(header);

		auto* SerialNumber = GetString(header, type17->SerialNumber);
		if (SerialNumber != NULL)
		{
			RandomizeString(SerialNumber);
		}

		auto* PartNumber = GetString(header, type17->PartNumber);
		if (PartNumber != NULL)
		{
			RandomizeString(PartNumber);
		}
	}
	if ( header->Type == 43 )
	{
		DbgPrintEx ( 0 , 0 , oxorany ("[KDW11S] Found Smbios Table : 43\n") );

		auto* type43 = reinterpret_cast< SMBIOS_TYPE43* >( header );
		auto* VendorID = GetUInt32 ( header , type43->VendorID );
		RandomizeUInt32 ( type43->VendorID );
	}
	if ( header->Type == 4 )
	{
		DbgPrintEx ( 0 , 0 , oxorany ( "[KDW11S] Found Smbios Table : 4\n") );

		auto* type4 = reinterpret_cast< SMBIOS_TYPE4* >( header );

		auto* SerialNumber = GetString ( header , type4->SerialNumber );


		if ( SerialNumber != NULL )
		{
			//if ( strcmp ( SerialNumber , ( "To Be Filled By O.E.M.") ) != 0 || strcmp ( SerialNumber , ( "Unknown" ) ) != 0 )
			//{
			//}
			strcpy(SerialNumber, ("To Be Filled By O.E.M."));
		}

		auto* PartNumber = GetString ( header , type4->PartNumber );
		if ( PartNumber != NULL )
		{
			//if ( strcmp ( SerialNumber , ( "To Be Filled By O.E.M.") ) != 0 || strcmp ( SerialNumber , ( "Unknown" ) ) != 0 )
			//{
			//}
			strcpy(PartNumber, ("To Be Filled By O.E.M."));
		}

	}



	return STATUS_SUCCESS;
}


NTSTATUS LoopTables ( void* mapped , ULONG size ) {
	if ( !mapped || size == 0 )
		return STATUS_INVALID_PARAMETER;

	// Seed the SMBIOS PRNG from the global hwid_seed — deterministic across reboots
	smbios_srand(kmdf_settings::hwid_seed ^ 0x534D4249); // 'SMBI'

	char* current = static_cast< char* >( mapped );
	char* endAddress = current + size;

	while ( current + sizeof ( SMBIOS_HEADER ) <= endAddress ) {
		SMBIOS_HEADER* header = reinterpret_cast< SMBIOS_HEADER* >( current );

 		if ( header->Length < sizeof ( SMBIOS_HEADER ) )
			break;

		if ( current + header->Length > endAddress )
			break;

		if ( header->Type == 127 ) {
			ProcessTable ( header );
			break;
		}

		ProcessTable ( header );

		current += header->Length;

		bool foundTerminator = false;
		while ( current + 1 < endAddress ) {
			if ( *current == 0 && *( current + 1 ) == 0 ) {
				current += 2;  
				foundTerminator = true;
				break;
			}
			current++;
		}

		if ( !foundTerminator ) {
			break;
		}

		if ( current >= endAddress ) {
			break;
		}
	}

	return STATUS_SUCCESS;
}



struct reg_mobo_ {
	auto write_reg ( void* mapped , ULONG size ) -> NTSTATUS {
		HANDLE KeyHandle = NULL;
		OBJECT_ATTRIBUTES ObjAttr;

		UNICODE_STRING uRegistryPath;
		RtlInitUnicodeString ( &uRegistryPath , oxorany ( L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data") );

		InitializeObjectAttributes ( &ObjAttr ,
			&uRegistryPath ,
			OBJ_KERNEL_HANDLE ,
			NULL , NULL );

		NTSTATUS Status = ZwOpenKey ( &KeyHandle ,
			KEY_ALL_ACCESS ,
			&ObjAttr );

		if ( NT_SUCCESS ( Status ) )
		{
			UNICODE_STRING uKeyName;
			RtlInitUnicodeString ( &uKeyName , oxorany ( L"SMBiosData" ) );

			Status = ZwSetValueKey ( KeyHandle ,
				&uKeyName ,
				0 ,
				REG_BINARY ,
				mapped ,
				size );

			ZwClose ( KeyHandle );
		}

		return Status;
	}
};

reg_mobo_ registry_motherboard;







ULONG CryptographicHash ( ULONG input ) {
	input = ( input ^ ( input >> 16 ) ) * 0x45D9F3B;
	input = ( input ^ ( input >> 16 ) ) * 0x45D9F3B;
	input = input ^ ( input >> 16 );
	return input;
}



struct registry_spoofing_ {

	auto GenerateSerialString ( ULONG seed , CHAR* output , SIZE_T size , const CHAR* charset ) -> VOID {
		if ( !output || size == 0 ) return;

		RtlZeroMemory ( output , size );
		ULONG localSeed = seed;
		SIZE_T charsetLen = 0;
		if ( charset ) {
			const CHAR* ptr = charset;
			while ( *ptr != '\0' ) {
				charsetLen++;
				ptr++;
			}
		}
		if ( charsetLen == 0 ) {
			output [ 0 ] = '\0';
			return;
		}

		for ( SIZE_T i = 0; i < size - 1; i++ ) {
			localSeed = CryptographicHash ( localSeed ^ i );
			output [ i ] = charset [ localSeed % charsetLen ];
		}

		output [ size - 1 ] = '\0';
	}
	void FreeMemory ( PVOID memory ) {
		if ( memory ) {
			__try {
				ExFreePool ( memory );
			}
			__except ( EXCEPTION_EXECUTE_HANDLER ) {
			}
		}
	}


	void CleanupUnicodeStr ( UNICODE_STRING* unicodeStr ) {
		if ( unicodeStr && unicodeStr->Buffer ) {
			FreeMemory ( unicodeStr->Buffer );
			unicodeStr->Buffer = nullptr;
			unicodeStr->Length = 0;
			unicodeStr->MaximumLength = 0;
		}
	}

	PVOID AllocateMemory ( SIZE_T size ) {
		PVOID memory = nullptr;

		__try {
			memory = ExAllocatePool2 ( POOL_FLAG_NON_PAGED , size , 'SMBI' );
		}
		__except ( EXCEPTION_EXECUTE_HANDLER ) {
			return nullptr;
		}

		return memory;
	}

	SIZE_T StringLength ( const char* str ) {
		if ( !str ) return 0;
		SIZE_T len = 0;
		while ( str [ len ] != '\0' ) len++;
		return len;
	}


	void InitUnicodeStr ( UNICODE_STRING* unicodeStr , PCWSTR wideStr ) {
		if ( !unicodeStr || !wideStr ) return;

		SIZE_T len = 0;
		while ( wideStr [ len ] != L'\0' ) len++;

		unicodeStr->Buffer = const_cast< PWCH >( wideStr );
		unicodeStr->Length = ( USHORT ) ( len * sizeof ( WCHAR ) );
		unicodeStr->MaximumLength = unicodeStr->Length + sizeof ( WCHAR );
	}

	NTSTATUS AnsiToUnicodeCustom ( PCSTR ansiStr , UNICODE_STRING* unicodeStr ) {
		if ( !ansiStr || !unicodeStr ) return STATUS_INVALID_PARAMETER;

		SIZE_T ansiLen = StringLength ( ansiStr );
		SIZE_T unicodeLen = ( ansiLen + 1 ) * sizeof ( WCHAR );

		unicodeStr->Buffer = ( PWCH ) AllocateMemory ( unicodeLen );
		if ( !unicodeStr->Buffer ) return STATUS_INSUFFICIENT_RESOURCES;

		unicodeStr->MaximumLength = ( USHORT ) unicodeLen;

		for ( SIZE_T i = 0; i < ansiLen; i++ ) {
			unicodeStr->Buffer [ i ] = ( WCHAR ) ansiStr [ i ];
		}
		unicodeStr->Buffer [ ansiLen ] = L'\0';
		unicodeStr->Length = ( USHORT ) ( ansiLen * sizeof ( WCHAR ) );

		return STATUS_SUCCESS;
	}

	auto spoof ( ) -> NTSTATUS {
		char  new_product_id [ 64 ] = { 0 };
		GenerateSerialString ( ( ULONG ) &kmdf_settings::hwid_seed , new_product_id , sizeof ( new_product_id ) , oxorany ( "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" ) );

		for ( int i = 5; i < 20; i += 6 ) {
			if ( i < 19 ) {
				memmove ( &new_product_id [ i + 1 ] , &new_product_id [ i ] , 19 - i );
				new_product_id [ i ] = '-';
			}
		}

		new_product_id [ 19 ] = '\0';

		NTSTATUS status = STATUS_SUCCESS;
		HANDLE hKey = NULL;

		const wchar_t* registry_paths [ ] = {
			oxorany ( L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ),
			oxorany ( L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion" ),
			oxorany ( L"\\Registry\\Machine\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion" )
		};

		BOOLEAN success = FALSE;

		UNICODE_STRING unicodeProductId;
		status = AnsiToUnicodeCustom ( new_product_id , &unicodeProductId );
		if ( !NT_SUCCESS ( status ) ) {
			return status;
		}

		for ( int path_idx = 0; path_idx < 3; path_idx++ ) {
			UNICODE_STRING keyPath;
			OBJECT_ATTRIBUTES objectAttributes;

			InitUnicodeStr ( &keyPath , registry_paths [ path_idx ] );

			InitializeObjectAttributes ( &objectAttributes , &keyPath , OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE , NULL , NULL );

			status = ZwOpenKey ( &hKey , KEY_SET_VALUE | KEY_WRITE , &objectAttributes );
			if ( !NT_SUCCESS ( status ) ) {
				continue;
			}

			UNICODE_STRING valueName;
			InitUnicodeStr ( &valueName , L"ProductId" );

			status = ZwSetValueKey ( hKey , &valueName , 0 , REG_SZ , unicodeProductId.Buffer , unicodeProductId.Length + sizeof ( WCHAR ) );
			if ( NT_SUCCESS ( status ) ) {
				success = TRUE;
			}
			ZwClose ( hKey );
			hKey = NULL;
		}

		CleanupUnicodeStr ( &unicodeProductId );

		if ( !success ) {
			return STATUS_ACCESS_DENIED;
		}
		return STATUS_SUCCESS;

	}
};

registry_spoofing_ registry;




typedef struct _IOC_REQUEST
{
	PVOID Buffer;
	ULONG Size;
	PVOID OriginalContext;
	PIO_COMPLETION_ROUTINE Original;
} IOC_REQUEST , * PIOC_REQUEST;



#define IOCTL_TPM_SUBMIT_COMMAND 0x22C00C

#pragma pack(push, 1)
// Page 71
// https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part3_Commands_pub.pdf
typedef struct _TPM_DATA_READ_PUBLIC
{
	TPM2_RESPONSE_HEADER Header;
	TPM2B_PUBLIC OutPublic;
} TPM_DATA_READ_PUBLIC;
#pragma pack(pop)

char* Compare ( const char* haystack , const char* needle )
{
	do
	{
		const char* h = haystack;
		const char* n = needle;
		while ( tolower ( static_cast< unsigned char >( *h ) ) == tolower ( static_cast< unsigned char >( *n ) ) && *n )
		{
			h++;
			n++;
		}

		if ( *n == 0 )
			return const_cast< char* >( haystack );
	} while ( *haystack++ );
	return nullptr;
}

PVOID GetModuleBase ( const char* moduleName )
{
	PVOID address = nullptr;
	ULONG size = 0;

	NTSTATUS status = ZwQuerySystemInformation ( SystemModuleInformation , &size , 0 , &size );
	if ( status != STATUS_INFO_LENGTH_MISMATCH )
		return nullptr;

#pragma warning(disable : 4996) // 'ExAllocatePool': ExAllocatePool is deprecated, use ExAllocatePool2
	PSYSTEM_MODULE_INFORMATION moduleList = static_cast< PSYSTEM_MODULE_INFORMATION >( ExAllocatePool ( NonPagedPool , size ) );
	if ( !moduleList )
		return nullptr;

	status = ZwQuerySystemInformation ( SystemModuleInformation , moduleList , size , nullptr );
	if ( !NT_SUCCESS ( status ) )
		goto end;

	for ( ULONG_PTR i = 0; i < moduleList->ulModuleCount; i++ )
	{
		ULONG64 pointer = reinterpret_cast< ULONG64 > ( &moduleList->Modules [ i ] );
		pointer += sizeof ( SYSTEM_MODULE );
		if ( pointer > ( reinterpret_cast< ULONG64 >( moduleList ) + size ) )
			break;

		SYSTEM_MODULE module = moduleList->Modules [ i ];
		module.ImageName [ 255 ] = '\0';
		if ( Compare ( module.ImageName , moduleName ) )
		{
			address = module.Base;
			break;
		}
	}

end:
	ExFreePool ( moduleList );
	return address;
}

#define IN_RANGE(x, a, b) (x >= a && x <= b)
#define GET_BITS(x) (IN_RANGE((x&(~0x20)),'A','F')?((x&(~0x20))-'A'+0xA):(IN_RANGE(x,'0','9')?x-'0':0))
#define GET_BYTE(a, b) (GET_BITS(a) << 4 | GET_BITS(b))
ULONG64 FindPattern ( void* baseAddress , ULONG64 size , const char* pattern )
{
	BYTE* firstMatch = nullptr;
	const char* currentPattern = pattern;

	BYTE* start = static_cast< BYTE* >( baseAddress );
	BYTE* end = start + size;

	for ( BYTE* current = start; current < end; current++ )
	{
		BYTE byte = currentPattern [ 0 ]; if ( !byte ) return reinterpret_cast< ULONG64 > ( firstMatch );
		if ( byte == '\?' || *static_cast< BYTE* > ( current ) == GET_BYTE ( byte , currentPattern [ 1 ] ) )
		{
			if ( !firstMatch ) firstMatch = current;
			if ( !currentPattern [ 2 ] ) return reinterpret_cast< ULONG64 > ( firstMatch );
			( ( byte == '\?' ) ? ( currentPattern += 2 ) : ( currentPattern += 3 ) );
		}
		else
		{
			currentPattern = pattern;
			firstMatch = nullptr;
		}
	}

	return 0;
}

ULONG64 FindPatternImage ( void* base , const char* pattern )
{
	ULONG64 match = 0;

	PIMAGE_NT_HEADERS64 headers = reinterpret_cast< PIMAGE_NT_HEADERS64 >( reinterpret_cast< ULONG64 >( base ) + static_cast< PIMAGE_DOS_HEADER >( base )->e_lfanew );
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION ( headers );
	for ( USHORT i = 0; i < headers->FileHeader.NumberOfSections; ++i )
	{
		PIMAGE_SECTION_HEADER section = &sections [ i ];
		if ( memcmp ( section->Name , ".text" , 5 ) == 0 || *reinterpret_cast< DWORD32* > ( section->Name ) == 'EGAP' )
		{
			match = FindPattern ( reinterpret_cast< void* > ( reinterpret_cast< ULONG64 > ( base ) + section->VirtualAddress ) , section->Misc.VirtualSize , pattern );
			if ( match )
				break;
		}
	}

	return match;
}


bool IsInRange ( ULONG64 start , SIZE_T size , ULONG64 input )
{
	return ( input > start && input < start + size );
}

void tpm_change_ioc ( PIO_STACK_LOCATION ioc , PIRP irp , PIO_COMPLETION_ROUTINE routine )
{
	PIOC_REQUEST request = static_cast< PIOC_REQUEST > ( ExAllocatePool ( NonPagedPool , sizeof ( IOC_REQUEST ) ) );

	request->Buffer = irp->AssociatedIrp.SystemBuffer;
	request->Size = ioc->Parameters.DeviceIoControl.OutputBufferLength;
	request->OriginalContext = ioc->Context;
	request->Original = ioc->CompletionRoutine;

	ioc->Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
	ioc->Context = request;
	ioc->CompletionRoutine = routine;
}

//
// Dynamic parser for TPM2_ReadPublic response.
// TPM2 uses variable-length marshalling — fixed struct overlays are wrong.
// This walks the response byte by byte to find the RSA modulus.
//
static __forceinline BYTE* FindRsaModulusInReadPublic(
	BYTE* response, ULONG responseLen, UINT16* pModulusSize)
{
	ULONG pos = 0;

	auto ReadU16 = [&]() -> UINT16 {
		UINT16 v = ((UINT16)response[pos] << 8) | response[pos + 1];
		pos += 2;
		return v;
	};

	auto ReadU32 = [&]() -> UINT32 {
		UINT32 v = ((UINT32)response[pos] << 24) | ((UINT32)response[pos + 1] << 16) |
			((UINT32)response[pos + 2] << 8) | response[pos + 3];
		pos += 4;
		return v;
	};

	// 1. Response header: tag(2) + paramSize(4) + responseCode(4) = 10 bytes
	if (responseLen < 10) return nullptr;
	pos += 2; // skip tag
	UINT32 paramSize = ReadU32();
	UINT32 rc = ReadU32();
	if (rc != 0) return nullptr;

	ULONG bounds = (paramSize < responseLen) ? paramSize : responseLen;

	// 2. TPM2B_PUBLIC: size(2)
	if (pos + 2 > bounds) return nullptr;
	ReadU16(); // publicSize (we parse fields individually)

	// 3. TPMT_PUBLIC: type(2) + nameAlg(2) + objectAttributes(4)
	if (pos + 8 > bounds) return nullptr;
	UINT16 algType = ReadU16();
	pos += 6; // skip nameAlg + objectAttributes
	if (algType != 0x0001) return nullptr; // TPM_ALG_RSA

	// 4. authPolicy: size(2) + buffer[size]
	if (pos + 2 > bounds) return nullptr;
	UINT16 authPolicySize = ReadU16();
	if (pos + authPolicySize > bounds) return nullptr;
	pos += authPolicySize;

	// 5. TPMS_RSA_PARMS:
	//    symmetric: algorithm(2) [+ keyBits(2) + mode(2)]
	if (pos + 2 > bounds) return nullptr;
	UINT16 symAlg = ReadU16();
	if (symAlg != 0x0010) { // not TPM_ALG_NULL
		if (pos + 4 > bounds) return nullptr;
		pos += 4;
	}
	//    scheme: scheme(2) [+ hashAlg(2)]
	if (pos + 2 > bounds) return nullptr;
	UINT16 schemeAlg = ReadU16();
	if (schemeAlg != 0x0010) { // not TPM_ALG_NULL
		if (pos + 2 > bounds) return nullptr;
		pos += 2;
	}
	//    keyBits(2) + exponent(4)
	if (pos + 6 > bounds) return nullptr;
	pos += 6;

	// 6. unique: size(2) + buffer[size]
	if (pos + 2 > bounds) return nullptr;
	UINT16 modulusSize = ReadU16();
	if (pos + modulusSize > bounds) return nullptr;

	if (pModulusSize) *pModulusSize = modulusSize;
	return response + pos;
}

UINT32 BigEndianToLittleEndian32 ( UINT32 bigEndianValue )
{
	return ( ( bigEndianValue >> 24 ) & 0x000000FF ) |
		( ( bigEndianValue >> 8 ) & 0x0000FF00 ) |
		( ( bigEndianValue << 8 ) & 0x00FF0000 ) |
		( ( bigEndianValue << 24 ) & 0xFF000000 );
}

USHORT BigEndianToLittleEndian16 ( USHORT bigEndianValue )
{
	return ( ( bigEndianValue >> 8 ) & 0x00FF ) |
		( ( bigEndianValue << 8 ) & 0xFF00 );
}

NTSTATUS GenerateRandomKey ( TPM2B_PUBLIC_KEY_RSA* inputKey )
{
	NTSTATUS status = STATUS_SUCCESS;
	BCRYPT_ALG_HANDLE algorithm = nullptr;
	BCRYPT_KEY_HANDLE keyHandle = nullptr;
	PUCHAR keyBlob = nullptr;
	DWORD keyBlobLength = 0;

	status = BCryptOpenAlgorithmProvider (
		&algorithm ,
		BCRYPT_RSA_ALGORITHM ,
		nullptr ,
		0
	);
	if ( !NT_SUCCESS ( status ) )
		goto Cleanup;

	status = BCryptGenerateKeyPair (
		algorithm ,
		&keyHandle ,
		2048 ,
		0
	);
	if ( !NT_SUCCESS ( status ) )
		goto Cleanup;

	status = BCryptFinalizeKeyPair ( keyHandle , 0 );
	if ( !NT_SUCCESS ( status ) )
		goto Cleanup;

	status = BCryptExportKey (
		keyHandle ,
		nullptr ,
		BCRYPT_RSAPUBLIC_BLOB ,
		nullptr ,
		0 ,
		&keyBlobLength ,
		0
	);
	if ( !NT_SUCCESS ( status ) )
		goto Cleanup;

	keyBlob = ( PUCHAR ) ExAllocatePoolWithTag (
		NonPagedPool ,
		keyBlobLength ,
		'kpyR'
	);
	if ( !keyBlob )
	{
		status = STATUS_NO_MEMORY;
		goto Cleanup;
	}

	status = BCryptExportKey (
		keyHandle ,
		nullptr ,
		BCRYPT_RSAPUBLIC_BLOB ,
		keyBlob ,
		keyBlobLength ,
		&keyBlobLength ,
		0
	);
	if ( !NT_SUCCESS ( status ) )
		goto Cleanup;

	// Extract ONLY the modulus from the BCrypt blob
	// Layout: [BCRYPT_RSAKEY_BLOB header] [exponent bytes] [modulus bytes]
	{
		BCRYPT_RSAKEY_BLOB* pBlob = (BCRYPT_RSAKEY_BLOB*)keyBlob;
		ULONG modulusOffset = sizeof(BCRYPT_RSAKEY_BLOB) + pBlob->cbPublicExp;
		ULONG modulusSize = pBlob->cbModulus;

		if (modulusSize > MAX_RSA_KEY_BYTES || modulusOffset + modulusSize > keyBlobLength) {
			status = STATUS_INVALID_PARAMETER;
			goto Cleanup;
		}

		RtlZeroMemory(inputKey->buffer, sizeof(inputKey->buffer));
		memcpy(inputKey->buffer, keyBlob + modulusOffset, modulusSize);
		inputKey->size = (UINT16)modulusSize;
	}

Cleanup:
	if ( keyBlob )
		ExFreePoolWithTag ( keyBlob , 'kpyR' );

	if ( keyHandle )
		BCryptDestroyKey ( keyHandle );

	if ( algorithm )
		BCryptCloseAlgorithmProvider ( algorithm , 0 );

	return status;
}



TPM2B_PUBLIC_KEY_RSA generatedKey = { 0 };
NTSTATUS HandleReadPublic ( PDEVICE_OBJECT device , PIRP irp , PVOID context )
{
	UNREFERENCED_PARAMETER ( device );

	if ( !context )
		return STATUS_SUCCESS;

	IOC_REQUEST request = *static_cast< PIOC_REQUEST >( context );
	ExFreePool ( context );

	// Only spoof on successful completion
	if ( !NT_SUCCESS ( irp->IoStatus.Status ) || !request.Buffer || generatedKey.size == 0 )
		goto _chain;

	{
		UINT16 modulusSize = 0;
		BYTE* modulus = FindRsaModulusInReadPublic (
			( BYTE* ) request.Buffer , request.Size , &modulusSize );

		if ( modulus && modulusSize == MAX_RSA_KEY_BYTES )
		{
			memcpy ( modulus , generatedKey.buffer , MAX_RSA_KEY_BYTES );
		}
	}

_chain:
	if ( request.Original )
		return request.Original ( device , irp , request.OriginalContext );

	return STATUS_SUCCESS;
}





struct motherboard_ {

	auto spoof ( ) -> NTSTATUS
	{

		auto* base = kmdf_utils::GetModuleBase ( oxorany ( "ntoskrnl.exe" ) );
		if ( !base )
		{
			return STATUS_UNSUCCESSFUL;
		}


		auto* physicalAddress = static_cast< PPHYSICAL_ADDRESS >(
			kmdf_utils::FindPatternImage (
				base ,
				oxorany ( "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8B\x15\x00\x00\x00\x00\x44\x8D\x43\x00\xE8" ) ,
				oxorany ( "xxx????xxxx?xx????xxx?x" )
			)
			);

		if ( !physicalAddress )
		{
			physicalAddress = static_cast< PPHYSICAL_ADDRESS >(
				kmdf_utils::FindPatternImage (
					base ,
					oxorany ( "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x74\x00\x8B\x15\x00\x00\x00\x00\x44\x8D\x43" ) ,
					oxorany ( "xxx????xxxx?xx????xxx" )
				)
				);
		}

		if ( !physicalAddress )
		{
			return STATUS_UNSUCCESSFUL;
		}

		physicalAddress = reinterpret_cast< PPHYSICAL_ADDRESS >(
			reinterpret_cast< char* >( physicalAddress ) +
			7 +
			*reinterpret_cast< int* >( reinterpret_cast< char* >( physicalAddress ) + 3 )
			);

		if ( !physicalAddress )
		{
			return STATUS_UNSUCCESSFUL;
		}


		auto* sizeScan = kmdf_utils::FindPatternImage (
			base ,
			oxorany ( "\x8B\x1D\x00\x00\x00\x00\x48\x8B\xD0\x44\x8B\xC3\x48\x8B\xCD\xE8\x00\x00\x00\x00\x8B\xD3\x48\x8B" ) ,
			oxorany ( "xx????xxxxxxxxxx????xxxx" )
		);

		if ( !sizeScan )
		{
			sizeScan = kmdf_utils::FindPatternImage (
				base ,
				oxorany ( "\x44\x8B\x05\x00\x00\x00\x00\x48\x8B\xD0\x48\x8B\xCE\xE8\x00\x00\x00\x00\x8B\x15" ) ,
				oxorany ( "xxx????xxxxxxx????xx" )
			);
		}

		if ( !sizeScan )
		{
			sizeScan = kmdf_utils::FindPatternImage (
				base ,
				oxorany ( "\x44\x8B\x05\x00\x00\x00\x00\x48\x8B\xD0\x48\x8B\xCE\xE8\x00\x00\x00\x00\x8B\x15\x00\x00\x00\x00\x48\x8B\xCB\xE8" ) ,
				oxorany ( "xxx????xxxxxxx????xx????xxxx" )
			);
		}

		if ( !sizeScan )
		{
			return STATUS_UNSUCCESSFUL;
		}


		const auto version = *( volatile UINT32* ) ( 0x7FFE0000 + 0x260 ); 
		const auto sizeOffset = ( version >= 26100 ) ? 3 : 2;
		const auto derefOffset = ( version >= 26100 ) ? 7 : 6;

		const auto size = *reinterpret_cast< ULONG* >(
			static_cast< char* >( sizeScan ) +
			derefOffset +
			*reinterpret_cast< int* >( static_cast< char* >( sizeScan ) + sizeOffset )
			);

		if ( !size )
		{
			return STATUS_UNSUCCESSFUL;
		}

		auto* mapped = MmMapIoSpace ( *physicalAddress , size , MmNonCached );
		if ( !mapped )
		{
			return STATUS_UNSUCCESSFUL;
		}
		registry_motherboard.write_reg ( mapped , size );

		spoof_boot_uuid ( );
		LoopTables ( mapped , size );

		MmUnmapIoSpace ( mapped , size );

		return STATUS_SUCCESS;
	}


};

motherboard_ motherboard;