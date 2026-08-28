#include "../disk/disk.h"
#include "../../hde64/hde64.h"
#include <usbioctl.h>

#pragma warning(error : 4024)  // Make mismatch an error

#define DBG_PREFIX oxorany("[KDW11S] ")



bool gpu_spoof_enabled = false;
bool monitor_spoof_enabled = false;
ULONG MonitorCount;

#pragma pack(push, 1)

#define WNODE_FLAG_ALL_DATA             0x00000001
#define WNODE_FLAG_SINGLE_INSTANCE      0x00000002
#define WNODE_FLAG_SINGLE_ITEM          0x00000004
#define WNODE_FLAG_EVENT_ITEM           0x00000008
#define WNODE_FLAG_FIXED_INSTANCE_SIZE  0x00000010
#define WNODE_FLAG_TOO_SMALL            0x00000020
#define WNODE_FLAG_INSTANCES_SAME       0x00000040

#ifndef FILE_DEVICE_USB
#define FILE_DEVICE_USB FILE_DEVICE_UNKNOWN
#endif

#ifndef USB_GET_NODE_CONNECTION_INFORMATION
#define USB_GET_NODE_CONNECTION_INFORMATION 259
#endif

#ifndef USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION
#define USB_GET_DESCRIPTOR_FROM_NODE_CONNECTION 260
#endif

#ifndef USB_GET_NODE_CONNECTION_INFORMATION_EX
#define USB_GET_NODE_CONNECTION_INFORMATION_EX 274
#endif

#ifndef USB_CTL
#define USB_CTL(id) CTL_CODE(FILE_DEVICE_USB, (id), METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

typedef struct _WNODE_HEADER {
	ULONG BufferSize;
	ULONG ProviderId;
	union {
		ULONG64 HistoricalContext;
		struct {
			ULONG Version;
			ULONG Linkage;
		};
	};
	union {
		ULONG CountLost;
		HANDLE KernelHandle;
		LARGE_INTEGER TimeStamp;
	};
	GUID Guid;
	ULONG ClientContext;
	ULONG Flags;
} WNODE_HEADER , * PWNODE_HEADER;

typedef struct _WNODE_ALL_DATA {
	WNODE_HEADER WnodeHeader;
	ULONG DataBlockOffset;
	ULONG InstanceCount;
	ULONG OffsetInstanceDataAndLength;
} WNODE_ALL_DATA , * PWNODE_ALL_DATA;

typedef struct _WNODE_ALL_DATA_EX {
	WNODE_HEADER WnodeHeader;
	ULONG DataBlockOffset;
	ULONG InstanceCount;
	ULONG OffsetInstanceDataAndLength;
} WNODE_ALL_DATA_EX , * PWNODE_ALL_DATA_EX;

typedef struct _OFFSETINSTANCEDATAANDLENGTH {
	ULONG OffsetInstanceData;
	ULONG LengthInstanceData;
} OFFSETINSTANCEDATAANDLENGTH , * POFFSETINSTANCEDATAANDLENGTH;

typedef struct _WmiMonitorID {
	USHORT Active;
	ULONG InstanceNameLength;
	PWSTR InstanceName;
	USHORT ProductCodeID [ 3 ];
	USHORT SerialNumberID [ 16 ];
	USHORT WeekOfManufacture;
	USHORT YearOfManufacture;
	ULONG SupportedDisplayFeatures;
	ULONG UserFriendlyNameLength;
	PWSTR UserFriendlyName;
} WmiMonitorID , * PWmiMonitorID;

#pragma pack(pop)

typedef struct
{
	BOOL              isInitialized;
	GUID                uuid;
} _GPU_UUID;




namespace nvidia_ctx
{
#define NV_MAX_DEVICES 32

	void GenerateRandomGUID ( GUID& newUUID ) {

		newUUID.Data1 = ( rand ( ) & 0xFFFFFFFF );
		newUUID.Data2 = static_cast< USHORT >( rand ( ) & 0xFFFF );
		newUUID.Data3 = static_cast< USHORT >( rand ( ) & 0xFFFF );

		newUUID.Data4 [ 0 ] = static_cast< UCHAR >( rand ( ) & 0xFF );
		newUUID.Data4 [ 1 ] = static_cast< UCHAR >( rand ( ) & 0xFF );
		newUUID.Data4 [ 2 ] = static_cast< UCHAR >( rand ( ) & 0xFF );
		newUUID.Data4 [ 3 ] = static_cast< UCHAR >( rand ( ) & 0xFF );
		newUUID.Data4 [ 4 ] = static_cast< UCHAR >( rand ( ) & 0xFF );
		newUUID.Data4 [ 5 ] = static_cast< UCHAR >( rand ( ) & 0xFF );
		newUUID.Data4 [ 6 ] = static_cast< UCHAR >( rand ( ) & 0xFF );
		newUUID.Data4 [ 7 ] = static_cast< UCHAR >( rand ( ) & 0xFF );
	}


	NTSTATUS SpoofGpu ( )
	{
		uint64_t nvlddmkm_base = ( uint64_t ) kmdf_utils::GetModuleBase ( "nvlddmkm.sys" );
		if ( !nvlddmkm_base )
		{
			return STATUS_UNSUCCESSFUL;
		}
		DebugPrint ( "Found nv base: %p\n" , nvlddmkm_base );
		uint32_t UuidValidOffset = 0xB2C;
		uint64_t found = ( uint64_t ) kmdf_utils::FindPatternImage ( ( PVOID ) nvlddmkm_base ,
			oxorany ( "\xE8\x00\x00\x00\x00\x48\x8B\xD8\x48\x85\xC0\x0F\x84\x00\x00\x00\x00\x44\x8B\x80\x00\x00\x00\x00\x48\x8D\x15" ) ,
			oxorany ( "x????xxxxxxxx????xxx????xxx" ) );
		if ( !found || *( uint8_t* ) ( found + 0x3C ) != 0xE8 )
		{
			DebugPrint ( "Could not find gpu pattern\n" );
			return STATUS_UNSUCCESSFUL;
		}
		else
		{
			uintptr_t offset = found - nvlddmkm_base;
			DebugPrint ( "Found gpu pattern at offset: 0x%llx\n" , offset );
		}

		uint64_t found_ = found;
		found_ += *( int* ) ( found_ + 1 ) + 5;
		uint64_t ( *result )( int ) = ( uint64_t ( * ) ( int ) ) ( found_ );

		found += 0x3C;

		found += *( int* ) ( found + 1 ) + 5;


		if ( !UuidValidOffset )
		{
			DebugPrint ( "Failed to find offset\n" );
			return STATUS_UNSUCCESSFUL;
		}
		else
		{
			DebugPrint ( "Found offset\n" );
		}

		for ( int i = 0; i < 32; i++ )
		{
			uint64_t ProbedGPU = result ( i );



			if ( !ProbedGPU )
			{
				continue;
			}
			else
			{
				uintptr_t offset = ProbedGPU - nvlddmkm_base;
				DebugPrint ( "Found probed gpu pattern at offset: %p\n" , ProbedGPU );


				for ( int j = 0; j < 1; j++ )
				{
					if ( !*( BOOL* ) ( ProbedGPU + UuidValidOffset ) )
					{
						DebugPrint ( "ProbedGPU + UuidValidOffset invalid\n" );
						UuidValidOffset += 1;
					}
					else
					{
						DebugPrint ( "Found GPU!\n" );
						//GUID* originalguid = (GUID*)(ProbedGPU + UuidValidOffset + 1);
						GUID* currentUUID = reinterpret_cast< GUID* >( ProbedGPU + UuidValidOffset + 1 );

						DebugPrint ( "GUID is valid!\n" );
						GUID newUUID {};
						GenerateRandomGUID ( newUUID );

						//GenerateRandomGUID(newUUID);
						//ExUuidCreate(&newUUID);
						const uint8_t* newUUIDBytes = reinterpret_cast< const uint8_t* >( &newUUID );
						for ( int b = 0; b < sizeof ( GUID ); b++ ) {
							*( uint8_t* ) ( ProbedGPU + UuidValidOffset + 1 + b ) = newUUIDBytes [ b ];
						}
					}
				}
			}
		}


		return STATUS_SUCCESS;
	}


	void PrintGuid ( const GUID& guid )
	{
		WCHAR guidString [ 40 ]; 

		swprintf_s (
			guidString ,
			sizeof ( guidString ) / sizeof ( guidString [ 0 ] ) ,
			L"%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X" ,
			guid.Data1 , guid.Data2 , guid.Data3 ,
			guid.Data4 [ 0 ] , guid.Data4 [ 1 ] ,
			guid.Data4 [ 2 ] , guid.Data4 [ 3 ] ,
			guid.Data4 [ 4 ] , guid.Data4 [ 5 ] ,
			guid.Data4 [ 6 ] , guid.Data4 [ 7 ]
		);

		DbgPrint ( "%S\n" , guidString );
	}

	GUID CreateGuid ( const uint8_t* data )
	{
		GUID guid = {
			*reinterpret_cast< const unsigned long* >( data ),
			*reinterpret_cast< const unsigned short* >( data + 4 ),
			*reinterpret_cast< const unsigned short* >( data + 6 ),
			{ 
				*reinterpret_cast< const unsigned char* >( data + 8 ),
				*reinterpret_cast< const unsigned char* >( data + 9 ),
				*reinterpret_cast< const unsigned char* >( data + 10 ),
				*reinterpret_cast< const unsigned char* >( data + 11 ),
				*reinterpret_cast< const unsigned char* >( data + 12 ),
				*reinterpret_cast< const unsigned char* >( data + 13 ),
				*reinterpret_cast< const unsigned char* >( data + 14 ),
				*reinterpret_cast< const unsigned char* >( data + 15 ),
			}
		};
		return guid;
	}

}

#define NV_MAX_DEVICES 32

namespace wp
{
	__forceinline uint32_t rand_u32 ( )
	{
		static ULONG seed = 0;

		if ( !seed )
		{
			LARGE_INTEGER time;
			KeQuerySystemTime ( &time );
			seed = time.LowPart ^ time.HighPart;
		}

		return RtlRandomEx ( &seed );
	}

	template<typename T>
	__forceinline T rand_between ( T min , T max )
	{
		static_assert( std::is_integral_v<T> , "Integral type required" );

		if ( min >= max )
			return min;

		uint32_t rnd = rand_u32 ( );
		return static_cast< T >( min + ( rnd % ( max - min + 1 ) ) );
	}
}


void dbg_print_uuid ( const GUID* guid )
{
	DbgPrintEx (
		0 ,
		0 ,
		"[UUID] %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X\n" ,
		guid->Data1 ,
		guid->Data2 ,
		guid->Data3 ,
		guid->Data4 [ 0 ] ,
		guid->Data4 [ 1 ] ,
		guid->Data4 [ 2 ] ,
		guid->Data4 [ 3 ] ,
		guid->Data4 [ 4 ] ,
		guid->Data4 [ 5 ] ,
		guid->Data4 [ 6 ] ,
		guid->Data4 [ 7 ]
	);
}


struct gpu_
{

	uintptr_t spoof ( ) {
		uintptr_t nvlddmkm_base = 0;
		uint32_t uuid_valid_offset = 0;

		nvlddmkm_base = ( uintptr_t ) kmdf_utils::GetModuleBase ( oxorany ( "nvlddmkm.sys" ) ); if ( !nvlddmkm_base ) {
			// Try AMD GPU if NVIDIA not found
			uintptr_t amdkmdag_base = ( uintptr_t ) kmdf_utils::GetModuleBase ( oxorany ( "amdkmdag.sys" ) );
			if ( amdkmdag_base ) {
				DbgPrintEx(0, 0, "[GPU] Found AMD GPU driver (amdkmdag.sys), spoofing registry...\n");
				spoof_amd_gpu_registry();
				return 1;
			}
			return 0;
		}

		uint64_t address = ( uint64_t ) kmdf_utils::FindPatternImage ( ( PVOID ) nvlddmkm_base ,
			oxorany("\xE8\xCC\xCC\xCC\xCC\x48\x8B\xD8\x48\x85\xC0\x0F\x84\xCC\xCC\xCC\xCC\x44\x8B\x80\xCC\xCC\xCC\xCC\x48\x8D\x15") ,
			oxorany("x????xxxxxxxx????xxx????xxx") );

		UINT64 address_offset = 0x3B;
		if ( !address || *( uint8_t* ) ( address + address_offset ) != 0xE8 ) {
			address_offset++;
			if ( *( UINT8* ) ( address + address_offset ) != 0xE8 ) {
				return 0;
			}
		}

		uint64_t ( *GpuMgrGetGpuFromId )( int ) = decltype( GpuMgrGetGpuFromId )( *( int* ) ( address + 1 ) + 5 + address );
		address += address_offset;
		address += *( int* ) ( address + 1 ) + 5;

		for ( int InstructionCount = 0; InstructionCount < 50; InstructionCount++ ) {
			hde64s HDE;
			hde64_disasm ( ( void* ) address , &HDE );

			if ( HDE.flags & F_ERROR ) return 0;

			uint32_t op = *( uint32_t* ) address & 0xFFFFFF;
			if ( op == 0x818D4C ) {
				uuid_valid_offset = *( UINT32* ) ( address + 3 ) - 1;
				break;
			}

			address += HDE.len;
		}

		if ( !uuid_valid_offset ) return false;

		for ( int i = 0; i < 32; i++ )
		{
			UINT64 gpu = GpuMgrGetGpuFromId ( i );	if ( !gpu ) continue;
			if ( !*( bool* ) ( gpu + uuid_valid_offset ) ) continue;

			for ( int j = 0; j < sizeof ( GUID ); j++ )
				*( uint8_t* ) ( gpu + uuid_valid_offset + 1 + j ) = __rdtsc ( );

			auto* newUuid = reinterpret_cast< GUID* > (
				gpu + uuid_valid_offset + 1
				);

			dbg_print_uuid ( newUuid );
		}

		return 1;

	}

	// AMD GPU registry spoofing
	void spoof_amd_gpu_registry() {
		// Spoof AMD GPU properties in registry
		UNICODE_STRING amdPath;
		RtlInitUnicodeString(&amdPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}");
		HANDLE hAmd;
		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(&oa, &amdPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

		if (NT_SUCCESS(ZwOpenKey(&hAmd, KEY_READ, &oa))) {
			ULONG idx = 0;
			BYTE keyBuf[512];
			while (TRUE) {
				ULONG resultLen;
				NTSTATUS st = ZwEnumerateKey(hAmd, idx++, KeyBasicInformation, keyBuf, sizeof(keyBuf), &resultLen);
				if (st == STATUS_NO_MORE_ENTRIES) break;
				if (!NT_SUCCESS(st)) continue;

				PKEY_BASIC_INFORMATION kbi = (PKEY_BASIC_INFORMATION)keyBuf;
				wchar_t subPath[512];
				RtlStringCchPrintfW(subPath, 512, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\%.*s",
					kbi->NameLength / sizeof(wchar_t), kbi->Name);

				UNICODE_STRING uSubPath;
				RtlInitUnicodeString(&uSubPath, subPath);
				HANDLE hSub;
				InitializeObjectAttributes(&oa, &uSubPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
				if (NT_SUCCESS(ZwOpenKey(&hSub, KEY_READ, &oa))) {
					// Check if this is an AMD GPU
					UNICODE_STRING providerName;
					RtlInitUnicodeString(&providerName, L"ProviderName");
					ULONG resultLen2;
					NTSTATUS st2 = ZwQueryValueKey(hSub, &providerName, KeyValuePartialInformation, NULL, 0, &resultLen2);
					if (st2 == STATUS_BUFFER_TOO_SMALL && resultLen2 > 0) {
						PKEY_VALUE_PARTIAL_INFORMATION pvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, resultLen2, 'puG_');
						if (pvpi) {
							st2 = ZwQueryValueKey(hSub, &providerName, KeyValuePartialInformation, pvpi, resultLen2, &resultLen2);
							if (NT_SUCCESS(st2) && pvpi->Type == REG_SZ) {
								wchar_t* provider = (wchar_t*)pvpi->Data;
								if (wcsstr(provider, L"Advanced Micro Devices") || wcsstr(provider, L"AMD")) {
									DbgPrintEx(0, 0, "[GPU] Found AMD GPU entry: %.*s\n", kbi->NameLength / sizeof(wchar_t), kbi->Name);
									// Spoof hardware ID
									spoof_amd_hwid(hSub);
								}
							}
							ExFreePoolWithTag(pvpi, 'puG_');
						}
					}
					ZwClose(hSub);
				}
			}
			ZwClose(hAmd);
		}
	}

	void spoof_amd_hwid(HANDLE hKey) {
		// Spoof HardwareInformation.AdapterString
		UNICODE_STRING adapterStr;
		RtlInitUnicodeString(&adapterStr, L"HardwareInformation.AdapterString");
		ULONG resultLen;
		NTSTATUS st = ZwQueryValueKey(hKey, &adapterStr, KeyValuePartialInformation, NULL, 0, &resultLen);
		if (st == STATUS_BUFFER_TOO_SMALL && resultLen > 0) {
			PKEY_VALUE_PARTIAL_INFORMATION pvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, resultLen, 'puG_');
			if (pvpi) {
				st = ZwQueryValueKey(hKey, &adapterStr, KeyValuePartialInformation, pvpi, resultLen, &resultLen);
				if (NT_SUCCESS(st) && pvpi->Type == REG_SZ) {
					wchar_t* adapter = (wchar_t*)pvpi->Data;
					ULONG seed = kmdf_settings::hwid_seed;
					for (int i = 0; i < pvpi->DataLength / sizeof(wchar_t) && adapter[i]; i++) {
						if (adapter[i] >= L'0' && adapter[i] <= L'9') {
							ULONG r = DiskLCG(seed);
							adapter[i] = L'0' + (r % 10);
						}
					}
					ZwSetValueKey(hKey, &adapterStr, 0, REG_SZ, pvpi->Data, pvpi->DataLength);
					DbgPrintEx(0, 0, "[GPU] Spoofed AMD adapter string\n");
				}
				ExFreePoolWithTag(pvpi, 'puG_');
			}
		}

		// Spoof DriverVersion
		UNICODE_STRING driverVer;
		RtlInitUnicodeString(&driverVer, L"DriverVersion");
		st = ZwQueryValueKey(hKey, &driverVer, KeyValuePartialInformation, NULL, 0, &resultLen);
		if (st == STATUS_BUFFER_TOO_SMALL && resultLen > 0) {
			PKEY_VALUE_PARTIAL_INFORMATION pvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, resultLen, 'puG_');
			if (pvpi) {
				st = ZwQueryValueKey(hKey, &driverVer, KeyValuePartialInformation, pvpi, resultLen, &resultLen);
				if (NT_SUCCESS(st) && pvpi->Type == REG_SZ) {
					wchar_t* version = (wchar_t*)pvpi->Data;
					ULONG seed = kmdf_settings::hwid_seed ^ 0x414D4456; // 'AMDV'
					for (int i = 0; i < pvpi->DataLength / sizeof(wchar_t) && version[i]; i++) {
						if (version[i] >= L'0' && version[i] <= L'9') {
							ULONG r = DiskLCG(seed);
							version[i] = L'0' + (r % 10);
						}
					}
					ZwSetValueKey(hKey, &driverVer, 0, REG_SZ, pvpi->Data, pvpi->DataLength);
					DbgPrintEx(0, 0, "[GPU] Spoofed AMD driver version\n");
				}
				ExFreePoolWithTag(pvpi, 'puG_');
			}
		}
	}
};

static gpu_ gpu;




struct monitor_ {


	void InitUnicodeStr ( UNICODE_STRING* unicodeStr , PCWSTR wideStr ) {
		if ( !unicodeStr || !wideStr ) return;

		SIZE_T len = 0;
		while ( wideStr [ len ] != L'\0' ) len++;

		unicodeStr->Buffer = const_cast< PWCH >( wideStr );
		unicodeStr->Length = ( USHORT ) ( len * sizeof ( WCHAR ) );
		unicodeStr->MaximumLength = unicodeStr->Length + sizeof ( WCHAR );
	}

	void StringCopy ( char* dest , const char* src , SIZE_T dest_size ) {
		if ( !dest || !src || dest_size == 0 ) return;

		SIZE_T i = 0;
		for ( ; i < dest_size - 1 && src [ i ] != '\0'; i++ ) {
			dest [ i ] = src [ i ];
		}
		dest [ i ] = '\0';
	}

	VOID GenerateSerialString ( ULONG seed , CHAR* output , SIZE_T size , const CHAR* charset ) {
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

	VOID ParseAndSpoofEdidData ( PUCHAR edidData , ULONG edidSize , ULONG monitorIndex ) {
		if ( edidSize < 128 ) {
			return;
		}

		CHAR new_serial [ 64 ] = { 0 };
		CHAR MonitorSerials [ 4 ][ 64 ];

		GenerateSerialString ( kmdf_settings::hwid_seed , new_serial , sizeof ( new_serial ) , oxorany( "0123456789") );

		ULONG newSerialValue = 0;
		for ( int i = 0; i < 12 && new_serial [ i ] != '\0'; i++ ) {
			if ( new_serial [ i ] >= '0' && new_serial [ i ] <= '9' ) {
				newSerialValue = newSerialValue * 10 + ( new_serial [ i ] - '0' );
			}
		}
		*( PULONG ) ( edidData + 12 ) = newSerialValue;

		UCHAR checksum = 0;
		for ( int i = 0; i < 127; i++ ) {
			checksum += edidData [ i ];
		}
		edidData [ 127 ] = ( UCHAR ) ( 256 - checksum );

		StringCopy ( MonitorSerials [ monitorIndex ] ,
			new_serial , sizeof ( MonitorSerials [ monitorIndex ] ) );

		MonitorCount = ( monitorIndex + 1 > MonitorCount ) ?
			monitorIndex + 1 : MonitorCount;
	}


	ULONG GenerateRandom ( ULONG* seed ) {
		if ( !seed ) return 0;
		*seed = ( *seed * 1103515245 + 12345 ) & 0x7FFFFFFF;
		return *seed;
	}

	NTSTATUS spoof_graphics ( ) {
		NTSTATUS status = STATUS_SUCCESS;
		HANDLE hConfigKey = NULL;

		UNICODE_STRING configPath;
		InitUnicodeStr ( &configPath , oxorany ( L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\Configuration") );

		OBJECT_ATTRIBUTES objectAttributes;
		InitializeObjectAttributes ( &objectAttributes , &configPath ,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE , NULL , NULL );

		status = ZwOpenKey ( &hConfigKey , KEY_READ | KEY_WRITE , &objectAttributes );
		if ( !NT_SUCCESS ( status ) ) {
			return status;
		}

		ULONG context = 0;
		WCHAR subkeyName [ 256 ];
		UNICODE_STRING subkeyStr;

		while ( TRUE ) {
			status = ZwEnumerateKey ( hConfigKey , context , KeyBasicInformation ,
				subkeyName , sizeof ( subkeyName ) , NULL );
			if ( !NT_SUCCESS ( status ) ) {
				break;
			}

			InitUnicodeStr ( &subkeyStr , subkeyName );

			HANDLE hSubKey = NULL;
			OBJECT_ATTRIBUTES subAttributes;
			InitializeObjectAttributes ( &subAttributes , &subkeyStr ,
				OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE ,
				hConfigKey , NULL );

			status = ZwOpenKey ( &hSubKey , KEY_READ | KEY_WRITE , &subAttributes );
			if ( NT_SUCCESS ( status ) ) {
				ULONG seed = kmdf_settings::hwid_seed;
				ULONG64 newTimestamp = ( ULONG64 ) GenerateRandom ( &seed ) << 32 | GenerateRandom ( &seed );

				UNICODE_STRING timestampName;
				InitUnicodeStr ( &timestampName , L"Timestamp" );

				status = ZwSetValueKey ( hSubKey , &timestampName , 0 , REG_QWORD ,
					&newTimestamp , sizeof ( newTimestamp ) );

				ZwClose ( hSubKey );
			}

			context++;
		}

		ZwClose ( hConfigKey );
		return STATUS_SUCCESS;
	}


	NTSTATUS spoof_reg ( ) {
		NTSTATUS status = STATUS_SUCCESS;
		HANDLE hDisplayKey = NULL;

		UNICODE_STRING displayPath;
		InitUnicodeStr ( &displayPath , oxorany ( L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\DISPLAY") );

		OBJECT_ATTRIBUTES objectAttributes;
		InitializeObjectAttributes ( &objectAttributes , &displayPath ,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE , NULL , NULL );

		status = ZwOpenKey ( &hDisplayKey , KEY_READ , &objectAttributes );
		if ( !NT_SUCCESS ( status ) ) {
			return status;
		}

		ULONG monitorIndex = 0;
		ULONG context = 0;
		WCHAR subkeyName [ 256 ];
		UNICODE_STRING subkeyStr;

		while ( TRUE ) {
			status = ZwEnumerateKey ( hDisplayKey , context , KeyBasicInformation ,
				subkeyName , sizeof ( subkeyName ) , NULL );
			if ( !NT_SUCCESS ( status ) ) {
				break;
			}

			InitUnicodeStr ( &subkeyStr , subkeyName );

			HANDLE hMonitorTypeKey = NULL;
			OBJECT_ATTRIBUTES monitorAttributes;
			InitializeObjectAttributes ( &monitorAttributes , &subkeyStr ,
				OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE ,
				hDisplayKey , NULL );

			status = ZwOpenKey ( &hMonitorTypeKey , KEY_READ , &monitorAttributes );
			if ( NT_SUCCESS ( status ) ) {
				ULONG deviceContext = 0;
				WCHAR deviceName [ 256 ];
				UNICODE_STRING deviceStr;

				while ( TRUE ) {
					status = ZwEnumerateKey ( hMonitorTypeKey , deviceContext ,
						KeyBasicInformation ,
						deviceName , sizeof ( deviceName ) , NULL );
					if ( !NT_SUCCESS ( status ) ) {
						break;
					}

					InitUnicodeStr ( &deviceStr , deviceName );

					HANDLE hDeviceKey = NULL;
					OBJECT_ATTRIBUTES deviceAttributes;
					InitializeObjectAttributes ( &deviceAttributes , &deviceStr ,
						OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE ,
						hMonitorTypeKey , NULL );

					status = ZwOpenKey ( &hDeviceKey , KEY_READ | KEY_WRITE , &deviceAttributes );
					if ( NT_SUCCESS ( status ) ) {
						HANDLE hParamsKey = NULL;
						UNICODE_STRING paramsStr;
						InitUnicodeStr ( &paramsStr , oxorany ( L"Device Parameters") );

						OBJECT_ATTRIBUTES paramsAttributes;
						InitializeObjectAttributes ( &paramsAttributes , &paramsStr ,
							OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE ,
							hDeviceKey , NULL );

						status = ZwOpenKey ( &hParamsKey , KEY_READ | KEY_WRITE , &paramsAttributes );
						if ( NT_SUCCESS ( status ) ) {
							UNICODE_STRING edidValueName;
							InitUnicodeStr ( &edidValueName , oxorany  ( L"EDID" ) );

							UCHAR edidData [ 512 ] = { 0 };
							ULONG resultLength = 0;

							status = ZwQueryValueKey ( hParamsKey , &edidValueName ,
								KeyValueFullInformation ,
								edidData , sizeof ( edidData ) , &resultLength );

							if ( NT_SUCCESS ( status ) ) {
								PKEY_VALUE_FULL_INFORMATION valueInfo =
									( PKEY_VALUE_FULL_INFORMATION ) edidData;
								PUCHAR edidContent = ( PUCHAR ) valueInfo + valueInfo->DataOffset;
								ULONG edidSize = valueInfo->DataLength;

								if ( edidSize >= 128 ) {
									ParseAndSpoofEdidData ( edidContent , edidSize , monitorIndex );
									status = ZwSetValueKey ( hParamsKey , &edidValueName ,
										0 , REG_BINARY ,
										edidContent , edidSize );

									if ( NT_SUCCESS ( status ) ) {
										monitorIndex++;
									}
								}
							}

							ZwClose ( hParamsKey );
						}

						ZwClose ( hDeviceKey );
					}

					deviceContext++;
				}
				ZwClose ( hMonitorTypeKey );
			}

			context++;
		}

		if ( hDisplayKey ) {
			ZwClose ( hDisplayKey );
		}

		return STATUS_SUCCESS;
	}

	auto clean ( ) -> NTSTATUS
	{
		UNICODE_STRING keyPath1;
		RtlInitUnicodeString ( &keyPath1 ,
			oxorany ( L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\DISPLAY" ) );
		kmdf_utils::DeleteSubKeys ( &keyPath1 );

		UNICODE_STRING keyPath2;
		RtlInitUnicodeString ( &keyPath2 ,
			oxorany ( L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\Configuration" ) );
		kmdf_utils::DeleteRegistryKey ( &keyPath2 );

		UNICODE_STRING keyPath3;
		RtlInitUnicodeString ( &keyPath3 ,
			oxorany ( L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\UnitedVideo\\CONTROL\\VIDEO" ) );
		kmdf_utils::DeleteRegistryKey ( &keyPath3 );

		UNICODE_STRING keyPath4;
		RtlInitUnicodeString ( &keyPath4 ,
			oxorany ( L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers\\ScaleFactors" ) );
		kmdf_utils::DeleteRegistryKey ( &keyPath4 );

		return STATUS_SUCCESS;
	}

};

static monitor_ monitor;



