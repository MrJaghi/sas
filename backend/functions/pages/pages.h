#pragma once
#include "ia32/ia32.h"
#include <intrin.h>
#include "ia32/definitions/definitions.h"
#include <ntintsafe.h>
extern "C"
{

    NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader ( IN PVOID   ModuleAddress );
}

int Runs;
PHYSICAL_MEMORY_RANGE MR [ 10 ];
char SpoofedString [ 80 ];

struct MgrHelper
{
    PVOID Page;
    PTE_64* PTE;
};
MgrHelper Pages [ 5 ];


enum MappingLevels
{
    PML4_LEVEL ,
    PDPT_LEVEL ,
    PD_LEVEL ,
    PT_LEVEL ,
    PTE_LEVEL ,
};

void PhysMemRange ( )
{
    PPHYSICAL_MEMORY_RANGE MmPhysicalMemoryRange = MmGetPhysicalMemoryRanges ( );
    Runs = 0;
    for ( int number_of_runs = 0; ( MmPhysicalMemoryRange [ number_of_runs ].BaseAddress.QuadPart ) || ( MmPhysicalMemoryRange [ number_of_runs ].NumberOfBytes.QuadPart ); number_of_runs++ )
    {
        MR [ number_of_runs ] = MmPhysicalMemoryRange [ number_of_runs ];
        Runs += 1;
    }
    return;
}








PT_ENTRY_64* GetPte ( VOID* VirtualAddress , CR3 HostCr3 )
{
    ADDRESS_TRANSLATION_HELPER helper;
    UINT32 level;
    PT_ENTRY_64* finalEntry;
    PML4E_64* pml4;
    PML4E_64* pml4e;
    PDPTE_64* pdpt;
    PDPTE_64* pdpte;
    PDE_64* pd;
    PDE_64* pde;
    PTE_64* pt;
    PTE_64* pte;

    helper.AsUInt64 = ( UINT64 ) VirtualAddress;

    PHYSICAL_ADDRESS    addr;



    addr.QuadPart = HostCr3.AddressOfPageDirectory << PAGE_SHIFT;

    pml4 = ( PML4E_64* ) MmGetVirtualForPhysical ( addr );

    pml4e = &pml4 [ helper.AsIndex.Pml4 ];

    if ( pml4e->Present == FALSE )
    {
        finalEntry = ( PT_ENTRY_64* ) pml4e;
        goto Exit;
    }




    addr.QuadPart = pml4e->PageFrameNumber << PAGE_SHIFT;

    pdpt = ( PDPTE_64* ) MmGetVirtualForPhysical ( addr );

    pdpte = &pdpt [ helper.AsIndex.Pdpt ];

    if ( ( pdpte->Present == FALSE ) || ( pdpte->LargePage != FALSE ) )
    {
        finalEntry = ( PT_ENTRY_64* ) pdpte;
        goto Exit;
    }



    addr.QuadPart = pdpte->PageFrameNumber << PAGE_SHIFT;

    pd = ( PDE_64* ) MmGetVirtualForPhysical ( addr );

    pde = &pd [ helper.AsIndex.Pd ];

    if ( ( pde->Present == FALSE ) || ( pde->LargePage != FALSE ) )
    {
        finalEntry = ( PT_ENTRY_64* ) pde;
        goto Exit;
    }





    addr.QuadPart = pde->PageFrameNumber << PAGE_SHIFT;

    pt = ( PTE_64* ) MmGetVirtualForPhysical ( addr );

    pte = &pt [ helper.AsIndex.Pt ];

    finalEntry = ( PT_ENTRY_64* ) pte;

    return  ( PT_ENTRY_64* ) pte;

Exit:
    return finalEntry;
}





void SetPages ( int amount , CR3 cr )
{
    Pages [ amount ].Page = MmAllocateMappingAddress ( PAGE_SIZE , 'EnDa' + amount );
    Pages [ amount ].PTE = ( PTE_64* ) GetPte ( Pages [ amount ].Page , cr );
}


void InitPages ( )
{
    CR3 ControlRegister;
    ControlRegister.Flags = __readcr3 ( );

    for ( int i = 0; i < 5; ++i )
    {
        SetPages ( i , ControlRegister );
    }

    PhysMemRange ( );
}

void DelPages ( )
{
    for ( int i = 0; i < 5; ++i )
    {
        MmFreeMappingAddress ( Pages [ i ].Page , 'EnDa' + i );
    }
}


BYTE AA_SerialNumber [ 80 ];

int AA_SerialLength;

namespace Utils
{
    PDEVICE_OBJECT GetRD ( const wchar_t* deviceName )
    {
        UNICODE_STRING raidPort;
        RtlInitUnicodeString ( &raidPort , deviceName );

        PFILE_OBJECT fileObject = nullptr;
        PDEVICE_OBJECT deviceObject = nullptr;
        auto status = IoGetDeviceObjectPointer ( &raidPort , FILE_READ_DATA , &fileObject , &deviceObject );
        if ( !NT_SUCCESS ( status ) )
        {
            return nullptr;
        }

        return deviceObject->DriverObject->DeviceObject;
    }



    PVOID GetDriverBaseAddy ( OUT PULONG pSize , const char* driverName )
    {
        NTSTATUS Status = STATUS_SUCCESS;
        ULONG Bytes = 0;
        PRTL_PROCESS_MODULES arrayOfModules;
        PVOID DriverBase = 0;
        ULONG64 DriverSize = 0;
        Status = ZwQuerySystemInformation ( SystemModuleInformation , 0 , Bytes , &Bytes );
        if ( Bytes == 0 )
        {
            return NULL;
        }
        arrayOfModules = ( PRTL_PROCESS_MODULES ) ExAllocatePoolWithTag ( NonPagedPool , Bytes , 'ONEN' );
        RtlZeroMemory ( arrayOfModules , Bytes );
        Status = ZwQuerySystemInformation ( SystemModuleInformation , arrayOfModules , Bytes , &Bytes );
        if ( NT_SUCCESS ( Status ) )
        {
            PRTL_PROCESS_MODULE_INFORMATION pMod = arrayOfModules->Modules;
            for ( int i = 0; i < arrayOfModules->NumberOfModules; ++i )
            {
                const char* DriverName = ( const char* ) pMod [ i ].FullPathName + pMod [ i ].OffsetToFileName;
                if ( strcmp ( DriverName , driverName ) == 0 )
                {
                    DriverBase = pMod [ i ].ImageBase;
                    DriverSize = pMod [ i ].ImageSize;
                    if ( arrayOfModules )
                        ExFreePoolWithTag ( arrayOfModules , 'ONEN' );

                    if ( pSize != NULL )
                    {
                        *pSize = DriverSize;
                    }
                    return DriverBase;
                }
            }
        }
        if ( arrayOfModules )
            ExFreePoolWithTag ( arrayOfModules , 'ONEN' );

        if ( pSize != NULL )
        {
            *pSize = DriverSize;
        }
        return ( PVOID ) DriverBase;
    }
}

namespace PatternScanUtil
{
    PVOID64 findPattern ( BYTE* pattern , int patternSize , BYTE    wildCard , ULONG64 startAddress , ULONG64   endAddress )
    {
        bool found = false;
        if ( !MmIsAddressValid ( ( PVOID ) startAddress ) )
        {
            return 0;
        }
        for ( BYTE* i = ( BYTE* ) startAddress; i < ( BYTE* ) ( endAddress - patternSize ); ++i )
        {
            found = true;
            for ( int j = 0; j < patternSize; ++j )
            {
                if ( ( pattern [ j ] != i [ j ] ) && ( pattern [ j ] != wildCard ) )
                {
                    found = false;
                    break;
                }
            }
            if ( found == true )
            {
                return ( PVOID64 ) i;
            }
        }
        return 0;
    }

    NTSTATUS BBSearchPattern ( IN PCUCHAR pattern , IN UCHAR wildcard , IN ULONG_PTR len , IN const VOID* base , IN ULONG_PTR size , OUT PVOID* ppFound )
    {
        ASSERT ( ppFound != NULL && pattern != NULL && base != NULL );
        if ( ppFound == NULL || pattern == NULL || base == NULL )
            return STATUS_INVALID_PARAMETER;

        for ( ULONG_PTR i = 0; i < size - len; i++ )
        {
            BOOLEAN found = TRUE;
            for ( ULONG_PTR j = 0; j < len; j++ )
            {
                if ( pattern [ j ] != wildcard && pattern [ j ] != ( ( PCUCHAR ) base ) [ i + j ] )
                {
                    found = FALSE;
                    break;
                }
            }

            if ( found != FALSE )
            {
                *ppFound = ( PUCHAR ) base + i;
                return STATUS_SUCCESS;
            }
        }

        return STATUS_NOT_FOUND;
    }

    NTSTATUS BBScan ( IN PCCHAR section , IN PCUCHAR pattern , IN UCHAR wildcard , IN ULONG_PTR len , OUT PVOID* ppFound , PVOID base = nullptr )
    {
        if ( ppFound == NULL )
            return STATUS_ACCESS_DENIED;

        if ( nullptr == base )
            base = Utils::GetDriverBaseAddy ( NULL , "ntoskrnl.exe" );
        if ( base == nullptr )
            return STATUS_ACCESS_DENIED;

        PIMAGE_NT_HEADERS64 pHdr = ( PIMAGE_NT_HEADERS64 ) RtlImageNtHeader ( base );
        if ( !pHdr )
            return STATUS_ACCESS_DENIED;
        PIMAGE_SECTION_HEADER pFirstSection = ( PIMAGE_SECTION_HEADER ) ( ( uintptr_t ) &pHdr->FileHeader + pHdr->FileHeader.SizeOfOptionalHeader + sizeof ( IMAGE_FILE_HEADER ) );

        PVOID ptr = NULL;

        for ( PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++ )
        {

            ANSI_STRING s1 , s2;
            RtlInitAnsiString ( &s1 , section );
            RtlInitAnsiString ( &s2 , ( PCCHAR ) pSection->Name );
            if ( ( ( RtlCompareString ( &s1 , &s2 , TRUE ) == 0 ) || ( pSection->Characteristics & IMAGE_SCN_CNT_CODE ) || ( pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE ) ) )
            {
                NTSTATUS status = BBSearchPattern ( pattern , wildcard , len , ( PUCHAR ) base + pSection->VirtualAddress , pSection->Misc.VirtualSize , &ptr );
                if ( NT_SUCCESS ( status ) ) {
                    *( PULONG64 ) ppFound = ( ULONG_PTR ) ( ptr );
                    return status;
                }
            }
        }

        return STATUS_ACCESS_DENIED;
    }

    PVOID ResolveRelativeAddress ( _In_ PVOID Instruction , _In_ ULONG OffsetOffset , _In_ ULONG InstructionSize )
    {
        ULONG_PTR Instr = ( ULONG_PTR ) Instruction;
        LONG RipOffset = *( PLONG ) ( Instr + OffsetOffset );
        PVOID ResolvedAddr = ( PVOID ) ( Instr + InstructionSize + RipOffset );

        return ResolvedAddr;
    }
}


SIZE_T MemoryCopySafe ( void* destination , void* source , SIZE_T size )
{
    MM_COPY_ADDRESS address;
    address.VirtualAddress = source;
    SIZE_T copied;
    SPOOF_CALL ( NTSTATUS , MmCopyMemory )( destination , address , size , MM_COPY_MEMORY_VIRTUAL , &copied );
    return copied;
}

BOOLEAN WriteToProtectedMem ( VOID* address , BYTE* source , ULONG length ) {
    MDL* mdl = IoAllocateMdl ( address , length , FALSE , FALSE , 0 );
    if ( !mdl )
        return FALSE;

    SPOOF_CALL ( void , MmProbeAndLockPages )( mdl , KernelMode , IoModifyAccess );

    VOID* map_address = ( MmMapLockedPagesSpecifyCache ) ( mdl , KernelMode , MmNonCached , 0 , FALSE , NormalPagePriority );
    if ( !map_address ) {
        SPOOF_CALL ( void , MmUnlockPages )( mdl );
        SPOOF_CALL ( void , IoFreeMdl )( mdl );
        return FALSE;
    }

    NTSTATUS status = SPOOF_CALL ( NTSTATUS , MmProtectMdlSystemAddress )( mdl , PAGE_EXECUTE_READWRITE );
    if ( status ) {
        SPOOF_CALL ( void , MmUnmapLockedPages )( map_address , mdl );
        SPOOF_CALL ( void , MmUnlockPages )( mdl );
        SPOOF_CALL ( void , IoFreeMdl )( mdl );
        return FALSE;
    }

    SPOOF_CALL ( void* __cdecl , memcpy )( map_address , source , length );
    SPOOF_CALL ( void , MmUnmapLockedPages )( map_address , mdl );
    SPOOF_CALL ( void , MmUnlockPages )( mdl );
    SPOOF_CALL ( void , IoFreeMdl )( mdl );
    return TRUE;
}



extern "C" NTSTATUS NTAPI ExRaiseHardError (
    NTSTATUS ErrorStatus , ULONG NumberOfParameters ,
    ULONG UnicodeStringParameterMask , PULONG_PTR Parameters ,
    ULONG ValidResponseOptions , PULONG Response );

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


void ScanCurrentPages ( PVOID64 VP , ULONG TotalSize , PHYSICAL_ADDRESS PA )
{
    if ( VP && MmIsAddressValid ( VP ) )
    {
        __invlpg ( VP );

        // change wildcard to diff letter if scanning is slow!

        PVOID64 SerialsInPhysicalMemory = PatternScanUtil::findPattern ( AA_SerialNumber , AA_SerialLength , 'J' , ( ULONG64 ) VP , ( ULONG64 ) VP + TotalSize );

        if ( SerialsInPhysicalMemory )
        {
            if ( memcmp ( PGSignature , ( PVOID ) ( ( DWORD64 ) ( SerialsInPhysicalMemory ) +AA_SerialLength ) , 3 ) != 0 )
            {
                //DbgPrintEx(0, 0, "FOUND!\n");
                //RtlCopyMemory(SerialsInPhysicalMemory, SpoofedString, AA_SerialLength);

                RtlCopyMemory ( SerialsInPhysicalMemory , SpoofedString , AA_SerialLength );

                //MemoryCopySafe(SerialsInPhysicalMemory, SpoofedString, AA_SerialLength);
                //BYTE* Bytes = reinterpret_cast<BYTE*>(const_cast<char*>(SpoofedString));
                //WriteToProtectedMem(SerialsInPhysicalMemory, Bytes, AA_SerialLength);
            }
        }
    }
}

bool IsPhysMemRange ( PHYSICAL_ADDRESS Addr )
{
    for ( int i = 0; i < Runs; ++i )
    {
        if ( ( Addr.QuadPart >= MR [ i ].BaseAddress.QuadPart ) && ( Addr.QuadPart <= ( MR [ i ].BaseAddress.QuadPart + MR [ i ].NumberOfBytes.QuadPart ) ) )
            return true;
    }
    return false;
}
void SetPTEPages ( int id , PVOID addr )
{
    Pages [ id ].PTE->Write = true;
    Pages [ id ].PTE->Present = true;
    Pages [ id ].PTE->PageFrameNumber = ( DWORD64 ) addr >> PAGE_SHIFT;
}

PVOID PageMapper ( PVOID Addy , int id )
{
    SetPTEPages ( id , Addy );
    __invlpg ( Pages [ id ].Page );
    return ( PVOID ) ( ( DWORD64 ) ( Pages [ id ].Page ) + ( ( DWORD64 ) Addy & PAGE_MASK ) );
}
PDPTE_64* ReservedPage1 ( PML4E_64* pml4 , int i , PHYSICAL_ADDRESS addy ) {
    addy.QuadPart = pml4 [ i ].PageFrameNumber << PAGE_SHIFT;
    return ( PDPTE_64* ) PageMapper ( ( PVOID ) addy.QuadPart , PDPT_LEVEL );
}
PVOID RemovePages ( PVOID Addy , int id )
{
    Pages [ id ].PTE->Flags = 0;
    __invlpg ( Pages [ id ].Page );
    return 0;
}
void ScanPhysMem ( )
{
    PHYSICAL_ADDRESS   addr;
    CR3 cr3;
    cr3.Flags = __readcr3 ( );
    addr.QuadPart = cr3.AddressOfPageDirectory << PAGE_SHIFT;

    PhysMemRange ( );

    PML4E_64* pml4 = ( PML4E_64* ) PageMapper ( ( PVOID ) addr.QuadPart , PML4_LEVEL );

    if ( MmIsAddressValid ( pml4 ) == FALSE || pml4 == 0 )
    {
        return;
    }

    for ( int i = 0; i < 512; ++i )
    {
        if ( pml4 [ i ].Present == false )
        {
            continue;
        }

        PDPTE_64* pdpt = ReservedPage1 ( pml4 , i , addr );

        if ( pdpt == 0 || ( MmIsAddressValid ( pdpt ) == FALSE ) )
        {
            continue;
        }


        for ( int ii = 0; ii < 512; ++ii )
        {
            addr.QuadPart = pdpt [ ii ].PageFrameNumber << PAGE_SHIFT;
            if ( pdpt [ ii ].Present == false )
            {
                continue;
            }
            if ( pdpt [ ii ].LargePage == true )
            {
                PDE_64* pageDir = ( PDE_64* ) MmGetVirtualForPhysical ( addr );
                if ( pageDir == 0 || ( MmIsAddressValid ( pageDir ) == FALSE ) )
                {
                    continue;
                }
                for ( int kkk = 0; kkk < 262144; ++kkk )
                {
                    ScanCurrentPages ( ( pageDir + ( kkk * PAGE_SIZE ) ) , PAGE_SIZE , addr );
                }
                continue;
            }
            PDE_64* pageDir = ( PDE_64* ) PageMapper ( ( PVOID ) addr.QuadPart , PD_LEVEL );
            if ( pageDir == 0 || ( MmIsAddressValid ( pageDir ) == FALSE ) )
            {
                continue;
            }
            for ( int iii = 0; iii < 512; ++iii )
            {
                addr.QuadPart = pageDir [ iii ].PageFrameNumber << PAGE_SHIFT;

                if ( pageDir [ iii ].Present == false )
                {
                    continue;
                }
                if ( pageDir [ iii ].LargePage == true )
                {
                    PTE_64* pageTable = ( PTE_64* ) MmGetVirtualForPhysical ( addr );
                    ScanCurrentPages ( pageTable , PAGE_SIZE * 512 , addr );
                    continue;
                }
                PTE_64* pageTable = ( PTE_64* ) PageMapper ( ( PVOID ) addr.QuadPart , PT_LEVEL );
                if ( pageTable == 0 || ( MmIsAddressValid ( pageTable ) == FALSE ) )
                {
                    continue;
                }
                for ( int iiii = 0; iiii < 512; ++iiii )
                {
                    if ( pageTable [ iiii ].Present == false || pageTable [ iiii ].Write == false || pageTable [ iiii ].ExecuteDisable == false )
                    {
                        continue;
                    }
                    addr.QuadPart = pageTable [ iiii ].PageFrameNumber << PAGE_SHIFT;
                    if ( IsPhysMemRange ( addr ) == TRUE )
                    {
                        PVOID64  virtualPage = ( PVOID64 ) PageMapper ( ( PVOID ) addr.QuadPart , 4 );
                        ScanCurrentPages ( virtualPage , PAGE_SIZE , addr );
                        RemovePages ( ( PVOID ) addr.QuadPart , 4 );
                    }
                }
                RemovePages ( ( PVOID ) addr.QuadPart , 3 );
            }
            RemovePages ( ( PVOID ) addr.QuadPart , 2 );
        }
        RemovePages ( ( PVOID ) addr.QuadPart , 1 );
    }
    RemovePages ( ( PVOID ) addr.QuadPart , 0 );
    return;
}

void ShiftPML4 ( PHYSICAL_ADDRESS addr , PML4E_64* pml4 , PML4E_64* pml4e , CR3 HCR , ADDRESS_TRANSLATION_HELPER ATH )
{
    addr.QuadPart = HCR.AddressOfPageDirectory << PAGE_SHIFT;
    pml4 = ( PML4E_64* ) MmGetVirtualForPhysical ( addr );
    pml4e = &pml4 [ ATH.AsIndex.Pml4 ];
}

void ShiftPDPT ( PHYSICAL_ADDRESS addr , PML4E_64* pml4e , PDPTE_64* pdpt , PDPTE_64* pdpte , ADDRESS_TRANSLATION_HELPER ATH )
{
    addr.QuadPart = pml4e->PageFrameNumber << PAGE_SHIFT;
    pdpt = ( PDPTE_64* ) MmGetVirtualForPhysical ( addr );
    pdpte = &pdpt [ ATH.AsIndex.Pdpt ];
}

void ShiftPDE ( PHYSICAL_ADDRESS addr , PDE_64* pd , PDE_64* pde , PDPTE_64* pdpte , ADDRESS_TRANSLATION_HELPER ATH )
{
    addr.QuadPart = pdpte->PageFrameNumber << PAGE_SHIFT;
    pd = ( PDE_64* ) MmGetVirtualForPhysical ( addr );
    pde = &pd [ ATH.AsIndex.Pd ];
}

void ShiftPTE ( PHYSICAL_ADDRESS addr , PTE_64* pt , PTE_64* pte , PDE_64* pde , ADDRESS_TRANSLATION_HELPER ATH )
{
    addr.QuadPart = pde->PageFrameNumber << PAGE_SHIFT;
    pt = ( PTE_64* ) MmGetVirtualForPhysical ( addr );
    pte = &pt [ ATH.AsIndex.Pt ];
}