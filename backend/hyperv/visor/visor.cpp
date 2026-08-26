#include "visor.h"

namespace Hypervisor {
    ULONG VmcsRevisionId = 0;
    VMX_STATE g_VmxState = { 0 };
    BOOLEAN g_VmxInitialized = FALSE;

    ULONG VmxGetRevisionId ( ) {
        if ( VmcsRevisionId == 0 ) {
            ULONG64 vmxBasic = __readmsr ( IA32_VMX_BASIC_MSR );
            VmcsRevisionId = ( ULONG ) ( vmxBasic & 0xFFFFFFFF );
        }
        return VmcsRevisionId;
    }

    VOID VmxGetCapabilities ( PVMX_CAPABILITIES Capabilities ) {
        if ( !Capabilities ) return;

        RtlZeroMemory ( Capabilities , sizeof ( VMX_CAPABILITIES ) );

        Capabilities->VmxBasic = __readmsr ( IA32_VMX_BASIC_MSR );
        Capabilities->VmxPinbasedCtls = __readmsr ( IA32_VMX_PINBASED_CTLS_MSR );
        Capabilities->VmxProcbasedCtls = __readmsr ( IA32_VMX_PROCBASED_CTLS_MSR );
        Capabilities->VmxExitCtls = __readmsr ( IA32_VMX_EXIT_CTLS_MSR );
        Capabilities->VmxEntryCtls = __readmsr ( IA32_VMX_ENTRY_CTLS_MSR );
        Capabilities->VmxMisc = __readmsr ( IA32_VMX_MISC_MSR );
        Capabilities->VmxCr0Fixed0 = __readmsr ( IA32_VMX_CR0_FIXED0_MSR );
        Capabilities->VmxCr0Fixed1 = __readmsr ( IA32_VMX_CR0_FIXED1_MSR );
        Capabilities->VmxCr4Fixed0 = __readmsr ( IA32_VMX_CR4_FIXED0_MSR );
        Capabilities->VmxCr4Fixed1 = __readmsr ( IA32_VMX_CR4_FIXED1_MSR );
        Capabilities->VmxVmcsEnum = __readmsr ( IA32_VMX_VMCS_ENUM_MSR );
        Capabilities->VmxProcbasedCtls2 = __readmsr ( IA32_VMX_PROCBASED_CTLS2_MSR );
        Capabilities->VmxEptVpidCap = __readmsr ( IA32_VMX_EPT_VPID_CAP_MSR );
        Capabilities->VmxTruePinbasedCtls = __readmsr ( IA32_VMX_TRUE_PINBASED_CTLS_MSR );
        Capabilities->VmxTrueProcbasedCtls = __readmsr ( IA32_VMX_TRUE_PROCBASED_CTLS_MSR );
        Capabilities->VmxTrueExitCtls = __readmsr ( IA32_VMX_TRUE_EXIT_CTLS_MSR );
        Capabilities->VmxTrueEntryCtls = __readmsr ( IA32_VMX_TRUE_ENTRY_CTLS_MSR );
        Capabilities->VmxVMFunc = __readmsr ( IA32_VMX_VMFUNC_MSR );

        Capabilities->EptSupported = ( Capabilities->VmxProcbasedCtls2 & ( 1ULL << 1 ) ) != 0;
        Capabilities->VpidSupported = ( Capabilities->VmxProcbasedCtls2 & ( 1ULL << 5 ) ) != 0;
        Capabilities->UnrestrictedGuest = ( Capabilities->VmxProcbasedCtls2 & ( 1ULL << 7 ) ) != 0;
        Capabilities->ApicRegisterVirtualization = ( Capabilities->VmxProcbasedCtls2 & ( 1ULL << 0 ) ) != 0;
        Capabilities->SecondaryControls = ( Capabilities->VmxProcbasedCtls & ( 1ULL << 31 ) ) != 0;
    }

    ULONG64 VmxAdjustControl ( ULONG Control , ULONG64 MsrValue ) {
        ULONG64 Low = MsrValue & 0xFFFFFFFF;
        ULONG64 High = ( MsrValue >> 32 ) & 0xFFFFFFFF;
        return ( Control & High ) | ( ~Control & Low );
    }


    VOID VmxInvalidateEpt ( ULONG64 EptPointer ) {
        UNREFERENCED_PARAMETER ( EptPointer );
    }

    VOID VmxInvalidateVpid ( USHORT Vpid ) {
        UNREFERENCED_PARAMETER ( Vpid );
    }

    BOOLEAN VmxIsSupported ( ) {
        INT cpuInfo [ 4 ] = { 0 };

        __cpuid ( cpuInfo , 1 );
        if ( !( cpuInfo [ 2 ] & ( 1 << 5 ) ) ) {
            return FALSE;
        }

        ULONG64 cr4 = __readcr4 ( );
        if ( !( cr4 & 0x2000 ) ) {
            return FALSE;
        }

        ULONG64 featureControl = __readmsr ( 0x3A );
        if ( !( featureControl & 0x1 ) ) {
            return FALSE;
        }

        return TRUE;
    }

    NTSTATUS VmxInitialize ( ) {
        if ( g_VmxInitialized ) {
            return STATUS_SUCCESS;
        }

        if ( !VmxIsSupported ( ) ) {
            return STATUS_NOT_SUPPORTED;
        }

        NTSTATUS status = STATUS_SUCCESS;

        VmxGetCapabilities ( &g_VmxState.Capabilities );

        if ( !g_VmxState.Capabilities.EptSupported ) {
            return STATUS_NOT_SUPPORTED;
        }

        status = EptInitialize ( &g_VmxState.Ept );
        if ( !NT_SUCCESS ( status ) ) {
            return status;
        }

        g_VmxState.EptPointer.AsUInt64 = 0;
        g_VmxState.EptPointer.MemoryType = EPT_MEMORY_TYPE_WRITE_BACK;
        g_VmxState.EptPointer.PageWalkLength = 3;
        g_VmxState.EptPointer.DirtyAndAceessEnabled = 1;
        g_VmxState.EptPointer.PhysicalAddress = g_VmxState.Ept.PhysicalPml4 >> 12;

        g_VmxInitialized = TRUE;
        return STATUS_SUCCESS;
    }

    VOID VmxCleanup ( ) {
        if ( !g_VmxInitialized ) {
            return;
        }

        if ( g_VmxState.VmxLaunched ) {
            VmxDisable ( );
        }

        if ( g_VmxState.Ept.Allocated ) {
            EptDestroy ( &g_VmxState.Ept );
        }

        RtlZeroMemory ( &g_VmxState , sizeof ( VMX_STATE ) );
        g_VmxInitialized = FALSE;
    }

    NTSTATUS VmxEnable ( ) {
        if ( g_VmxState.VmxEnabled ) {
            return STATUS_SUCCESS;
        }

        PHYSICAL_ADDRESS maxPhysAddr;
        maxPhysAddr.QuadPart = MAXULONG64;

        g_VmxState.VmcsRegion = ( ULONG64 ) MmAllocateContiguousMemorySpecifyCache (
            4096 , maxPhysAddr , maxPhysAddr , maxPhysAddr , MmNonCached );

        if ( !g_VmxState.VmcsRegion ) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory ( ( PVOID ) g_VmxState.VmcsRegion , 4096 );

        *( PULONG ) g_VmxState.VmcsRegion = VmxGetRevisionId ( );

        __try {
            VmxOn ( g_VmxState.VmcsRegion );
            g_VmxState.VmxEnabled = TRUE;
            return STATUS_SUCCESS;
        }
        __except ( EXCEPTION_EXECUTE_HANDLER ) {
            MmFreeContiguousMemory ( ( PVOID ) g_VmxState.VmcsRegion );
            g_VmxState.VmcsRegion = 0;
            return GetExceptionCode ( );
        }
    }

    NTSTATUS VmxDisable ( ) {
        if ( !g_VmxState.VmxEnabled ) {
            return STATUS_SUCCESS;
        }

        __try {
            VmxOff ( );

            if ( g_VmxState.VmcsRegion ) {
                MmFreeContiguousMemory ( ( PVOID ) g_VmxState.VmcsRegion );
                g_VmxState.VmcsRegion = 0;
            }

            g_VmxState.VmxEnabled = FALSE;
            g_VmxState.VmxLaunched = FALSE;

            return STATUS_SUCCESS;
        }
        __except ( EXCEPTION_EXECUTE_HANDLER ) {
            return GetExceptionCode ( );
        }
    }

    NTSTATUS VmcsCreate ( PVMX_STATE VmxState ) {
        if ( !VmxState || !VmxState->VmxEnabled ) {
            return STATUS_INVALID_PARAMETER;
        }

        PHYSICAL_ADDRESS maxPhysAddr;
        maxPhysAddr.QuadPart = MAXULONG64;

        ULONG64 vmcsRegion = ( ULONG64 ) MmAllocateContiguousMemorySpecifyCache (
            4096 , maxPhysAddr , maxPhysAddr , maxPhysAddr , MmNonCached );

        if ( !vmcsRegion ) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory ( ( PVOID ) vmcsRegion , 4096 );
        *( PULONG ) vmcsRegion = VmxGetRevisionId ( );

        VmClear ( vmcsRegion );
        VmPtrLd ( vmcsRegion );

        VmxState->VmcsRegion = vmcsRegion;
        return STATUS_SUCCESS;
    }

    NTSTATUS VmcsDestroy ( PVMX_STATE VmxState ) {
        if ( !VmxState || !VmxState->VmcsRegion ) {
            return STATUS_SUCCESS;
        }

        MmFreeContiguousMemory ( ( PVOID ) VmxState->VmcsRegion );
        VmxState->VmcsRegion = 0;
        return STATUS_SUCCESS;
    }

    NTSTATUS VmcsSetupGuest ( PVMX_STATE VmxState , PVOID GuestRip , PVOID GuestRsp ) {
        if ( !VmxState || !GuestRip || !GuestRsp ) {
            return STATUS_INVALID_PARAMETER;
        }

        VmPtrLd ( VmxState->VmcsRegion );

        ULONG64 cr0 = __readcr0 ( );
        ULONG64 cr3 = __readcr3 ( );
        ULONG64 cr4 = __readcr4 ( );

        VmWrite64 ( VMCS_GUEST_CR0 , cr0 );
        VmWrite64 ( VMCS_GUEST_CR3 , cr3 );
        VmWrite64 ( VMCS_GUEST_CR4 , cr4 );

        VmWrite64 ( VMCS_GUEST_RIP , ( ULONG64 ) GuestRip );
        VmWrite64 ( VMCS_GUEST_RSP , ( ULONG64 ) GuestRsp );
        VmWrite64 ( VMCS_GUEST_RFLAGS , 0x2 );

        return STATUS_SUCCESS;
    }

    NTSTATUS VmcsSetupHost ( PVMX_STATE VmxState ) {
        if ( !VmxState ) {
            return STATUS_INVALID_PARAMETER;
        }

        VmPtrLd ( VmxState->VmcsRegion );

        ULONG64 cr0 = __readcr0 ( );
        ULONG64 cr3 = __readcr3 ( );
        ULONG64 cr4 = __readcr4 ( );

        VmWrite64 ( VMCS_HOST_CR0 , cr0 );
        VmWrite64 ( VMCS_HOST_CR3 , cr3 );
        VmWrite64 ( VMCS_HOST_CR4 , cr4 );

        VmWrite64 ( VMCS_HOST_RIP , ( ULONG64 ) VmxLaunchInternal );
        VmWrite64 ( VMCS_HOST_RSP , ( ULONG64 ) _AddressOfReturnAddress ( ) + 8 );

        return STATUS_SUCCESS;
    }

    NTSTATUS VmcsSetupControls ( PVMX_STATE VmxState ) {
        if ( !VmxState ) {
            return STATUS_INVALID_PARAMETER;
        }

        VmPtrLd ( VmxState->VmcsRegion );

        ULONG64 pinbasedCtls = VmxAdjustControl (
            0 ,
            g_VmxState.Capabilities.VmxPinbasedCtls
        );
        VmWrite64 ( VMCS_PIN_BASED_VM_EXEC_CONTROL , pinbasedCtls );

        ULONG64 probasedCtls = VmxAdjustControl (
            VMX_CTRL_CPU_BASED_HLT_EXITING |
            VMX_CTRL_CPU_BASED_ACTIVATE_SECONDARY_CONTROLS ,
            g_VmxState.Capabilities.VmxProcbasedCtls
        );
        VmWrite64 ( VMCS_PRIMARY_PROCESSOR_BASED_VM_EXEC_CONTROL , probasedCtls );

        ULONG64 secondaryCtls = VmxAdjustControl (
            VMX_CTRL_CPU_BASED2_ENABLE_EPT |
            VMX_CTRL_CPU_BASED2_ENABLE_RDTSCP ,
            g_VmxState.Capabilities.VmxProcbasedCtls2
        );
        VmWrite64 ( VMCS_SECONDARY_PROCESSOR_BASED_VM_EXEC_CONTROL , secondaryCtls );

        VmWrite64 ( VMCS_EPT_POINTER , VmxState->EptPointer.AsUInt64 );
        return STATUS_SUCCESS;
    }


    ULONG VmcsRead ( ULONG Field ) {
        ULONG64 value = 0;
        VmRead ( Field , &value );
        return ( ULONG ) value;
    }

    NTSTATUS VmcsWrite ( ULONG Field , ULONG64 Value ) {
        __try {
            VmWrite ( Field , Value );
            return STATUS_SUCCESS;
        }
        __except ( EXCEPTION_EXECUTE_HANDLER ) {
            return GetExceptionCode ( );
        }
    }

    NTSTATUS VmcsReadNatural ( ULONG Field , PULONG64 Value ) {
        if ( !Value ) {
            return STATUS_INVALID_PARAMETER;
        }

        __try {
            VmRead ( Field , Value );
            return STATUS_SUCCESS;
        }
        __except ( EXCEPTION_EXECUTE_HANDLER ) {
            return GetExceptionCode ( );
        }
    }

    NTSTATUS VmcsWriteNatural ( ULONG Field , ULONG64 Value ) {
        return VmcsWrite ( Field , Value );
    }


    NTSTATUS EptInitialize ( PEPT_HIERARCHY Ept ) {
        if ( !Ept || Ept->Allocated ) {
            return STATUS_INVALID_PARAMETER;
        }

        RtlZeroMemory ( Ept , sizeof ( EPT_HIERARCHY ) );

        PHYSICAL_ADDRESS maxPhysAddr;
        maxPhysAddr.QuadPart = MAXULONG64;

        Ept->Pml4 = ( PEPT_PML4_ENTRY ) MmAllocateContiguousMemorySpecifyCache (
            4096 , maxPhysAddr , maxPhysAddr , maxPhysAddr , MmNonCached );
        if ( !Ept->Pml4 ) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory ( Ept->Pml4 , 4096 );
        Ept->PhysicalPml4 = MmGetPhysicalAddress ( Ept->Pml4 ).QuadPart;

        Ept->Pdpt = ( PEPT_PDPT_ENTRY_LARGE ) MmAllocateContiguousMemorySpecifyCache (
            4096 , maxPhysAddr , maxPhysAddr , maxPhysAddr , MmNonCached );
        if ( !Ept->Pdpt ) {
            MmFreeContiguousMemory ( Ept->Pml4 );
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory ( Ept->Pdpt , 4096 );
        Ept->PhysicalPdpt = MmGetPhysicalAddress ( Ept->Pdpt ).QuadPart;

        Ept->Pd = ( PEPT_PD_ENTRY_LARGE ) MmAllocateContiguousMemorySpecifyCache (
            4096 , maxPhysAddr , maxPhysAddr , maxPhysAddr , MmNonCached );
        if ( !Ept->Pd ) {
            MmFreeContiguousMemory ( Ept->Pml4 );
            MmFreeContiguousMemory ( Ept->Pdpt );
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory ( Ept->Pd , 4096 );
        Ept->PhysicalPd = MmGetPhysicalAddress ( Ept->Pd ).QuadPart;

        Ept->Pt = ( PEPT_PT_ENTRY ) MmAllocateContiguousMemorySpecifyCache (
            4096 , maxPhysAddr , maxPhysAddr , maxPhysAddr , MmNonCached );
        if ( !Ept->Pt ) {
            MmFreeContiguousMemory ( Ept->Pml4 );
            MmFreeContiguousMemory ( Ept->Pdpt );
            MmFreeContiguousMemory ( Ept->Pd );
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlZeroMemory ( Ept->Pt , 4096 );
        Ept->PhysicalPt = MmGetPhysicalAddress ( Ept->Pt ).QuadPart;

        // PML4[0] -> PDPT
        Ept->Pml4 [ 0 ].Read = 1;
        Ept->Pml4 [ 0 ].Write = 1;
        Ept->Pml4 [ 0 ].Execute = 1;
        Ept->Pml4 [ 0 ].PhysicalAddress = Ept->PhysicalPdpt >> 12;

        // PDPT[0] -> PD
        Ept->Pdpt [ 0 ].Read = 1;
        Ept->Pdpt [ 0 ].Write = 1;
        Ept->Pdpt [ 0 ].Execute = 1;
        Ept->Pdpt [ 0 ].PhysicalAddress = Ept->PhysicalPd >> 12;

        // PD[0] -> PT
        Ept->Pd [ 0 ].Read = 1;
        Ept->Pd [ 0 ].Write = 1;
        Ept->Pd [ 0 ].Execute = 1;
        Ept->Pd [ 0 ].PhysicalAddress = Ept->PhysicalPt >> 12;

        Ept->Allocated = TRUE;
        return STATUS_SUCCESS;
    }

    VOID EptDestroy ( PEPT_HIERARCHY Ept ) {
        if ( !Ept || !Ept->Allocated ) {
            return;
        }

        if ( Ept->Pt ) {
            MmFreeContiguousMemory ( Ept->Pt );
            Ept->Pt = nullptr;
        }

        if ( Ept->Pd ) {
            MmFreeContiguousMemory ( Ept->Pd );
            Ept->Pd = nullptr;
        }

        if ( Ept->Pdpt ) {
            MmFreeContiguousMemory ( Ept->Pdpt );
            Ept->Pdpt = nullptr;
        }

        if ( Ept->Pml4 ) {
            MmFreeContiguousMemory ( Ept->Pml4 );
            Ept->Pml4 = nullptr;
        }
        Ept->Allocated = FALSE;
    }

    NTSTATUS EptMapPage ( PEPT_HIERARCHY Ept , ULONG64 GuestPhysical , ULONG64 HostPhysical ,
        ULONG MemoryType , BOOLEAN Writeable , BOOLEAN Executable ) {
        if ( !Ept || !Ept->Allocated ) {
            return STATUS_INVALID_PARAMETER;
        }

        ULONG ptIndex = ( GuestPhysical >> 12 ) & 0x1FF;
        if ( ptIndex >= 512 ) {
            return STATUS_INVALID_PARAMETER;
        }

        Ept->Pt [ ptIndex ].AsUInt64 = 0;
        Ept->Pt [ ptIndex ].Read = 1;
        Ept->Pt [ ptIndex ].Write = Writeable ? 1 : 0;
        Ept->Pt [ ptIndex ].Execute = Executable ? 1 : 0;
        Ept->Pt [ ptIndex ].MemoryType = MemoryType;
        Ept->Pt [ ptIndex ].Accessed = 0;
        Ept->Pt [ ptIndex ].Dirty = 0;
        Ept->Pt [ ptIndex ].PhysicalAddress = HostPhysical >> 12;

        return STATUS_SUCCESS;
    }

    NTSTATUS EptUnmapPage ( PEPT_HIERARCHY Ept , ULONG64 GuestPhysical ) {
        if ( !Ept || !Ept->Allocated ) {
            return STATUS_INVALID_PARAMETER;
        }

        ULONG ptIndex = ( GuestPhysical >> 12 ) & 0x1FF;
        if ( ptIndex >= 512 ) {
            return STATUS_INVALID_PARAMETER;
        }

        Ept->Pt [ ptIndex ].AsUInt64 = 0;

        return STATUS_SUCCESS;
    }

    NTSTATUS EptProtectPage ( PEPT_HIERARCHY Ept , ULONG64 GuestPhysical ,
        BOOLEAN Writeable , BOOLEAN Executable ) {
        if ( !Ept || !Ept->Allocated ) {
            return STATUS_INVALID_PARAMETER;
        }

        ULONG ptIndex = ( GuestPhysical >> 12 ) & 0x1FF;
        if ( ptIndex >= 512 ) {
            return STATUS_INVALID_PARAMETER;
        }

        Ept->Pt [ ptIndex ].Write = Writeable ? 1 : 0;
        Ept->Pt [ ptIndex ].Execute = Executable ? 1 : 0;

        return STATUS_SUCCESS;
    }

    ULONG64 EptGetPointer ( PEPT_HIERARCHY Ept ) {
        if ( !Ept || !Ept->Allocated ) {
            return 0;
        }

        EPT_POINTER pointer = { 0 };
        pointer.MemoryType = EPT_MEMORY_TYPE_WRITE_BACK;
        pointer.PageWalkLength = 3;
        pointer.DirtyAndAceessEnabled = 1;
        pointer.PhysicalAddress = ( Ept->PhysicalPml4 >> 12 ) & 0xFFFFFFFFF;

        return pointer.AsUInt64;
    }


    NTSTATUS VmxLaunch ( PVOID GuestRip , PVOID GuestRsp ) {
        if ( !g_VmxState.VmxEnabled || g_VmxState.VmxLaunched ) {
            return STATUS_INVALID_PARAMETER;
        }

        NTSTATUS status = STATUS_SUCCESS;

        status = VmcsCreate ( &g_VmxState );
        if ( !NT_SUCCESS ( status ) ) {
            return status;
        }

        status = VmcsSetupControls ( &g_VmxState );
        if ( !NT_SUCCESS ( status ) ) {
            VmcsDestroy ( &g_VmxState );
            return status;
        }

        status = VmcsSetupHost ( &g_VmxState );
        if ( !NT_SUCCESS ( status ) ) {
            VmcsDestroy ( &g_VmxState );
            return status;
        }

        status = VmcsSetupGuest ( &g_VmxState , GuestRip , GuestRsp );
        if ( !NT_SUCCESS ( status ) ) {
            VmcsDestroy ( &g_VmxState );
            return status;
        }

        __try {
            VmxLaunchInternal ( );
            g_VmxState.VmxLaunched = TRUE;
            return STATUS_SUCCESS;
        }
        __except ( EXCEPTION_EXECUTE_HANDLER ) {
            VmcsDestroy ( &g_VmxState );
            return GetExceptionCode ( );
        }
    }

    NTSTATUS VmxResume ( ) {
        if ( !g_VmxState.VmxEnabled || !g_VmxState.VmxLaunched ) {
            return STATUS_INVALID_PARAMETER;
        }

        __try {
            VmxResumeInternal ( );
            return STATUS_SUCCESS;
        }
        __except ( EXCEPTION_EXECUTE_HANDLER ) {
            return GetExceptionCode ( );
        }
    }
}