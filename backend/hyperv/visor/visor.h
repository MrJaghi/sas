#pragma once

#include <ntddk.h>
#include <intrin.h>
#define HV_TAG 'HVSP'

namespace Hypervisor {
    typedef union _EPT_PML4_ENTRY {
        struct {
            ULONG64 Read : 1;
            ULONG64 Write : 1;
            ULONG64 Execute : 1;
            ULONG64 Reserved1 : 5;
            ULONG64 Accessed : 1;
            ULONG64 IgnorePat : 1;
            ULONG64 ExecuteForUserMode : 1;
            ULONG64 Reserved2 : 1;
            ULONG64 PhysicalAddress : 36;
            ULONG64 Reserved3 : 4;
            ULONG64 SuppressVE : 1;
            ULONG64 Reserved4 : 11;
        };
        ULONG64 AsUInt64;
    } EPT_PML4_ENTRY , * PEPT_PML4_ENTRY;

    typedef union _EPT_PDPT_ENTRY_LARGE {
        struct {
            ULONG64 Read : 1;
            ULONG64 Write : 1;
            ULONG64 Execute : 1;
            ULONG64 MemoryType : 3;
            ULONG64 IgnorePat : 1;
            ULONG64 LargePage : 1;
            ULONG64 Accessed : 1;
            ULONG64 Dirty : 1;
            ULONG64 ExecuteForUserMode : 1;
            ULONG64 Reserved1 : 1;
            ULONG64 PhysicalAddress : 27;
            ULONG64 Reserved2 : 14;
            ULONG64 SuppressVE : 1;
            ULONG64 Reserved3 : 10;
        };
        ULONG64 AsUInt64;
    } EPT_PDPT_ENTRY_LARGE , * PEPT_PDPT_ENTRY_LARGE;

    typedef union _EPT_PD_ENTRY_LARGE {
        struct {
            ULONG64 Read : 1;
            ULONG64 Write : 1;
            ULONG64 Execute : 1;
            ULONG64 MemoryType : 3;
            ULONG64 IgnorePat : 1;
            ULONG64 LargePage : 1;
            ULONG64 Accessed : 1;
            ULONG64 Dirty : 1;
            ULONG64 ExecuteForUserMode : 1;
            ULONG64 Reserved1 : 1;
            ULONG64 PhysicalAddress : 27;
            ULONG64 Reserved2 : 14;
            ULONG64 SuppressVE : 1;
            ULONG64 Reserved3 : 10;
        };
        ULONG64 AsUInt64;
    } EPT_PD_ENTRY_LARGE , * PEPT_PD_ENTRY_LARGE;

    typedef union _EPT_PT_ENTRY {
        struct {
            ULONG64 Read : 1;
            ULONG64 Write : 1;
            ULONG64 Execute : 1;
            ULONG64 MemoryType : 3;
            ULONG64 IgnorePat : 1;
            ULONG64 Accessed : 1;
            ULONG64 Dirty : 1;
            ULONG64 ExecuteForUserMode : 1;
            ULONG64 Reserved1 : 1;
            ULONG64 PhysicalAddress : 36;
            ULONG64 Reserved2 : 6;
            ULONG64 SuppressVE : 1;
            ULONG64 Reserved3 : 10;
        };
        ULONG64 AsUInt64;
    } EPT_PT_ENTRY , * PEPT_PT_ENTRY;

    typedef union _EPT_POINTER {
        struct {
            ULONG64 MemoryType : 3;
            ULONG64 PageWalkLength : 3;
            ULONG64 DirtyAndAceessEnabled : 1;
            ULONG64 Reserved1 : 5;
            ULONG64 PhysicalAddress : 36;
            ULONG64 Reserved2 : 16;
        };
        ULONG64 AsUInt64;
    } EPT_POINTER , * PEPT_POINTER;

    typedef struct _INVEPT_DESCRIPTOR {
        ULONG64 EptPointer;
        ULONG64 Reserved;
    } INVEPT_DESCRIPTOR , * PINVEPT_DESCRIPTOR;

    typedef struct _INVVPID_DESCRIPTOR {
        ULONG64 Vpid : 16;
        ULONG64 Reserved1 : 48;
        ULONG64 Address;
        ULONG64 Reserved2;
    } INVVPID_DESCRIPTOR , * PINVVPID_DESCRIPTOR;

    typedef struct _VMX_CAPABILITIES {
        ULONG64 VmxBasic;
        ULONG64 VmxPinbasedCtls;
        ULONG64 VmxProcbasedCtls;
        ULONG64 VmxExitCtls;
        ULONG64 VmxEntryCtls;
        ULONG64 VmxMisc;
        ULONG64 VmxCr0Fixed0;
        ULONG64 VmxCr0Fixed1;
        ULONG64 VmxCr4Fixed0;
        ULONG64 VmxCr4Fixed1;
        ULONG64 VmxVmcsEnum;
        ULONG64 VmxProcbasedCtls2;
        ULONG64 VmxEptVpidCap;
        ULONG64 VmxTruePinbasedCtls;
        ULONG64 VmxTrueProcbasedCtls;
        ULONG64 VmxTrueExitCtls;
        ULONG64 VmxTrueEntryCtls;
        ULONG64 VmxVMFunc;
        BOOLEAN EptSupported;
        BOOLEAN VpidSupported;
        BOOLEAN UnrestrictedGuest;
        BOOLEAN ApicRegisterVirtualization;
        BOOLEAN SecondaryControls;
    } VMX_CAPABILITIES , * PVMX_CAPABILITIES;

    // EPT
    typedef struct _EPT_HIERARCHY {
        PEPT_PML4_ENTRY Pml4;
        PEPT_PDPT_ENTRY_LARGE Pdpt;
        PEPT_PD_ENTRY_LARGE Pd;
        PEPT_PT_ENTRY Pt;
        ULONG64 PhysicalPml4;
        ULONG64 PhysicalPdpt;
        ULONG64 PhysicalPd;
        ULONG64 PhysicalPt;
        BOOLEAN Allocated;
    } EPT_HIERARCHY , * PEPT_HIERARCHY;

    // VMX
    typedef struct _VMX_STATE {
        ULONG64 VmcsRegion;
        ULONG64 MsrBitmap;
        ULONG64 IoBitmapA;
        ULONG64 IoBitmapB;
        EPT_HIERARCHY Ept;
        EPT_POINTER EptPointer;
        VMX_CAPABILITIES Capabilities;
        BOOLEAN VmxEnabled;
        BOOLEAN VmxLaunched;
        ULONG ProcessorId;
    } VMX_STATE , * PVMX_STATE;



#define VMCS_FIELD_WIDTH_16BIT     0
#define VMCS_FIELD_WIDTH_64BIT     1
#define VMCS_FIELD_WIDTH_32BIT     2
#define VMCS_FIELD_WIDTH_NATURAL   3

#define VMCS_TYPE_CONTROL          0
#define VMCS_TYPE_GUEST_STATE      1
#define VMCS_TYPE_HOST_STATE       2
#define VMCS_TYPE_READ_ONLY        3

#define VMCS_ENCODING(width, index, type) (((width) << 10) | ((index) << 1) | (type))

#define VMCS_GUEST_CR0             VMCS_ENCODING(VMCS_FIELD_WIDTH_64BIT, 0x6800, VMCS_TYPE_GUEST_STATE)
#define VMCS_GUEST_CR3             VMCS_ENCODING(VMCS_FIELD_WIDTH_64BIT, 0x6802, VMCS_TYPE_GUEST_STATE)
#define VMCS_GUEST_CR4             VMCS_ENCODING(VMCS_FIELD_WIDTH_64BIT, 0x6804, VMCS_TYPE_GUEST_STATE)
#define VMCS_GUEST_RIP             VMCS_ENCODING(VMCS_FIELD_WIDTH_64BIT, 0x681E, VMCS_TYPE_GUEST_STATE)
#define VMCS_GUEST_RSP             VMCS_ENCODING(VMCS_FIELD_WIDTH_64BIT, 0x681C, VMCS_TYPE_GUEST_STATE)
#define VMCS_GUEST_RFLAGS          VMCS_ENCODING(VMCS_FIELD_WIDTH_64BIT, 0x6820, VMCS_TYPE_GUEST_STATE)

#define VMCS_HOST_CR0              VMCS_ENCODING(VMCS_FIELD_WIDTH_64BIT, 0x6C00, VMCS_TYPE_HOST_STATE)
#define VMCS_HOST_CR3              VMCS_ENCODING(VMCS_FIELD_WIDTH_64BIT, 0x6C02, VMCS_TYPE_HOST_STATE)
#define VMCS_HOST_CR4              VMCS_ENCODING(VMCS_FIELD_WIDTH_64BIT, 0x6C04, VMCS_TYPE_HOST_STATE)
#define VMCS_HOST_RIP              VMCS_ENCODING(VMCS_FIELD_WIDTH_64BIT, 0x6C1C, VMCS_TYPE_HOST_STATE)
#define VMCS_HOST_RSP              VMCS_ENCODING(VMCS_FIELD_WIDTH_64BIT, 0x6C1A, VMCS_TYPE_HOST_STATE)

#define VMCS_PIN_BASED_VM_EXEC_CONTROL           VMCS_ENCODING(VMCS_FIELD_WIDTH_32BIT, 0x4000, VMCS_TYPE_CONTROL)
#define VMCS_PRIMARY_PROCESSOR_BASED_VM_EXEC_CONTROL VMCS_ENCODING(VMCS_FIELD_WIDTH_32BIT, 0x4002, VMCS_TYPE_CONTROL)
#define VMCS_SECONDARY_PROCESSOR_BASED_VM_EXEC_CONTROL VMCS_ENCODING(VMCS_FIELD_WIDTH_32BIT, 0x401E, VMCS_TYPE_CONTROL)
#define VMCS_VM_EXIT_CONTROLS        VMCS_ENCODING(VMCS_FIELD_WIDTH_32BIT, 0x400C, VMCS_TYPE_CONTROL)
#define VMCS_VM_ENTRY_CONTROLS       VMCS_ENCODING(VMCS_FIELD_WIDTH_32BIT, 0x4012, VMCS_TYPE_CONTROL)
#define VMCS_EXCEPTION_BITMAP        VMCS_ENCODING(VMCS_FIELD_WIDTH_32BIT, 0x4004, VMCS_TYPE_CONTROL)
#define VMCS_EPT_POINTER             VMCS_ENCODING(VMCS_FIELD_WIDTH_64BIT, 0x201A, VMCS_TYPE_CONTROL)

#define IA32_VMX_BASIC_MSR                      0x480
#define IA32_VMX_PINBASED_CTLS_MSR              0x481
#define IA32_VMX_PROCBASED_CTLS_MSR             0x482
#define IA32_VMX_EXIT_CTLS_MSR                  0x483
#define IA32_VMX_ENTRY_CTLS_MSR                 0x484
#define IA32_VMX_MISC_MSR                       0x485
#define IA32_VMX_CR0_FIXED0_MSR                 0x486
#define IA32_VMX_CR0_FIXED1_MSR                 0x487
#define IA32_VMX_CR4_FIXED0_MSR                 0x488
#define IA32_VMX_CR4_FIXED1_MSR                 0x489
#define IA32_VMX_VMCS_ENUM_MSR                  0x48A
#define IA32_VMX_PROCBASED_CTLS2_MSR            0x48B
#define IA32_VMX_EPT_VPID_CAP_MSR               0x48C
#define IA32_VMX_TRUE_PINBASED_CTLS_MSR         0x48D
#define IA32_VMX_TRUE_PROCBASED_CTLS_MSR        0x48E
#define IA32_VMX_TRUE_EXIT_CTLS_MSR             0x48F
#define IA32_VMX_TRUE_ENTRY_CTLS_MSR            0x490
#define IA32_VMX_VMFUNC_MSR                     0x491

#define EPT_MEMORY_TYPE_UNCACHEABLE         0x0
#define EPT_MEMORY_TYPE_WRITE_COMBINING     0x1
#define EPT_MEMORY_TYPE_WRITE_THROUGH       0x4
#define EPT_MEMORY_TYPE_WRITE_PROTECTED     0x5
#define EPT_MEMORY_TYPE_WRITE_BACK          0x6

#define VMX_CTRL_CPU_BASED_HLT_EXITING                        0x00000080
#define VMX_CTRL_CPU_BASED_ACTIVATE_SECONDARY_CONTROLS        0x80000000
#define VMX_CTRL_CPU_BASED2_ENABLE_EPT                        0x00000002
#define VMX_CTRL_CPU_BASED2_ENABLE_RDTSCP                     0x00000008

#define INVEPT_TYPE_SINGLE_CONTEXT     0x00000001
#define INVEPT_TYPE_ALL_CONTEXTS       0x00000002

#define INVVPID_TYPE_INDIVIDUAL_ADDRESS        0x00000000
#define INVVPID_TYPE_SINGLE_CONTEXT            0x00000001
#define INVVPID_TYPE_ALL_CONTEXTS              0x00000002
#define INVVPID_TYPE_SINGLE_CONTEXT_RETAINING_GLOBALS 0x00000003

    extern ULONG VmcsRevisionId;
    extern VMX_STATE g_VmxState;
    extern BOOLEAN g_VmxInitialized;

    NTSTATUS VmxInitialize ( );
    VOID VmxCleanup ( );
    BOOLEAN VmxIsSupported ( );

    NTSTATUS VmxEnable ( );
    NTSTATUS VmxDisable ( );

    NTSTATUS VmcsCreate ( PVMX_STATE VmxState );
    NTSTATUS VmcsDestroy ( PVMX_STATE VmxState );
    NTSTATUS VmcsSetupGuest ( PVMX_STATE VmxState , PVOID GuestRip , PVOID GuestRsp );
    NTSTATUS VmcsSetupHost ( PVMX_STATE VmxState );
    NTSTATUS VmcsSetupControls ( PVMX_STATE VmxState );

    ULONG VmcsRead ( ULONG Field );
    NTSTATUS VmcsWrite ( ULONG Field , ULONG64 Value );
    NTSTATUS VmcsReadNatural ( ULONG Field , PULONG64 Value );
    NTSTATUS VmcsWriteNatural ( ULONG Field , ULONG64 Value );

    NTSTATUS EptInitialize ( PEPT_HIERARCHY Ept );
    VOID EptDestroy ( PEPT_HIERARCHY Ept );
    NTSTATUS EptMapPage ( PEPT_HIERARCHY Ept , ULONG64 GuestPhysical , ULONG64 HostPhysical ,
        ULONG MemoryType , BOOLEAN Writeable , BOOLEAN Executable );
    NTSTATUS EptUnmapPage ( PEPT_HIERARCHY Ept , ULONG64 GuestPhysical );
    NTSTATUS EptProtectPage ( PEPT_HIERARCHY Ept , ULONG64 GuestPhysical ,
        BOOLEAN Writeable , BOOLEAN Executable );
    ULONG64 EptGetPointer ( PEPT_HIERARCHY Ept );

    VOID VmxGetCapabilities ( PVMX_CAPABILITIES Capabilities );
    ULONG VmxGetRevisionId ( );
    ULONG64 VmxAdjustControl ( ULONG Control , ULONG64 MsrValue );
    VOID VmxInvalidateEpt ( ULONG64 EptPointer );
    VOID VmxInvalidateVpid ( USHORT Vpid );

    NTSTATUS VmxLaunch ( PVOID GuestRip , PVOID GuestRsp );
    NTSTATUS VmxResume ( );

    FORCEINLINE VOID VmxOn ( ULONG64 VmxonRegion ) {
        __vmx_on ( &VmxonRegion );
    }

    FORCEINLINE VOID VmxOff ( VOID ) {
        __vmx_off ( );
    }

    FORCEINLINE VOID VmClear ( ULONG64 VmcsRegion ) {
        __vmx_vmclear ( &VmcsRegion );
    }

    FORCEINLINE VOID VmPtrLd ( ULONG64 VmcsRegion ) {
        __vmx_vmptrld ( &VmcsRegion );
    }

    FORCEINLINE VOID VmPtrSt ( PULONG64 VmcsRegion ) {
        __vmx_vmptrst ( VmcsRegion );
    }

    FORCEINLINE VOID VmRead ( ULONG Field , PULONG64 Value ) {
        __vmx_vmread ( Field , Value );
    }

    FORCEINLINE VOID VmWrite ( ULONG Field , ULONG64 Value ) {
        __vmx_vmwrite ( Field , Value );
    }

    FORCEINLINE ULONG VmRead32 ( ULONG Field ) {
        ULONG64 Value;
        __vmx_vmread ( Field , &Value );
        return ( ULONG ) Value;
    }

    FORCEINLINE ULONG64 VmRead64 ( ULONG Field ) {
        ULONG64 Value;
        __vmx_vmread ( Field , &Value );
        return Value;
    }

    FORCEINLINE VOID VmWrite32 ( ULONG Field , ULONG Value ) {
        __vmx_vmwrite ( Field , Value );
    }

    FORCEINLINE VOID VmWrite64 ( ULONG Field , ULONG64 Value ) {
        __vmx_vmwrite ( Field , Value );
    }

    FORCEINLINE VOID VmxLaunchInternal ( VOID ) {
        __vmx_vmlaunch ( );
    }

    FORCEINLINE VOID VmxResumeInternal ( VOID ) {
        __vmx_vmresume ( );
    }
}