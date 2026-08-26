#pragma once
#include <ntifs.h>
#include <ntstrsafe.h>

extern "C"
{
	NTSTATUS ObReferenceObjectByName(
		PUNICODE_STRING objectName,
		ULONG attributes,
		PACCESS_STATE accessState,
		ACCESS_MASK desiredAccess,
		POBJECT_TYPE objectType,
		KPROCESSOR_MODE accessMode,
		PVOID parseContext, PVOID* object);

	extern POBJECT_TYPE* IoDriverObjectType;
}

#define IOCTL_NSI_GETALLPARAM 0x0012001B
#define NSI_GET_IP_NET_TABLE   (11)
