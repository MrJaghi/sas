#pragma once
// No-op all kernel debug logging for release builds.
// Include this AFTER kernel headers (ntddk.h/wdm.h) so the original
// DbgPrintEx/DbgPrint declarations are not affected.
#ifdef ENABLE_EPT_PROTECTION
#undef DbgPrintEx
#undef DbgPrint
#define DbgPrintEx(...) ((void)0)
#define DbgPrint(...)   ((void)0)
#endif
