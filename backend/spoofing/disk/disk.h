#pragma once
#include "../../../backend/functions/functions.h"
#include <classpnp.h>

#include <ata.h>
#include <nvme.h>
#include "serial db/database.h"
#include "diskmodels.h"
#include <mountmgr.h>
#include <mountdev.h>
#include "../../protection/oxorany/oxorany.h"
#include "../../../nolog.h"

typedef NTSTATUS ( __fastcall* DiskEnableDisableFailurePrediction )( void* a1 , bool a2 );
#define NVME_STORPORT_DRIVER 0xE000
#define IOCTL_INTEL_NVME_PASS_THROUGH CTL_CODE(0xf000, 0xA02, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define NVME_PASS_THROUGH_SRB_IO_CODE CTL_CODE(NVME_STORPORT_DRIVER, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define NVME_RESET_DEVICE CTL_CODE(NVME_STORPORT_DRIVER, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define NVME_HOT_ADD_NAMESPACE CTL_CODE(NVME_STORPORT_DRIVER, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define NVME_HOT_REMOVE_NAMESPACE CTL_CODE(NVME_STORPORT_DRIVER, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define NVME_SIG_STR          "NvmeMini"
#define NVME_SIG_STR_LEN      8
#define SCSI_SIG_STR          "SCSIDISK"
#define SCSI_SIG_STR_LEN      8
#define NVME_NO_DATA_TX       0
#define NVME_FROM_HOST_TO_DEV 1
#define NVME_FROM_DEV_TO_HOST 2
#define NVME_BI_DIRECTION     3

#define NVME_IOCTL_VENDOR_SPECIFIC_DW_SIZE 6
#define NVME_IOCTL_CMD_DW_SIZE             16
#define NVME_IOCTL_COMPLETE_DW_SIZE        4

typedef struct _WWN {
	USHORT WorldWideName [ 4 ];
	USHORT ReservedForWorldWideName128 [ 4 ];
} WWN , * PWWN;

typedef union
{
	struct
	{
		ULONG Opcode : 8;
		ULONG FUSE : 2;
		ULONG _Rsvd : 4;
		ULONG PSDT : 2;
		ULONG CID : 16;
	} DUMMYSTRUCTNAME;
	ULONG AsDWord;
} NVME_CDW0 , * PNVME_CDW0;

typedef union
{
	struct
	{
		ULONG   CNS : 2;
		ULONG   _Rsvd : 30;
	} DUMMYSTRUCTNAME;
	ULONG AsDWord;
} NVME_IDENTIFY_CDW10 , * PNVME_IDENTIFY_CDW10;

struct ata_identify_device {
	unsigned short words000_009 [ 10 ];
	unsigned char  serial_no [ 20 ];
	unsigned short words020_022 [ 3 ];
	unsigned char  fw_rev [ 8 ];
	unsigned char  model [ 40 ];
	unsigned short words047_079 [ 33 ];
	unsigned short major_rev_num;
	unsigned short minor_rev_num;
	unsigned short command_set_1;
	unsigned short command_set_2;
	unsigned short command_set_extension;
	unsigned short cfs_enable_1;
	unsigned short word086;
	unsigned short csf_default;
	unsigned short words088_255 [ 168 ];
};

typedef union
{
	struct
	{
		ULONG   LID : 8;
		ULONG   _Rsvd1 : 8;
		ULONG   NUMD : 12;
		ULONG   _Rsvd2 : 4;
	} DUMMYSTRUCTNAME;
	ULONG   AsDWord;
} NVME_GET_LOG_PAGE_CDW10 , * PNVME_GET_LOG_PAGE_CDW10;

typedef union
{
	struct
	{
		ULONG   LID : 8;
		ULONG   LSP : 4;
		ULONG   Reserved0 : 3;
		ULONG   RAE : 1;
		ULONG   NUMDL : 16;
	} DUMMYSTRUCTNAME;
	ULONG   AsDWord;
} NVME_GET_LOG_PAGE_CDW10_V13 , * PNVME_GET_LOG_PAGE_CDW10_V13;

typedef struct
{
	NVME_CDW0           CDW0;
	ULONG               NSID;
	ULONG               _Rsvd [ 2 ];
	ULONGLONG           MPTR;
	ULONGLONG           PRP1;
	ULONGLONG           PRP2;
	union
	{
		struct
		{
			NVME_IDENTIFY_CDW10 CDW10;
			ULONG   CDW11;
			ULONG   CDW12;
			ULONG   CDW13;
			ULONG   CDW14;
			ULONG   CDW15;
		} IDENTIFY;
		struct
		{
			NVME_GET_LOG_PAGE_CDW10 CDW10;
			ULONG   CDW11;
			ULONG   CDW12;
			ULONG   CDW13;
			ULONG   CDW14;
			ULONG   CDW15;
		} GET_LOG_PAGE;
	} u;
} NVME_CMD , * PNVME_CMD;

typedef struct _INTEL_NVME_PAYLOAD
{
	BYTE    Version;
	BYTE    PathId;
	BYTE    TargetID;
	BYTE    Lun;
	NVME_CMD Cmd;
	DWORD   CplEntry [ 4 ];
	DWORD   QueueId;
	DWORD   ParamBufLen;
	DWORD   ReturnBufferLen;
	BYTE    __rsvd2 [ 0x28 ];
} INTEL_NVME_PAYLOAD , * PINTEL_NVME_PAYLOAD;

typedef struct _INTEL_NVME_PASS_THROUGH
{
	SRB_IO_CONTROL SRB;
	INTEL_NVME_PAYLOAD Payload;
	BYTE DataBuffer [ 0x1000 ];
} INTEL_NVME_PASS_THROUGH , * PINTEL_NVME_PASS_THROUGH;

typedef struct _NVME_PASS_THROUGH_IOCTL
{
	SRB_IO_CONTROL SrbIoCtrl;
	ULONG          VendorSpecific [ NVME_IOCTL_VENDOR_SPECIFIC_DW_SIZE ];
	ULONG          NVMeCmd [ NVME_IOCTL_CMD_DW_SIZE ];
	ULONG          CplEntry [ NVME_IOCTL_COMPLETE_DW_SIZE ];
	ULONG          Direction;
	ULONG          QueueId;
	ULONG          DataBufferLen;
	ULONG          MetaDataLen;
	ULONG          ReturnBufferLen;
	UCHAR          DataBuffer [ 1 ];
} NVME_PASS_THROUGH_IOCTL , * PNVME_PASS_THROUGH_IOCTL;

struct NVME_IDENTIFY_DEVICE
{
	CHAR		Reserved1 [ 4 ];
	CHAR		SerialNumber [ 20 ];
	CHAR		Model [ 40 ];
	CHAR		FirmwareRev [ 8 ];
	CHAR		Reserved2 [ 9 ];
	CHAR		MinorVersion;
	SHORT		MajorVersion;
	CHAR		Reserved3 [ 428 ];
	CHAR		Reserved4 [ 3584 ];
};

// Protocol-specific data for SQP PropertyId 49/50 (NVMe protocol queries)
struct KMDF_PROTO_SPECIFIC_DATA {
	ULONG ProtocolType;               // 3 = NVMe
	ULONG DataType;                   // 1 = Identify, 2 = LogPage
	ULONG ProtocolDataRequestValue;   // CNS for Identify, LogPageId for LogPage
	ULONG ProtocolDataRequestSubValue;// NSID
	ULONG ProtocolDataOffset;         // Offset from start of this struct to data
	ULONG ProtocolDataLength;
};

struct KMDF_PROTO_DATA_DESCRIPTOR {
	ULONG Version;
	ULONG Size;
	KMDF_PROTO_SPECIFIC_DATA ProtocolSpecificData;
};

// SCSI Adapter Bus Info structures for IOCTL_SCSI_GET_INQUIRY_DATA
struct KMDF_SCSI_BUS_DATA {
	UCHAR NumberOfLogicalUnits;
	UCHAR InitiatorBusId;
	ULONG InquiryDataOffset;
};

struct KMDF_SCSI_ADAPTER_BUS_INFO {
	UCHAR NumberOfBuses;
	KMDF_SCSI_BUS_DATA BusData[1];
};

struct KMDF_SCSI_INQUIRY_DATA {
	UCHAR PathId;
	UCHAR TargetId;
	UCHAR Lun;
	BOOLEAN DeviceClaimed;
	ULONG InquiryDataLength;
	ULONG NextInquiryDataOffset;
	UCHAR InquiryData[1];
};

#define SPT_CDB_LENGTH 32
#define SPT_SENSE_LENGTH 32
#define SPTWB_DATA_LENGTH 512

typedef struct _SCSI_PASS_THROUGH_WITH_BUFFERS_EX {
	SCSI_PASS_THROUGH_EX Spt;
	UCHAR             ucCdbBuf [ SPT_CDB_LENGTH - 1 ];
	ULONG             Filler;
	UCHAR             ucSenseBuf [ SPT_SENSE_LENGTH ];
	UCHAR             ucDataBuf [ SPTWB_DATA_LENGTH ];
} SCSI_PASS_THROUGH_WITH_BUFFERS_EX , * PSCSI_PASS_THROUGH_WITH_BUFFERS_EX;

typedef struct _IDINFO
{
	USHORT	wGenConfig;
	USHORT	wNumCyls;
	USHORT	wReserved;
	USHORT	wNumHeads;
	USHORT	wBytesPerTrack;
	USHORT	wBytesPerSector;
	USHORT	wNumSectorsPerTrack;
	USHORT	wVendorUnique [ 3 ];
	CHAR	sSerialNumber [ 20 ];
	USHORT	wBufferType;
	USHORT	wBufferSize;
	USHORT	wECCSize;
	CHAR	sFirmwareRev [ 8 ];
	CHAR	sModelNumber [ 40 ];
	USHORT	wMoreVendorUnique;
	USHORT	wDoubleWordIO;
	struct {
		USHORT	Reserved : 8;
		USHORT	DMA : 1;
		USHORT	LBA : 1;
		USHORT	DisIORDY : 1;
		USHORT	IORDY : 1;
		USHORT	SoftReset : 1;
		USHORT	Overlap : 1;
		USHORT	Queue : 1;
		USHORT	InlDMA : 1;
	} wCapabilities;
	USHORT	wReserved1;
	USHORT	wPIOTiming;
	USHORT	wDMATiming;
	struct {
		USHORT	CHSNumber : 1;
		USHORT	CycleNumber : 1;
		USHORT	UnltraDMA : 1;
		USHORT	Reserved : 13;
	} wFieldValidity;
	USHORT	wNumCurCyls;
	USHORT	wNumCurHeads;
	USHORT	wNumCurSectorsPerTrack;
	USHORT	wCurSectorsLow;
	USHORT	wCurSectorsHigh;
	struct {
		USHORT	CurNumber : 8;
		USHORT	Multi : 1;
		USHORT	Reserved : 7;
	} wMultSectorStuff;
	ULONG	dwTotalSectors;
	USHORT	wSingleWordDMA;
	struct {
		USHORT	Mode0 : 1;
		USHORT	Mode1 : 1;
		USHORT	Mode2 : 1;
		USHORT	Reserved1 : 5;
		USHORT	Mode0Sel : 1;
		USHORT	Mode1Sel : 1;
		USHORT	Mode2Sel : 1;
		USHORT	Reserved2 : 5;
	} wMultiWordDMA;
	struct {
		USHORT	AdvPOIModes : 8;
		USHORT	Reserved : 8;
	} wPIOCapacity;
	USHORT	wMinMultiWordDMACycle;
	USHORT	wRecMultiWordDMACycle;
	USHORT	wMinPIONoFlowCycle;
	USHORT	wMinPOIFlowCycle;
	USHORT	wReserved69 [ 11 ];
	struct {
		USHORT	Reserved1 : 1;
		USHORT	ATA1 : 1;
		USHORT	ATA2 : 1;
		USHORT	ATA3 : 1;
		USHORT	ATA4 : 1;
		USHORT	ATA5 : 1;
		USHORT	ATA6 : 1;
		USHORT	ATA7 : 1;
		USHORT	ATA8 : 1;
		USHORT	ATA9 : 1;
		USHORT	ATA10 : 1;
		USHORT	ATA11 : 1;
		USHORT	ATA12 : 1;
		USHORT	ATA13 : 1;
		USHORT	ATA14 : 1;
		USHORT	Reserved2 : 1;
	} wMajorVersion;
	USHORT	wMinorVersion;
	USHORT	wReserved82 [ 6 ];
	struct {
		USHORT	Mode0 : 1;
		USHORT	Mode1 : 1;
		USHORT	Mode2 : 1;
		USHORT	Mode3 : 1;
		USHORT	Mode4 : 1;
		USHORT	Mode5 : 1;
		USHORT	Mode6 : 1;
		USHORT	Mode7 : 1;
		USHORT	Mode0Sel : 1;
		USHORT	Mode1Sel : 1;
		USHORT	Mode2Sel : 1;
		USHORT	Mode3Sel : 1;
		USHORT	Mode4Sel : 1;
		USHORT	Mode5Sel : 1;
		USHORT	Mode6Sel : 1;
		USHORT	Mode7Sel : 1;
	} wUltraDMA;
	USHORT	wReserved89 [ 167 ];
} IDINFO , * PIDINFO;

typedef struct _IDSECTOR {
	USHORT  wGenConfig;
	USHORT  wNumCyls;
	USHORT  wReserved;
	USHORT  wNumHeads;
	USHORT  wBytesPerTrack;
	USHORT  wBytesPerSector;
	USHORT  wSectorsPerTrack;
	USHORT  wVendorUnique [ 3 ];
	CHAR    sSerialNumber [ 20 ];
	USHORT  wBufferType;
	USHORT  wBufferSize;
	USHORT  wECCSize;
	CHAR    sFirmwareRev [ 8 ];
	CHAR    sModelNumber [ 40 ];
	USHORT  wMoreVendorUnique;
	USHORT  wDoubleWordIO;
	USHORT  wCapabilities;
	USHORT  wReserved1;
	USHORT  wPIOTiming;
	USHORT  wDMATiming;
	USHORT  wBS;
	USHORT  wNumCurrentCyls;
	USHORT  wNumCurrentHeads;
	USHORT  wNumCurrentSectorsPerTrack;
	ULONG   ulCurrentSectorCapacity;
	USHORT  wMultSectorStuff;
	ULONG   ulTotalAddressableSectors;
	USHORT  wSingleWordDMA;
	USHORT  wMultiWordDMA;
	BYTE    bThisReserved [ 128 ];
} IDSECTOR , * PIDSECTOR;

// ============================================================================
// Driver dispatch pointers
// ============================================================================

PDRIVER_DISPATCH g_original_partmgr_control = 0;
PDRIVER_DISPATCH g_original_disk_control = 0;
PDRIVER_DISPATCH g_original_mountmgr_control = 0;
PDRIVER_DISPATCH HDD_Disk_Control = 0;
PDRIVER_DISPATCH store_port = 0;

// Additional driver hooks
PDRIVER_DISPATCH g_original_storahci_control = 0;
PDRIVER_DISPATCH g_original_stornvme_control = 0;
PDRIVER_DISPATCH g_original_spaceport_control = 0;
PDRIVER_DISPATCH g_original_volmgr_control = 0;
PDRIVER_DISPATCH g_original_ntfs_volinfo = 0;

// Multi-driver dispatch table: maps DriverObject -> original function
struct DiskHookEntry {
	PDRIVER_OBJECT driverObject;
	PDRIVER_DISPATCH original;
};
#define MAX_DISK_HOOKS 16
static DiskHookEntry g_diskHooks[MAX_DISK_HOOKS] = {};
static int g_diskHookCount = 0;

// ============================================================================
// Multi-entry serial cache
// ============================================================================

#define DISK_SERIAL_MAX_LENGTH 20
#define MAX_SERIAL_CACHE 64
#define MAX_WWN_CACHE 32

struct SerialCacheEntry {
	char orig[64];
	char spoofed[64];
	int sz;
};

struct WwnCacheEntry {
	WWN orig;
	WWN spoofed;
};

static SerialCacheEntry g_serialCache[MAX_SERIAL_CACHE] = {};
static int g_serialCount = 0;
static WwnCacheEntry g_wwnCache[MAX_WWN_CACHE] = {};
static int g_wwnCount = 0;

// ============================================================================
// Model cache (Phase 2)
// ============================================================================

#define MAX_MODEL_CACHE 64

struct ModelCacheEntry {
	char orig[41];
	char spoofed[41];
	int len;
};

static ModelCacheEntry g_modelCache[MAX_MODEL_CACHE] = {};
static int g_modelCount = 0;

// ============================================================================
// Volume GUID cache (Phase 5)
// ============================================================================

#define VOLUME_GUID_MAX_LENGTH 0x24
#define GUID_OFFSET 22
#define MAX_VOL_GUID_CACHE 64

struct VolumeGuidCacheEntry {
	wchar_t orig[VOLUME_GUID_MAX_LENGTH + 1];
	wchar_t spoofed[VOLUME_GUID_MAX_LENGTH + 1];
};

static VolumeGuidCacheEntry g_volGuidCache[MAX_VOL_GUID_CACHE] = {};
static int g_volGuidCount = 0;

// ============================================================================
// RNG and hash helpers
// ============================================================================

ULONG DiskLCG(ULONG& value) {
	const ULONG a = 1664525;
	const ULONG c = 1013904223;
	value = a * value + c;
	return value;
}

ULONG HashSerialBytes(const char* s, int len) {
	ULONG h = 0x811C9DC5;
	for (int i = 0; i < len; i++) {
		h ^= (UCHAR)s[i];
		h *= 0x01000193;
	}
	return h;
}

void ShuffleBytes(char* data, int len, ULONG seed) {
	for (int i = len - 1; i > 0; i--) {
		ULONG r = DiskLCG(seed);
		int j = r % (i + 1);
		char tmp = data[i];
		data[i] = data[j];
		data[j] = tmp;
	}
}

void SpoofSerialChars(char* serial, int len, ULONG baseSeed) {
	ULONG seed = baseSeed ^ HashSerialBytes(serial, len);

	bool bHexOnly = true;
	for (int i = 0; i < len; i++) {
		char c = serial[i];
		if (c == ' ' || c == '_' || c == '-' || c == '.' || c == '\0' || c == ';') continue;
		if ((c >= 'G' && c <= 'Z') || (c >= 'g' && c <= 'z')) {
			bHexOnly = false;
			break;
		}
	}

	static const char hexCharset[] = "0123456789ABCDEF";
	static const char digitCharset[] = "0123456789";
	static const char letterCharset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	static const char letterCharsetLower[] = "abcdefghijklmnopqrstuvwxyz";

	if (bHexOnly) {
		// NVMe hex serial: preserve zero BYTES (0x00->"00"), randomize non-zero bytes in pairs
		int hexPos[64];
		int numHex = 0;
		for (int i = 0; i < len && numHex < 64; i++) {
			char c = serial[i];
			if (c == ' ' || c == '_' || c == '-' || c == '.' || c == '\0' || c == ';') continue;
			hexPos[numHex++] = i;
		}
		for (int p = 0; p < numHex - 1; p += 2) {
			if (p < 2) continue; // preserve first byte
			int hi = hexPos[p], lo = hexPos[p + 1];
			if (serial[hi] == '0' && serial[lo] == '0') continue; // zero byte
			ULONG r1 = DiskLCG(seed);
			ULONG r2 = DiskLCG(seed);
			serial[hi] = hexCharset[r1 % 16];
			serial[lo] = hexCharset[r2 % 16];
		}
	} else {
		for (int i = 2; i < len; i++) {
			char c = serial[i];
			if (c == ' ' || c == '_' || c == '-' || c == '.' || c == '\0' || c == ';') continue;
			ULONG r = DiskLCG(seed);
			if (c >= '0' && c <= '9') {
				serial[i] = digitCharset[r % 10];
			} else if (c >= 'a' && c <= 'z') {
				serial[i] = letterCharsetLower[r % 26];
			} else {
				serial[i] = letterCharset[r % 26];
			}
		}
	}
}

// ============================================================================
// SMART attribute zeroing helper
// ============================================================================

void ZeroSmartAttributes(PVOID buffer, int len) {
	// SMART attribute table starts at offset 2, each attribute is 12 bytes
	// Attribute ID 9 = Power-On Hours, ID 12 = Power Cycle Count
	if (!buffer || !MmIsAddressValid(buffer) || len < 362) return;
	UCHAR* data = (UCHAR*)buffer;
	for (int i = 0; i < 30; i++) {
		int off = 2 + i * 12;
		if (off + 12 > len) break;
		UCHAR attrId = data[off];
		if (attrId == 0) break; // end of attributes
		if (attrId == 9 || attrId == 12) {
			// Zero the raw value (bytes 5-10 of the attribute entry)
			RtlZeroMemory(&data[off + 5], 6);
		}
	}
}

// Spoof NVMe firmware revision (8-byte ASCII)
void SpoofFirmwareRevision(char* fwRev, int len, ULONG seed) {
	if (!fwRev || !MmIsAddressValid(fwRev)) return;
	bool allZero = true;
	for (int i = 0; i < len; i++) {
		if (fwRev[i] != 0 && fwRev[i] != ' ') { allZero = false; break; }
	}
	if (allZero) return;
	seed ^= HashSerialBytes(fwRev, len);
	static const char fwDigits[] = "0123456789";
	static const char fwLetters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	static const char fwLettersLower[] = "abcdefghijklmnopqrstuvwxyz";
	for (int i = 0; i < len; i++) {
		char c = fwRev[i];
		if (c == 0 || c == ' ') continue;
		ULONG r = DiskLCG(seed);
		if (c >= '0' && c <= '9') {
			fwRev[i] = fwDigits[r % 10];
		} else if (c >= 'a' && c <= 'z') {
			fwRev[i] = fwLettersLower[r % 26];
		} else {
			fwRev[i] = fwLetters[r % 26];
		}
	}
}

// Spoof binary data (EUI64/NGUID) using LCG, preserving zero bytes
void SpoofBinaryIdentifier(UCHAR* data, int len, ULONG seed) {
	if (!data || !MmIsAddressValid(data) || len <= 0) return;
	bool allZero = true;
	for (int i = 0; i < len; i++) {
		if (data[i] != 0) { allZero = false; break; }
	}
	if (allZero) return;
	seed ^= HashSerialBytes((const char*)data, len);
	for (int i = 0; i < len; i++) {
		if (data[i] == 0) continue;
		ULONG r = DiskLCG(seed);
		data[i] = (UCHAR)(r & 0xFF);
		if (data[i] == 0) data[i] = 1; // avoid zero to preserve non-zero pattern
	}
}

// ============================================================================
// Serial spoofing (Phase 3: improved with trimmed/separator-stripped matching)
// ============================================================================

static int TrimSerialLen(const char* s, int len) {
	while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\0'))
		len--;
	return len;
}

bool FindFakeDiskSerial(char* pOriginal, int len = DISK_SERIAL_MAX_LENGTH) {
	if (!pOriginal || (ULONG_PTR)pOriginal < 0xFFFF800000000000ULL)
		return false;
	if (!MmIsAddressValid(pOriginal))
		return false;

	if (pOriginal[0] == 0 && len > 1)
		pOriginal++;

	int inputTrimmed = TrimSerialLen(pOriginal, len);

	// Exact match (fast path)
	for (int i = 0; i < g_serialCount; i++) {
		if (g_serialCache[i].sz == len && !memcmp(g_serialCache[i].orig, pOriginal, len)) {
			RtlCopyMemory(pOriginal, g_serialCache[i].spoofed, len);
			return true;
		}
		// Trimmed match: same meaningful content but different trailing padding
		int entryTrimmed = TrimSerialLen(g_serialCache[i].orig, g_serialCache[i].sz);
		if (entryTrimmed > 0 && entryTrimmed == inputTrimmed
			&& !memcmp(g_serialCache[i].orig, pOriginal, entryTrimmed)) {
			int writeLen = len < g_serialCache[i].sz ? len : g_serialCache[i].sz;
			RtlCopyMemory(pOriginal, g_serialCache[i].spoofed, writeLen);
			return true;
		}
	}

	// Already spoofed? (init code may modify device extension in-place)
	for (int i = 0; i < g_serialCount; i++) {
		if (g_serialCache[i].sz == len && !memcmp(g_serialCache[i].spoofed, pOriginal, len)) {
			return true;
		}
		int entryTrimmed = TrimSerialLen(g_serialCache[i].spoofed, g_serialCache[i].sz);
		if (entryTrimmed > 0 && entryTrimmed == inputTrimmed
			&& !memcmp(g_serialCache[i].spoofed, pOriginal, entryTrimmed)) {
			return true;
		}
	}

	// Separator-stripped match: same serial with different separator formatting
	{
		char inputStripped[64];
		int inputSrcPos[64];
		int inputStrippedLen = 0;
		for (int i = 0; i < len && inputStrippedLen < 64; i++) {
			char c = pOriginal[i];
			if (c == '_' || c == '-' || c == '.' || c == ' ' || c == '\0') continue;
			inputSrcPos[inputStrippedLen] = i;
			inputStripped[inputStrippedLen++] = c;
		}

		if (inputStrippedLen > 2) {
			for (int i = 0; i < g_serialCount; i++) {
				// Strip entry's original
				char entryStripped[64];
				int entryStrippedLen = 0;
				for (int j = 0; j < g_serialCache[i].sz && entryStrippedLen < 64; j++) {
					char c = g_serialCache[i].orig[j];
					if (c == '_' || c == '-' || c == '.' || c == ' ' || c == '\0') continue;
					entryStripped[entryStrippedLen++] = c;
				}

				if (entryStrippedLen == inputStrippedLen
					&& !memcmp(entryStripped, inputStripped, entryStrippedLen)) {
					// Same base serial — use matched entry's spoofed chars
					char spoofStripped[64];
					int spoofStrippedLen = 0;
					for (int j = 0; j < g_serialCache[i].sz && spoofStrippedLen < 64; j++) {
						char c = g_serialCache[i].spoofed[j];
						if (c == '_' || c == '-' || c == '.' || c == ' ' || c == '\0') continue;
						spoofStripped[spoofStrippedLen++] = c;
					}
					int writeCount = inputStrippedLen < spoofStrippedLen ? inputStrippedLen : spoofStrippedLen;
					for (int k = 0; k < writeCount; k++) {
						pOriginal[inputSrcPos[k]] = spoofStripped[k];
					}
					DbgPrintEx(0, 0, "[SPOOF] Serial (stripped match): <%.20s> -> <%.20s>\n",
						g_serialCache[i].orig, g_serialCache[i].spoofed);
					return true;
				}

				// Also check if already spoofed with different separators
				char spoofStripped2[64];
				int spoofStrippedLen2 = 0;
				for (int j = 0; j < g_serialCache[i].sz && spoofStrippedLen2 < 64; j++) {
					char c = g_serialCache[i].spoofed[j];
					if (c == '_' || c == '-' || c == '.' || c == ' ' || c == '\0') continue;
					spoofStripped2[spoofStrippedLen2++] = c;
				}
				if (spoofStrippedLen2 == inputStrippedLen
					&& !memcmp(spoofStripped2, inputStripped, inputStrippedLen)) {
					return true; // already spoofed, different separator format
				}
			}
		}
	}

	// New serial - create cache entry
	if (g_serialCount >= MAX_SERIAL_CACHE) return false;

	SerialCacheEntry* entry = &g_serialCache[g_serialCount];
	entry->sz = len;
	RtlZeroMemory(entry->orig, sizeof(entry->orig));
	RtlZeroMemory(entry->spoofed, sizeof(entry->spoofed));
	RtlCopyMemory(entry->orig, pOriginal, len);
	RtlCopyMemory(entry->spoofed, pOriginal, len);

	SpoofSerialChars(entry->spoofed, len, kmdf_settings::hwid_seed);

	DbgPrintEx(0, 0, "[SPOOF] Serial [%d]: <%.20s> -> <%.20s>\n", g_serialCount, entry->orig, entry->spoofed);
	g_serialCount++;
	RtlCopyMemory(pOriginal, entry->spoofed, len);
	return true;
}

bool FindFakeWWN(WWN* pOriginal) {
	if (!pOriginal || !MmIsAddressValid(pOriginal))
		return false;

	for (int i = 0; i < g_wwnCount; i++) {
		if (g_wwnCache[i].orig.WorldWideName[0] == pOriginal->WorldWideName[0]) {
			RtlCopyMemory(pOriginal, &g_wwnCache[i].spoofed, sizeof(WWN));
			return true;
		}
	}

	if (g_wwnCount >= MAX_WWN_CACHE) return false;

	WwnCacheEntry* entry = &g_wwnCache[g_wwnCount];
	entry->orig = *pOriginal;
	entry->spoofed = *pOriginal;

	ULONG seed = kmdf_settings::hwid_seed;
	ShuffleBytes((char*)&entry->spoofed.WorldWideName[1], 6, seed);

	DbgPrintEx(0, 0, "[SPOOF] WWN: <%04X%04X%04X%04X> -> <%04X%04X%04X%04X>\n",
		entry->orig.WorldWideName[0], entry->orig.WorldWideName[1],
		entry->orig.WorldWideName[2], entry->orig.WorldWideName[3],
		entry->spoofed.WorldWideName[0], entry->spoofed.WorldWideName[1],
		entry->spoofed.WorldWideName[2], entry->spoofed.WorldWideName[3]);

	// Register hex string of WWN in serial cache so buffer scanning can match
	if (g_serialCount < MAX_SERIAL_CACHE) {
		static const char hc[] = "0123456789ABCDEF";
		SerialCacheEntry* se = &g_serialCache[g_serialCount];
		se->sz = 16;
		RtlZeroMemory(se->orig, sizeof(se->orig));
		RtlZeroMemory(se->spoofed, sizeof(se->spoofed));
		for (int j = 0; j < 4; j++) {
			USHORT ow = entry->orig.WorldWideName[j];
			USHORT sw = entry->spoofed.WorldWideName[j];
			se->orig[j * 4]     = hc[(ow >> 12) & 0xF];
			se->orig[j * 4 + 1] = hc[(ow >> 8) & 0xF];
			se->orig[j * 4 + 2] = hc[(ow >> 4) & 0xF];
			se->orig[j * 4 + 3] = hc[ow & 0xF];
			se->spoofed[j * 4]     = hc[(sw >> 12) & 0xF];
			se->spoofed[j * 4 + 1] = hc[(sw >> 8) & 0xF];
			se->spoofed[j * 4 + 2] = hc[(sw >> 4) & 0xF];
			se->spoofed[j * 4 + 3] = hc[sw & 0xF];
		}
		g_serialCount++;
	}

	g_wwnCount++;
	RtlCopyMemory(pOriginal, &entry->spoofed, sizeof(WWN));
	return true;
}

// ============================================================================
// ATA byte-swap helpers
// ============================================================================

__forceinline void AtaSwapBytesPairs(char* str, int len) {
	for (int i = 0; i < len - 1; i += 2) {
		char tmp = str[i];
		str[i] = str[i + 1];
		str[i + 1] = tmp;
	}
}

__forceinline void FindFakeDiskSerialAta(char* pOriginal, int len = DISK_SERIAL_MAX_LENGTH) {
	char swapBuf[41] = { 0 };
	if (len > 40) len = 40;
	RtlCopyMemory(swapBuf, pOriginal, len);
	AtaSwapBytesPairs(swapBuf, len);
	FindFakeDiskSerial(swapBuf, len);
	AtaSwapBytesPairs(swapBuf, len);
	RtlCopyMemory(pOriginal, swapBuf, len);
}

static void SmartFixupSerial(char* serial) {
	if (!serial) return;

	char checkBuf[DISK_SERIAL_MAX_LENGTH + 1] = { 0 };
	RtlCopyMemory(checkBuf, serial, DISK_SERIAL_MAX_LENGTH);
	AtaSwapBytesPairs(checkBuf, DISK_SERIAL_MAX_LENGTH);

	for (int idx = 0; idx < g_serialCount; idx++) {
		SerialCacheEntry* entry = &g_serialCache[idx];
		if (entry->sz < DISK_SERIAL_MAX_LENGTH) continue;

		bool match = true;
		int matched = 0;
		for (int k = 0; k < DISK_SERIAL_MAX_LENGTH && match; k++) {
			char ck = checkBuf[k];
			if (ck == ' ' || ck == '\0') continue;
			if (entry->spoofed[k] != ck)
				match = false;
			else
				matched++;
		}

		if (match && matched >= 3) {
			RtlCopyMemory(checkBuf, entry->spoofed, DISK_SERIAL_MAX_LENGTH);
			AtaSwapBytesPairs(checkBuf, DISK_SERIAL_MAX_LENGTH);
			RtlCopyMemory(serial, checkBuf, DISK_SERIAL_MAX_LENGTH);
			return;
		}
	}
}

// ============================================================================
// Model spoofing (Phase 2: ported from HV diskspoof.cpp)
// ============================================================================

static bool ModelContains(const char* model, int len, const char* needle) {
	int needleLen = 0;
	while (needle[needleLen]) needleLen++;
	if (needleLen > len) return false;

	for (int i = 0; i <= len - needleLen; i++) {
		bool match = true;
		for (int j = 0; j < needleLen; j++) {
			char a = model[i + j];
			char b = needle[j];
			if (a >= 'a' && a <= 'z') a -= 32;
			if (b >= 'a' && b <= 'z') b -= 32;
			if (a != b) { match = false; break; }
		}
		if (match) return true;
	}
	return false;
}

static DiskModels::DiskType DetectDiskType(const char* model, int len) {
	if (ModelContains(model, len, "NVMe")) return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "KIOXIA")) return DiskModels::NVME_SSD;
	if (len >= 3 && model[0] == 'K' && model[1] == 'B' && model[2] == 'G') return DiskModels::NVME_SSD;
	if (len >= 2 && model[0] == 'X' && model[1] == 'G') return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "TOSHIBA MEMORY")) return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "980 PRO")) return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "970 EVO")) return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "990 PRO")) return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "990 EVO")) return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "980 ")) return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "SSDPE")) return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "HYNIX")) return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "SNV2S")) return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "SNVS")) return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "P3SSD")) return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "P3PSSD")) return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "P5SSD")) return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "P5PSSD")) return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "Rocket")) return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "LEGEND")) return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "SN770")) return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "SN850")) return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "SN750")) return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "SN580")) return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "3X0C")) return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "1X0E")) return DiskModels::NVME_SSD;
	if (ModelContains(model, len, "0E-00AFY")) return DiskModels::NVME_SSD;

	if (ModelContains(model, len, "USB")) return DiskModels::USB_DRIVE;
	if (ModelContains(model, len, "DataTraveler")) return DiskModels::USB_DRIVE;
	if (ModelContains(model, len, "Flash Drive")) return DiskModels::USB_DRIVE;
	if (ModelContains(model, len, "Flash Fit")) return DiskModels::USB_DRIVE;
	if (ModelContains(model, len, "Flash BAR")) return DiskModels::USB_DRIVE;
	if (ModelContains(model, len, "Cruzer")) return DiskModels::USB_DRIVE;
	if (ModelContains(model, len, "JumpDrive")) return DiskModels::USB_DRIVE;
	if (ModelContains(model, len, "Voyager")) return DiskModels::USB_DRIVE;
	if (ModelContains(model, len, "JetFlash")) return DiskModels::USB_DRIVE;
	if (ModelContains(model, len, "Survivor")) return DiskModels::USB_DRIVE;
	if (ModelContains(model, len, "Elite-X")) return DiskModels::USB_DRIVE;
	if (ModelContains(model, len, "Turbo")) return DiskModels::USB_DRIVE;

	if (ModelContains(model, len, "SSD")) return DiskModels::SATA_SSD;
	if (ModelContains(model, len, "MX500")) return DiskModels::SATA_SSD;
	if (ModelContains(model, len, "BX500")) return DiskModels::SATA_SSD;
	if (ModelContains(model, len, "SA400")) return DiskModels::SATA_SSD;
	if (ModelContains(model, len, "KC600")) return DiskModels::SATA_SSD;
	if (ModelContains(model, len, "SSDSC")) return DiskModels::SATA_SSD;
	if (ModelContains(model, len, "Solid State")) return DiskModels::SATA_SSD;
	if (ModelContains(model, len, "SU650")) return DiskModels::SATA_SSD;
	if (ModelContains(model, len, "SU800")) return DiskModels::SATA_SSD;
	if (ModelContains(model, len, "CS900")) return DiskModels::SATA_SSD;
	if (ModelContains(model, len, "2B0A")) return DiskModels::SATA_SSD;

	if (len >= 3 && model[0] == 'S' && model[1] == 'T' && model[2] >= '0' && model[2] <= '9')
		return DiskModels::HDD;
	if (ModelContains(model, len, "WDC WD")) return DiskModels::HDD;
	if (ModelContains(model, len, "TOSHIBA")) return DiskModels::HDD;
	if (ModelContains(model, len, "Hitachi")) return DiskModels::HDD;
	if (ModelContains(model, len, "HGST")) return DiskModels::HDD;
	if (ModelContains(model, len, "HDD")) return DiskModels::HDD;
	if (ModelContains(model, len, "DT01ACA")) return DiskModels::HDD;
	if (ModelContains(model, len, "HDWD")) return DiskModels::HDD;
	if (ModelContains(model, len, "MQ01AB")) return DiskModels::HDD;
	if (ModelContains(model, len, "MQ04AB")) return DiskModels::HDD;

	return DiskModels::SATA_SSD;
}

static ULONG ModelHash(const char* str, int len) {
	ULONG hash = 5381;
	for (int i = 0; i < len; i++) {
		char c = str[i];
		if (c == ' ' || c == '\0') continue;
		hash = ((hash << 5) + hash) + (UCHAR)c;
	}
	return hash;
}

bool FindFakeDiskModel(char* pModel, int fieldLen = 40) {
	if (!pModel || !MmIsAddressValid(pModel))
		return false;

	// Find actual string length: stop at first null terminator, then trim trailing spaces
	// This is critical for STORAGE_DEVICE_DESCRIPTOR where bytes after the null
	// may contain serial/revision data that would inflate trimLen
	int trimLen = 0;
	while (trimLen < fieldLen && pModel[trimLen] != '\0')
		trimLen++;
	while (trimLen > 0 && pModel[trimLen - 1] == ' ')
		trimLen--;
	if (trimLen == 0) return false;

	DbgPrintEx(0, 0, "[SPOOF] FindModel: <%.*s> fieldLen=%d trimLen=%d\n", trimLen, pModel, fieldLen, trimLen);

	// Exact match
	for (int i = 0; i < g_modelCount; i++) {
		if (g_modelCache[i].len == trimLen && !memcmp(g_modelCache[i].orig, pModel, trimLen)) {
			RtlCopyMemory(pModel, g_modelCache[i].spoofed, fieldLen);
			return true;
		}
	}

	// Already spoofed check
	for (int i = 0; i < g_modelCount; i++) {
		int spoofedTrim = 40;
		while (spoofedTrim > 0 && (g_modelCache[i].spoofed[spoofedTrim - 1] == ' ' || g_modelCache[i].spoofed[spoofedTrim - 1] == '\0'))
			spoofedTrim--;
		if (spoofedTrim <= 0) continue;
		if (spoofedTrim == trimLen && !memcmp(g_modelCache[i].spoofed, pModel, trimLen))
			return true;
		if (spoofedTrim > trimLen && trimLen >= 8 && !memcmp(g_modelCache[i].spoofed, pModel, trimLen))
			return true;
		if (spoofedTrim > trimLen && trimLen >= 8) {
			int off = spoofedTrim - trimLen;
			if (g_modelCache[i].spoofed[off - 1] == ' ' && !memcmp(g_modelCache[i].spoofed + off, pModel, trimLen))
				return true;
		}
	}

	// Suffix-substring match (vendor-prefix variants)
	for (int i = 0; i < g_modelCount; i++) {
		bool match = false;
		if (g_modelCache[i].len < trimLen && g_modelCache[i].len > 3) {
			int offset = trimLen - g_modelCache[i].len;
			if (pModel[offset - 1] == ' ' && !memcmp(g_modelCache[i].orig, pModel + offset, g_modelCache[i].len))
				match = true;
		} else if (g_modelCache[i].len > trimLen && trimLen > 3) {
			int offset = g_modelCache[i].len - trimLen;
			if (g_modelCache[i].orig[offset - 1] == ' ' && !memcmp(g_modelCache[i].orig + offset, pModel, trimLen))
				match = true;
		}
		if (match) {
			// Always write the full spoofed model (truncated to fit) for consistency
			int spoofedTrim = 40;
			while (spoofedTrim > 0 && (g_modelCache[i].spoofed[spoofedTrim - 1] == ' ' || g_modelCache[i].spoofed[spoofedTrim - 1] == '\0'))
				spoofedTrim--;
			char buf[41] = { 0 };
			int copyLen = spoofedTrim > fieldLen ? fieldLen : spoofedTrim;
			RtlCopyMemory(buf, g_modelCache[i].spoofed, copyLen);
			for (int k = copyLen; k < fieldLen && k < 40; k++) buf[k] = ' ';
			RtlCopyMemory(pModel, buf, fieldLen);
			return true;
		}
	}

	// Prefix-truncation match
	for (int i = 0; i < g_modelCount; i++) {
		if (g_modelCache[i].len > trimLen && trimLen > 3
			&& !memcmp(g_modelCache[i].orig, pModel, trimLen)) {
			int spoofedTrim = 40;
			while (spoofedTrim > 0 && (g_modelCache[i].spoofed[spoofedTrim - 1] == ' ' || g_modelCache[i].spoofed[spoofedTrim - 1] == '\0'))
				spoofedTrim--;
			char buf[41] = { 0 };
			int copyLen = spoofedTrim > fieldLen ? fieldLen : spoofedTrim;
			RtlCopyMemory(buf, g_modelCache[i].spoofed, copyLen);
			for (int k = copyLen; k < fieldLen && k < 40; k++) buf[k] = ' ';
			RtlCopyMemory(pModel, buf, fieldLen);
			return true;
		}
	}

	// Reverse prefix match
	for (int i = 0; i < g_modelCount; i++) {
		if (g_modelCache[i].len < trimLen && g_modelCache[i].len > 3
			&& !memcmp(g_modelCache[i].orig, pModel, g_modelCache[i].len)) {
			RtlCopyMemory(g_modelCache[i].orig, pModel, trimLen);
			g_modelCache[i].len = trimLen;
			int spoofedTrim = 40;
			while (spoofedTrim > 0 && (g_modelCache[i].spoofed[spoofedTrim - 1] == ' ' || g_modelCache[i].spoofed[spoofedTrim - 1] == '\0'))
				spoofedTrim--;
			char buf[41] = { 0 };
			int copyLen = spoofedTrim > fieldLen ? fieldLen : spoofedTrim;
			RtlCopyMemory(buf, g_modelCache[i].spoofed, copyLen);
			for (int k = copyLen; k < fieldLen && k < 40; k++) buf[k] = ' ';
			RtlCopyMemory(pModel, buf, fieldLen);
			return true;
		}
	}

	// Leading-space-normalized prefix match
	for (int i = 0; i < g_modelCount; i++) {
		int eSkip = 0;
		while (eSkip < g_modelCache[i].len && g_modelCache[i].orig[eSkip] == ' ') eSkip++;
		int pSkip = 0;
		while (pSkip < trimLen && pModel[pSkip] == ' ') pSkip++;
		if (eSkip == 0 && pSkip == 0) continue;
		int eContent = g_modelCache[i].len - eSkip;
		int pContent = trimLen - pSkip;
		if (eContent <= 3 || pContent <= 3) continue;

		int cmpLen = eContent < pContent ? eContent : pContent;
		if (cmpLen > 3 && !memcmp(g_modelCache[i].orig + eSkip, pModel + pSkip, cmpLen)) {
			if (eContent < pContent) {
				RtlCopyMemory(g_modelCache[i].orig, pModel, trimLen);
				g_modelCache[i].len = trimLen;
			}
			int spoofedTrim = 40;
			while (spoofedTrim > 0 && (g_modelCache[i].spoofed[spoofedTrim - 1] == ' ' || g_modelCache[i].spoofed[spoofedTrim - 1] == '\0'))
				spoofedTrim--;
			int sSkip = 0;
			while (sSkip < spoofedTrim && g_modelCache[i].spoofed[sSkip] == ' ') sSkip++;
			int sContent = spoofedTrim - sSkip;
			char buf[41] = { 0 };
			int copyLen = sContent > fieldLen ? fieldLen : sContent;
			RtlCopyMemory(buf, g_modelCache[i].spoofed + sSkip, copyLen);
			for (int k = copyLen; k < fieldLen && k < 40; k++) buf[k] = ' ';
			RtlCopyMemory(pModel, buf, fieldLen);
			return true;
		}
	}

	// No cache hit - generate new spoofed model
	if (g_modelCount >= MAX_MODEL_CACHE) return false;

	DiskModels::DiskType type = DetectDiskType(pModel, trimLen);

	const char* modelBase = nullptr;
	int count = 0;
	switch (type) {
	case DiskModels::SATA_SSD:
		modelBase = &DiskModels::SataSsdModels[0][0];
		count = DiskModels::SataSsdCount;
		break;
	case DiskModels::NVME_SSD:
		modelBase = &DiskModels::NvmeSsdModels[0][0];
		count = DiskModels::NvmeSsdCount;
		break;
	case DiskModels::HDD:
		modelBase = &DiskModels::HddModels[0][0];
		count = DiskModels::HddCount;
		break;
	case DiskModels::USB_DRIVE:
		modelBase = &DiskModels::UsbModels[0][0];
		count = DiskModels::UsbCount;
		break;
	default:
		modelBase = &DiskModels::SataSsdModels[0][0];
		count = DiskModels::SataSsdCount;
		break;
	}

	if (!modelBase || count == 0) return false;

	ULONG hash = ModelHash(pModel, trimLen);
	ULONG combined = hash ^ (ULONG)(kmdf_settings::hwid_seed & 0xFFFFFFFF);
	int index = combined % count;

	const char* selectedModel = modelBase + (index * 41);
	int selectedLen = 0;
	while (selectedModel[selectedLen]) selectedLen++;
	if (selectedLen > 40) selectedLen = 40;

	// Anti-collision
	if (trimLen >= 10 && selectedLen == trimLen && !memcmp(selectedModel, pModel, trimLen)) {
		index = (index + 1) % count;
		selectedModel = modelBase + (index * 41);
		selectedLen = 0;
		while (selectedModel[selectedLen]) selectedLen++;
		if (selectedLen > 40) selectedLen = 40;
	}

	ModelCacheEntry* entry = &g_modelCache[g_modelCount];
	RtlZeroMemory(entry, sizeof(*entry));
	RtlCopyMemory(entry->orig, pModel, trimLen);
	entry->len = trimLen;
	RtlCopyMemory(entry->spoofed, selectedModel, selectedLen);
	for (int i = selectedLen; i < 40; i++) entry->spoofed[i] = ' ';
	entry->spoofed[40] = '\0';

	DbgPrintEx(0, 0, "[SPOOF] Model [%d]: <%.*s> -> <%s> (type=%d idx=%d)\n",
		g_modelCount, trimLen, entry->orig, entry->spoofed, type, index);

	g_modelCount++;
	RtlCopyMemory(pModel, entry->spoofed, fieldLen);
	return true;
}

__forceinline void FindFakeDiskModelAta(char* pModel, int len = 40) {
	char swapBuf[41] = { 0 };
	if (len > 40) len = 40;
	RtlCopyMemory(swapBuf, pModel, len);
	AtaSwapBytesPairs(swapBuf, len);
	FindFakeDiskModel(swapBuf, len);
	AtaSwapBytesPairs(swapBuf, len);
	RtlCopyMemory(pModel, swapBuf, len);
}

// ============================================================================
// VPD Page spoofing (Phase 6B)
// ============================================================================

static void SpoofVpd83(UCHAR* vpd, int bufLen) {
	if (bufLen < 4 || vpd[1] != 0x83) return;
	int pageLen = (vpd[2] << 8) | vpd[3];
	if (pageLen + 4 > bufLen) pageLen = bufLen - 4;

	int offset = 4;
	while (offset + 4 <= 4 + pageLen) {
		int idType = vpd[offset + 1] & 0x0F;
		int idLen = vpd[offset + 3];
		if (idLen == 0 || offset + 4 + idLen > 4 + pageLen) break;

		UCHAR* idData = &vpd[offset + 4];

		if (idType == 3 && idLen == 8) {
			// NAA WWN: 8-byte binary
			WWN wwnCopy;
			RtlZeroMemory(&wwnCopy, sizeof(wwnCopy));
			for (int j = 0; j < 4; j++)
				wwnCopy.WorldWideName[j] = (USHORT)(idData[j * 2] << 8) | idData[j * 2 + 1];
			FindFakeWWN(&wwnCopy);
			for (int j = 0; j < 4; j++) {
				idData[j * 2] = (UCHAR)(wwnCopy.WorldWideName[j] >> 8);
				idData[j * 2 + 1] = (UCHAR)(wwnCopy.WorldWideName[j] & 0xFF);
			}
		}
		else if (idType == 2 && (idLen == 8 || idLen == 16)) {
			// EUI-64 (8 bytes) or EUI-128/NGUID (16 bytes): serialize as hex serial, spoof, deserialize
			const char hc[] = "0123456789ABCDEF";
			char serialBuf[41]; // max 40 chars + null
			int p = 0;
			for (int j = 0; j < idLen; j++) {
				serialBuf[p++] = hc[(idData[j] >> 4) & 0xF];
				serialBuf[p++] = hc[idData[j] & 0xF];
				if (j % 2 == 1 && j < idLen - 1) serialBuf[p++] = '_';
			}
			serialBuf[p++] = '.';
			serialBuf[p] = 0;
			FindFakeDiskSerial(serialBuf, p);
			int ri = 0;
			for (int j = 0; j < p && ri < idLen; j++) {
				char c = serialBuf[j];
				if (c == '_' || c == '.') continue;
				UCHAR hi2 = (c >= 'A') ? (c - 'A' + 10) : ((c >= 'a') ? (c - 'a' + 10) : (c - '0'));
				j++;
				if (j >= p) break;
				c = serialBuf[j];
				UCHAR lo2 = (c >= 'A') ? (c - 'A' + 10) : ((c >= 'a') ? (c - 'a' + 10) : (c - '0'));
				idData[ri++] = (hi2 << 4) | lo2;
			}
		}
		else if (idType == 1 && idLen > 8) {
			// T10 Vendor ID: vendor(8) + product-specific data
			// ATA format: vendor(8) + model(40) + serial(20) = 68 bytes total
			char* prodStart = (char*)idData + 8;
			int prodLen = idLen - 8;
			if (prodLen >= 60) {
				// Full ATA T10: model(40) + serial(20)
				FindFakeDiskModel(prodStart, 40);
				FindFakeDiskSerial(prodStart + 40, 20);
			} else if (prodLen > 0 && prodLen <= 40) {
				FindFakeDiskSerial(prodStart, prodLen);
			}
		}
		else if (idType == 8 && idLen >= 20) {
			// SCSI name string
			UCHAR* str = idData;
			bool isNaa = (str[0] == 'n' && str[1] == 'a' && str[2] == 'a' && str[3] == '.');
			bool isEui = (str[0] == 'e' && str[1] == 'u' && str[2] == 'i' && str[3] == '.');

			if (isNaa && idLen >= 20) {
				UCHAR* hex = str + 4;
				UCHAR binData[8] = { 0 };
				bool valid = true;
				for (int j = 0; j < 16; j++) {
					UCHAR c = hex[j];
					UCHAR nibble;
					if (c >= '0' && c <= '9') nibble = c - '0';
					else if (c >= 'A' && c <= 'F') nibble = c - 'A' + 10;
					else if (c >= 'a' && c <= 'f') nibble = c - 'a' + 10;
					else { valid = false; break; }
					if (j % 2 == 0) binData[j / 2] = nibble << 4;
					else binData[j / 2] |= nibble;
				}
				if (valid) {
					WWN wwnCopy;
					RtlZeroMemory(&wwnCopy, sizeof(wwnCopy));
					for (int j = 0; j < 4; j++)
						wwnCopy.WorldWideName[j] = (USHORT)(binData[j * 2] << 8) | binData[j * 2 + 1];
					FindFakeWWN(&wwnCopy);
					for (int j = 0; j < 4; j++) {
						binData[j * 2] = (UCHAR)(wwnCopy.WorldWideName[j] >> 8);
						binData[j * 2 + 1] = (UCHAR)(wwnCopy.WorldWideName[j] & 0xFF);
					}
					const char hexChars[] = "0123456789ABCDEF";
					for (int j = 0; j < 8; j++) {
						hex[j * 2] = hexChars[(binData[j] >> 4) & 0xF];
						hex[j * 2 + 1] = hexChars[binData[j] & 0xF];
					}
				}
			}
			if (isEui && idLen >= 20) {
				UCHAR* hex = str + 4;
				int hexLen = idLen - 4; // 16 for EUI-64, 32 for EUI-128
				if (hexLen == 16 || hexLen == 32) {
				int byteCount = hexLen / 2; // 8 or 16
				char serialBuf[41]; // max 40 chars + null
				int p = 0;
				for (int b = 0; b < byteCount; b++) {
					serialBuf[p++] = hex[b * 2];
					serialBuf[p++] = hex[b * 2 + 1];
					if (b % 2 == 1 && b < byteCount - 1) serialBuf[p++] = '_';
				}
				serialBuf[p++] = '.';
				serialBuf[p] = 0;
				FindFakeDiskSerial(serialBuf, p);
				// Write back: extract hex chars, skip separators
				int hi = 0;
				for (int j = 0; j < p && hi < hexLen; j++) {
					if (serialBuf[j] == '_' || serialBuf[j] == '.') continue;
					hex[hi++] = serialBuf[j];
				}
				}
			}
		}

		offset += 4 + idLen;
	}
}

static void SpoofStandardInquiry(UCHAR* data, int dataLen) {
	if (dataLen < 36) return;
	// Vendor[8] at byte 8, Product[16] at byte 16, Revision[4] at byte 32
	char* product = (char*)data + 16;
	char origProduct[17] = { 0 };
	RtlCopyMemory(origProduct, product, 16);

	// Only spoof product field (16 bytes) for both NVMe and non-NVMe
	// Suffix-substring match in FindFakeDiskModel ensures consistency with SQP cache
	FindFakeDiskModel(product, 16);
	DbgPrintEx(0, 0, "[SPOOF] SCSI Inquiry Product: <%.16s> -> <%.16s>\n", origProduct, product);
}

// ============================================================================
// Completion routines
// ============================================================================

NTSTATUS NVME_Pass_Through(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (!NT_SUCCESS(irp->IoStatus.Status)) goto _nvme_pt_end;

		if (request.BufferLength >= sizeof(NVME_PASS_THROUGH_IOCTL)) {
			PNVME_PASS_THROUGH_IOCTL pte = (PNVME_PASS_THROUGH_IOCTL)request.Buffer;
			if (pte->DataBufferLen >= sizeof(NVME_IDENTIFY_CONTROLLER_DATA)) {
				PNVME_IDENTIFY_CONTROLLER_DATA Data = (PNVME_IDENTIFY_CONTROLLER_DATA)pte->DataBuffer;
				char serialBuf[21] = { 0 };
				RtlCopyMemory(serialBuf, Data->SN, 20);
				FindFakeDiskSerial(serialBuf);
				RtlCopyMemory(Data->SN, serialBuf, 20);
				FindFakeDiskModel((char*)Data->MN, 40);
			}
		}

		if (request.BufferLength >= sizeof(INTEL_NVME_PASS_THROUGH)) {
			INTEL_NVME_PASS_THROUGH* data = (INTEL_NVME_PASS_THROUGH*)request.Buffer;
			NVME_IDENTIFY_DEVICE* nvmeId = (NVME_IDENTIFY_DEVICE*)data->DataBuffer;
			char serialBuf[21] = { 0 };
			RtlCopyMemory(serialBuf, nvmeId->SerialNumber, 20);
			FindFakeDiskSerial(serialBuf);
			RtlCopyMemory(nvmeId->SerialNumber, serialBuf, 20);
			FindFakeDiskModel(nvmeId->Model, 40);
		}

	_nvme_pt_end:
		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

NTSTATUS ScSlPassIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		SCSI_PASS_THROUGH* spt = nullptr;

		if (!NT_SUCCESS(irp->IoStatus.Status)) goto _spt_end;

		spt = (SCSI_PASS_THROUGH*)request.Buffer;
		if (MmIsAddressValid(spt) && spt->DataBufferOffset && spt->DataBufferOffset < request.BufferLength) {
			PVOID dataBuffer = (PBYTE)request.Buffer + spt->DataBufferOffset;
			if (!MmIsAddressValid(dataBuffer)) goto _spt_end;
			int dataLen = (int)(request.BufferLength - spt->DataBufferOffset);

			if (spt->Cdb[0] == 0xA1 || spt->Cdb[0] == 0x85) {
				UCHAR ataCmd = (spt->Cdb[0] == 0xA1) ? spt->Cdb[9] : spt->Cdb[14];
				if (ataCmd == 0xEC) {
					ata_identify_device* aid = (ata_identify_device*)dataBuffer;
					if (MmIsAddressValid(aid)) {
						FindFakeDiskSerialAta((char*)aid->serial_no);
						FindFakeDiskModelAta((char*)aid->model, 40);
					}
				}
				else if (ataCmd == 0xB0) {
					// ATA SMART command
					UCHAR feature = (spt->Cdb[0] == 0xA1) ? spt->Cdb[3] : spt->Cdb[4];
					if (feature == 0xD0 && dataLen >= 362) // SMART READ DATA
						ZeroSmartAttributes(dataBuffer, dataLen);
				}
			}
			else if (spt->Cdb[0] == 0x12 && (spt->Cdb[1] & 0x01)) {
				UCHAR* vpd = (UCHAR*)dataBuffer;
				if (spt->Cdb[2] == 0x80) {
					if (vpd[1] == 0x80 && vpd[3] >= 3) {
						int slen = vpd[3]; if (slen > 40) slen = 40;
						FindFakeDiskSerial((char*)&vpd[4], slen);
					}
				}
				else if (spt->Cdb[2] == 0x83) {
					SpoofVpd83(vpd, dataLen);
				}
				else if (spt->Cdb[2] == 0x89) {
					// VPD 0x89: ATA Information — IDENTIFY data at offset 60
					if (dataLen >= 60 + 512) {
						ata_identify_device* aid = (ata_identify_device*)(vpd + 60);
						if (MmIsAddressValid(aid)) {
							FindFakeDiskSerialAta((char*)aid->serial_no);
							FindFakeDiskModelAta((char*)aid->model, 40);
						}
					}
				}
			}
			else if (spt->Cdb[0] == 0x12 && !(spt->Cdb[1] & 0x01)) {
				SpoofStandardInquiry((UCHAR*)dataBuffer, dataLen);
			}
			else if (spt->Cdb[0] == 0xE4 || spt->Cdb[0] == 0xE6) {
				NVME_IDENTIFY_DEVICE* nvmeIdentify = (NVME_IDENTIFY_DEVICE*)dataBuffer;
				if (MmIsAddressValid(nvmeIdentify)) {
					char serialBuf[21] = { 0 };
					RtlCopyMemory(serialBuf, nvmeIdentify->SerialNumber, 20);
					FindFakeDiskSerial(serialBuf);
					RtlCopyMemory(nvmeIdentify->SerialNumber, serialBuf, 20);
					FindFakeDiskModel(nvmeIdentify->Model, 40);
				}
			}
			else {
				PCHAR serial = (PCHAR)dataBuffer + 4;
				if (MmIsAddressValid(serial)) {
					size_t length = strlen(serial);
					if (length >= 5 && length <= 40)
						FindFakeDiskSerial(serial, (int)length);
				}
			}
		}

	_spt_end:
		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

NTSTATUS StorageQueryIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (!NT_SUCCESS(irp->IoStatus.Status)) goto _sqp_end;

		if (request.BufferLength >= sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
			PSTORAGE_DEVICE_DESCRIPTOR desc = (PSTORAGE_DEVICE_DESCRIPTOR)request.Buffer;
			ULONG SerialNumber_offset = desc->SerialNumberOffset;

			if (SerialNumber_offset && SerialNumber_offset < request.BufferLength) {
				PCHAR serial = (PCHAR)desc + SerialNumber_offset;
				if (MmIsAddressValid(serial)) {
					size_t length = strlen(serial);
					if (length >= 3 && length <= 40) {
						char origSerial[41] = { 0 };
						RtlCopyMemory(origSerial, serial, length);
						FindFakeDiskSerial(serial, (int)length);
						DbgPrintEx(0, 0, "[SPOOF] SQP Serial: <%.*s> -> <%.*s>\n", (int)length, origSerial, (int)length, serial);
					}
				}
			}

			// Model spoofing via ProductId field
			ULONG productOffset = desc->ProductIdOffset;
			if (productOffset && productOffset < request.BufferLength) {
				PCHAR product = (PCHAR)desc + productOffset;
				if (MmIsAddressValid(product)) {
					size_t length = strlen(product);
					if (length >= 3 && length <= 40) {
						char origModel[41] = { 0 };
						RtlCopyMemory(origModel, product, length);
						FindFakeDiskModel(product, (int)length);
						DbgPrintEx(0, 0, "[SPOOF] SQP Model: <%.*s> -> <%.*s>\n", (int)length, origModel, (int)length, product);
					}
				}
			}
		}

	_sqp_end:
		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

// StorageDeviceIdProperty (PropertyId=1): handles WWN and EUI-64
NTSTATUS StorageDeviceIdIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (NT_SUCCESS(irp->IoStatus.Status) && MmIsAddressValid(request.Buffer)) {
			__try {
				PSTORAGE_DEVICE_ID_DESCRIPTOR desc = (PSTORAGE_DEVICE_ID_DESCRIPTOR)request.Buffer;
				ULONG descSize = (ULONG)irp->IoStatus.Information;
				if (descSize < sizeof(STORAGE_DEVICE_ID_DESCRIPTOR) || desc->NumberOfIdentifiers == 0)
					goto _devid_end;

				UCHAR* base = desc->Identifiers;
				UCHAR* end = (UCHAR*)desc + descSize;

				for (ULONG i = 0; i < desc->NumberOfIdentifiers; i++) {
					if (base >= end) break;
					PSTORAGE_IDENTIFIER id = (PSTORAGE_IDENTIFIER)base;
					if (!MmIsAddressValid(id) || id->NextOffset == 0) break;
					if ((UCHAR*)id + sizeof(STORAGE_IDENTIFIER) > end) break;

					if (id->Type == StorageIdTypeFCPHName && id->IdentifierSize == 8
						&& (UCHAR*)id->Identifier + 8 <= end) {
						WWN wwnCopy;
						RtlZeroMemory(&wwnCopy, sizeof(wwnCopy));
						UCHAR* src = id->Identifier;
						for (int j = 0; j < 4; j++)
							wwnCopy.WorldWideName[j] = (USHORT)(src[j * 2] << 8) | src[j * 2 + 1];
						FindFakeWWN(&wwnCopy);
						for (int j = 0; j < 4; j++) {
							src[j * 2] = (UCHAR)(wwnCopy.WorldWideName[j] >> 8);
							src[j * 2 + 1] = (UCHAR)(wwnCopy.WorldWideName[j] & 0xFF);
						}
					}

					if (id->Type == StorageIdTypeEUI64 && (id->IdentifierSize == 8 || id->IdentifierSize == 16)
						&& (UCHAR*)id->Identifier + id->IdentifierSize <= end) {
						UCHAR* raw = id->Identifier;
						int euiLen = id->IdentifierSize; // 8 or 16
						const char hc[] = "0123456789ABCDEF";
						char serialBuf[41]; // max 40 + null
						int p = 0;
						for (int j = 0; j < euiLen; j++) {
							serialBuf[p++] = hc[(raw[j] >> 4) & 0xF];
							serialBuf[p++] = hc[raw[j] & 0xF];
							if (j % 2 == 1 && j < euiLen - 1) serialBuf[p++] = '_';
						}
						serialBuf[p++] = '.';
						serialBuf[p] = 0;
						FindFakeDiskSerial(serialBuf, p);
						int ri = 0;
						for (int j = 0; j < p && ri < euiLen; j++) {
							char c = serialBuf[j];
							if (c == '_' || c == '.') continue;
							UCHAR hi = (c >= 'A') ? (c - 'A' + 10) : ((c >= 'a') ? (c - 'a' + 10) : (c - '0'));
							j++;
							if (j >= p) break;
							c = serialBuf[j];
							UCHAR lo = (c >= 'A') ? (c - 'A' + 10) : ((c >= 'a') ? (c - 'a' + 10) : (c - '0'));
							raw[ri++] = (hi << 4) | lo;
						}
					}

					if (id->Type == 8 && id->IdentifierSize >= 20
						&& (UCHAR*)id->Identifier + id->IdentifierSize <= end) {
						UCHAR* str = id->Identifier;
						bool isNaa = (str[0] == 'n' && str[1] == 'a' && str[2] == 'a' && str[3] == '.');
						bool isEui = (str[0] == 'e' && str[1] == 'u' && str[2] == 'i' && str[3] == '.');

						if (isNaa) {
							UCHAR* hex = str + 4;
							UCHAR binData[8] = { 0 };
							bool valid = true;
							for (int j = 0; j < 16; j++) {
								UCHAR c = hex[j];
								UCHAR nibble;
								if (c >= '0' && c <= '9') nibble = c - '0';
								else if (c >= 'A' && c <= 'F') nibble = c - 'A' + 10;
								else if (c >= 'a' && c <= 'f') nibble = c - 'a' + 10;
								else { valid = false; break; }
								if (j % 2 == 0) binData[j / 2] = nibble << 4;
								else binData[j / 2] |= nibble;
							}
							if (valid) {
								WWN wwnCopy;
								RtlZeroMemory(&wwnCopy, sizeof(wwnCopy));
								for (int j = 0; j < 4; j++)
									wwnCopy.WorldWideName[j] = (USHORT)(binData[j * 2] << 8) | binData[j * 2 + 1];
								FindFakeWWN(&wwnCopy);
								for (int j = 0; j < 4; j++) {
									binData[j * 2] = (UCHAR)(wwnCopy.WorldWideName[j] >> 8);
									binData[j * 2 + 1] = (UCHAR)(wwnCopy.WorldWideName[j] & 0xFF);
								}
								const char hexChars[] = "0123456789ABCDEF";
								for (int j = 0; j < 8; j++) {
									hex[j * 2] = hexChars[(binData[j] >> 4) & 0xF];
									hex[j * 2 + 1] = hexChars[binData[j] & 0xF];
								}
							}
						}

						if (isEui) {
							UCHAR* hex = str + 4;
							int hexLen = id->IdentifierSize - 4; // 16 or 32
							if (hexLen == 16 || hexLen == 32) {
								int byteCount = hexLen / 2;
								char serialBuf[41];
								int p = 0;
								for (int b = 0; b < byteCount; b++) {
									serialBuf[p++] = hex[b * 2];
									serialBuf[p++] = hex[b * 2 + 1];
									if (b % 2 == 1 && b < byteCount - 1) serialBuf[p++] = '_';
								}
								serialBuf[p++] = '.';
								serialBuf[p] = 0;
								FindFakeDiskSerial(serialBuf, p);
								int hi2 = 0;
								for (int j = 0; j < p && hi2 < hexLen; j++) {
									if (serialBuf[j] == '_' || serialBuf[j] == '.') continue;
									hex[hi2++] = serialBuf[j];
								}
							}
						}
					}

					if (id->Type == StorageIdTypeVendorId && id->IdentifierSize > 8
						&& (UCHAR*)id->Identifier + id->IdentifierSize <= end) {
						// T10 Vendor ID: vendor(8) + product-specific data
						char* prodStart = (char*)id->Identifier + 8;
						int prodLen = id->IdentifierSize - 8;
						if (prodLen >= 60) {
							FindFakeDiskModel(prodStart, 40);
							FindFakeDiskSerial(prodStart + 40, 20);
						} else if (prodLen > 0 && prodLen <= 40) {
							FindFakeDiskSerial(prodStart, prodLen);
						}
					}

					base += id->NextOffset;
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {}
		}

	_devid_end:
		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

// ATA SMART via ATA_PASS_THROUGH_EX (buffered)
NTSTATUS AtaSmartIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (NT_SUCCESS(irp->IoStatus.Status) && MmIsAddressValid(request.Buffer) &&
			request.BufferLength >= sizeof(ATA_PASS_THROUGH_EX) + 362) {
			PATA_PASS_THROUGH_EX pte = (PATA_PASS_THROUGH_EX)request.Buffer;
			ULONG offset = (ULONG)pte->DataBufferOffset;
			if (offset && offset < request.BufferLength) {
				PVOID data = (PBYTE)request.Buffer + offset;
				int dataLen = (int)(request.BufferLength - offset);
				if (MmIsAddressValid(data) && dataLen >= 362)
					ZeroSmartAttributes(data, dataLen);
			}
		}

		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

// ATA SMART via ATA_PASS_THROUGH_DIRECT (MDL)
NTSTATUS AtaSmartDirectIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (NT_SUCCESS(irp->IoStatus.Status) && request.DataMdl) {
			PVOID dataBuffer = MmGetSystemAddressForMdlSafe(request.DataMdl, NormalPagePriority);
			ATA_PASS_THROUGH_DIRECT* aptd = (ATA_PASS_THROUGH_DIRECT*)request.Buffer;
			if (dataBuffer && MmIsAddressValid(aptd) && aptd->DataTransferLength >= 362)
				ZeroSmartAttributes(dataBuffer, aptd->DataTransferLength);
		}

		if (request.DataMdl) {
			MmUnlockPages(request.DataMdl);
			IoFreeMdl(request.DataMdl);
		}

		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

// SMART READ DATA via SMART_RCV_DRIVE_DATA (zeros attributes instead of serial/model)
NTSTATUS SmartSmartDataIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (NT_SUCCESS(irp->IoStatus.Status) && request.BufferLength >= sizeof(SENDCMDOUTPARAMS) - 1 + 362) {
			PSENDCMDOUTPARAMS cmdOut = (PSENDCMDOUTPARAMS)request.Buffer;
			if (MmIsAddressValid(cmdOut) && MmIsAddressValid(cmdOut->bBuffer))
				ZeroSmartAttributes(cmdOut->bBuffer, 512);
		}

		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

NTSTATUS AtaPassIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (!NT_SUCCESS(irp->IoStatus.Status) || !MmIsAddressValid(request.Buffer)) goto _ata_end;

		if (request.BufferLength >= (sizeof(ATA_PASS_THROUGH_EX) + sizeof(IDENTIFY_DEVICE_DATA))) {
			PATA_PASS_THROUGH_EX pte = (PATA_PASS_THROUGH_EX)request.Buffer;
			ULONG offset = (ULONG)pte->DataBufferOffset;
			if (MmIsAddressValid(pte) && offset && offset < request.BufferLength) {
				PIDENTIFY_DEVICE_DATA pDeviceData = ((PIDENTIFY_DEVICE_DATA)((PBYTE)request.Buffer + offset));
				FindFakeDiskSerialAta((PCHAR)pDeviceData->SerialNumber);
				FindFakeDiskModelAta((PCHAR)pDeviceData->ModelNumber, 40);

				WWN* pWwn = (WWN*)&pDeviceData->WorldWideName;
				FindFakeWWN(pWwn);
			}
		}

	_ata_end:
		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

NTSTATUS ATAPass_DirectIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (NT_SUCCESS(irp->IoStatus.Status) && request.DataMdl) {
			ATA_PASS_THROUGH_DIRECT* aptd = (ATA_PASS_THROUGH_DIRECT*)request.Buffer;
			PVOID dataBuffer = MmGetSystemAddressForMdlSafe(request.DataMdl, NormalPagePriority);

			if (dataBuffer && MmIsAddressValid(aptd)) {
				if (aptd->DataTransferLength >= sizeof(IDENTIFY_DEVICE_DATA)) {
					PIDENTIFY_DEVICE_DATA pDeviceData = (PIDENTIFY_DEVICE_DATA)dataBuffer;
					FindFakeDiskSerialAta((PCHAR)pDeviceData->SerialNumber);
					FindFakeDiskModelAta((PCHAR)pDeviceData->ModelNumber, 40);

					WWN* pWwn = (WWN*)&pDeviceData->WorldWideName;
					FindFakeWWN(pWwn);
				}
			}
		}

		if (request.DataMdl) {
			MmUnlockPages(request.DataMdl);
			IoFreeMdl(request.DataMdl);
		}

		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

NTSTATUS ScSlPass_DirectIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (NT_SUCCESS(irp->IoStatus.Status) && request.DataMdl) {
			SCSI_PASS_THROUGH_DIRECT* sptd = (SCSI_PASS_THROUGH_DIRECT*)request.Buffer;
			PVOID dataBuffer = MmGetSystemAddressForMdlSafe(request.DataMdl, NormalPagePriority);

			if (dataBuffer && MmIsAddressValid(sptd)) {
				int dataLen = (int)sptd->DataTransferLength;
				if (sptd->Cdb[0] == 0xA1 || sptd->Cdb[0] == 0x85) {
					UCHAR ataCmd = (sptd->Cdb[0] == 0xA1) ? sptd->Cdb[9] : sptd->Cdb[14];
					if (ataCmd == 0xEC) {
						ata_identify_device* aid = (ata_identify_device*)dataBuffer;
						FindFakeDiskSerialAta((char*)aid->serial_no);
						FindFakeDiskModelAta((char*)aid->model, 40);
					}
					else if (ataCmd == 0xB0) {
						UCHAR feature = (sptd->Cdb[0] == 0xA1) ? sptd->Cdb[3] : sptd->Cdb[4];
						if (feature == 0xD0 && dataLen >= 362)
							ZeroSmartAttributes(dataBuffer, dataLen);
					}
				}
				else if (sptd->Cdb[0] == 0x12 && (sptd->Cdb[1] & 0x01)) {
					UCHAR* vpd = (UCHAR*)dataBuffer;
					if (sptd->Cdb[2] == 0x80 && vpd[1] == 0x80 && vpd[3] >= 3) {
						int slen = vpd[3]; if (slen > 40) slen = 40;
						char vpdSerial[41] = { 0 };
						RtlCopyMemory(vpdSerial, &vpd[4], slen);
						FindFakeDiskSerial(vpdSerial, slen);
						RtlCopyMemory(&vpd[4], vpdSerial, slen);
					}
					else if (sptd->Cdb[2] == 0x83) {
						SpoofVpd83(vpd, dataLen);
					}
					else if (sptd->Cdb[2] == 0x89 && dataLen >= 60 + 512) {
						ata_identify_device* aid = (ata_identify_device*)(vpd + 60);
						FindFakeDiskSerialAta((char*)aid->serial_no);
						FindFakeDiskModelAta((char*)aid->model, 40);
					}
				}
				else if (sptd->Cdb[0] == 0x12 && !(sptd->Cdb[1] & 0x01)) {
					SpoofStandardInquiry((UCHAR*)dataBuffer, dataLen);
				}
				else if (sptd->Cdb[0] == 0xE4 || sptd->Cdb[0] == 0xE6) {
					NVME_IDENTIFY_DEVICE* nvmeIdentify = (NVME_IDENTIFY_DEVICE*)dataBuffer;
					char serialBuf[21] = { 0 };
					RtlCopyMemory(serialBuf, nvmeIdentify->SerialNumber, 20);
					FindFakeDiskSerial(serialBuf);
					RtlCopyMemory(nvmeIdentify->SerialNumber, serialBuf, 20);
					FindFakeDiskModel(nvmeIdentify->Model, 40);
				}
			}
		}

		if (request.DataMdl) {
			MmUnlockPages(request.DataMdl);
			IoFreeMdl(request.DataMdl);
		}

		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

NTSTATUS ScSlPass_DirectIocEX(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (NT_SUCCESS(irp->IoStatus.Status) && request.DataMdl) {
			SCSI_PASS_THROUGH_DIRECT_EX* sptdex = (SCSI_PASS_THROUGH_DIRECT_EX*)request.Buffer;
			PVOID dataBuffer = MmGetSystemAddressForMdlSafe(request.DataMdl, NormalPagePriority);

			if (dataBuffer && MmIsAddressValid(sptdex) && sptdex->CdbLength > 0) {
				UCHAR cdb0 = sptdex->Cdb[0];
				int dataLen = (int)sptdex->DataInTransferLength;

				if ((cdb0 == 0xA1 || cdb0 == 0x85) && sptdex->CdbLength >= 12) {
					UCHAR ataCmd = (cdb0 == 0xA1) ? sptdex->Cdb[9] :
						(sptdex->CdbLength >= 16 ? sptdex->Cdb[14] : 0);
					if (ataCmd == 0xEC) {
						ata_identify_device* aid = (ata_identify_device*)dataBuffer;
						FindFakeDiskSerialAta((char*)aid->serial_no);
						FindFakeDiskModelAta((char*)aid->model, 40);
					}
					else if (ataCmd == 0xB0) {
						UCHAR feature = (cdb0 == 0xA1) ? sptdex->Cdb[3] : sptdex->Cdb[4];
						if (feature == 0xD0 && dataLen >= 362)
							ZeroSmartAttributes(dataBuffer, dataLen);
					}
				}
				else if (cdb0 == 0x12 && sptdex->CdbLength >= 3 && (sptdex->Cdb[1] & 0x01)) {
					UCHAR* vpd = (UCHAR*)dataBuffer;
					if (sptdex->Cdb[2] == 0x80 && vpd[1] == 0x80 && vpd[3] >= 3) {
						int slen = vpd[3]; if (slen > 40) slen = 40;
						char vpdSerial[41] = { 0 };
						RtlCopyMemory(vpdSerial, &vpd[4], slen);
						FindFakeDiskSerial(vpdSerial, slen);
						RtlCopyMemory(&vpd[4], vpdSerial, slen);
					}
					else if (sptdex->Cdb[2] == 0x83) {
						SpoofVpd83(vpd, dataLen);
					}
					else if (sptdex->Cdb[2] == 0x89 && dataLen >= 60 + 512) {
						ata_identify_device* aid = (ata_identify_device*)((UCHAR*)dataBuffer + 60);
						FindFakeDiskSerialAta((char*)aid->serial_no);
						FindFakeDiskModelAta((char*)aid->model, 40);
					}
				}
				else if (cdb0 == 0x12 && sptdex->CdbLength >= 3 && !(sptdex->Cdb[1] & 0x01)) {
					SpoofStandardInquiry((UCHAR*)dataBuffer, dataLen);
				}
				else if (cdb0 == 0xE4 || cdb0 == 0xE6) {
					NVME_IDENTIFY_DEVICE* nvmeIdentify = (NVME_IDENTIFY_DEVICE*)dataBuffer;
					char serialBuf[21] = { 0 };
					RtlCopyMemory(serialBuf, nvmeIdentify->SerialNumber, 20);
					FindFakeDiskSerial(serialBuf);
					RtlCopyMemory(nvmeIdentify->SerialNumber, serialBuf, 20);
					FindFakeDiskModel(nvmeIdentify->Model, 40);
				}
			}
		}

		if (request.DataMdl) {
			MmUnlockPages(request.DataMdl);
			IoFreeMdl(request.DataMdl);
		}

		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

NTSTATUS ScSlPassIocEX(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		SCSI_PASS_THROUGH_EX* spte = nullptr;

		if (!NT_SUCCESS(irp->IoStatus.Status)) goto _sptex_end;

		spte = (SCSI_PASS_THROUGH_EX*)request.Buffer;
		if (MmIsAddressValid(spte) && spte->DataInBufferOffset && spte->DataInBufferOffset < request.BufferLength) {
			PVOID dataBuffer = (PBYTE)request.Buffer + spte->DataInBufferOffset;
			if (!MmIsAddressValid(dataBuffer)) goto _sptex_end;
			int dataLen = (int)(request.BufferLength - spte->DataInBufferOffset);

			if (spte->Cdb[0] == 0xA1 || spte->Cdb[0] == 0x85) {
				UCHAR ataCmd = (spte->Cdb[0] == 0xA1) ? spte->Cdb[9] : spte->Cdb[14];
				if (ataCmd == 0xEC) {
					ata_identify_device* aid = (ata_identify_device*)dataBuffer;
					if (MmIsAddressValid(aid)) {
						FindFakeDiskSerialAta((char*)aid->serial_no);
						FindFakeDiskModelAta((char*)aid->model, 40);
					}
				}
				else if (ataCmd == 0xB0) {
					UCHAR feature = (spte->Cdb[0] == 0xA1) ? spte->Cdb[3] : spte->Cdb[4];
					if (feature == 0xD0 && dataLen >= 362)
						ZeroSmartAttributes(dataBuffer, dataLen);
				}
			}
			else if (spte->Cdb[0] == 0x12 && (spte->Cdb[1] & 0x01)) {
				UCHAR* vpd = (UCHAR*)dataBuffer;
				if (spte->Cdb[2] == 0x80 && vpd[1] == 0x80 && vpd[3] >= 3) {
					int slen = vpd[3]; if (slen > 40) slen = 40;
					FindFakeDiskSerial((char*)&vpd[4], slen);
				}
				else if (spte->Cdb[2] == 0x83)
					SpoofVpd83(vpd, dataLen);
				else if (spte->Cdb[2] == 0x89 && dataLen >= 60 + 512) {
					ata_identify_device* aid = (ata_identify_device*)((UCHAR*)dataBuffer + 60);
					if (MmIsAddressValid(aid)) {
						FindFakeDiskSerialAta((char*)aid->serial_no);
						FindFakeDiskModelAta((char*)aid->model, 40);
					}
				}
			}
			else if (spte->Cdb[0] == 0x12 && !(spte->Cdb[1] & 0x01)) {
				SpoofStandardInquiry((UCHAR*)dataBuffer, dataLen);
			}
			else if (spte->Cdb[0] == 0xE4 || spte->Cdb[0] == 0xE6) {
				NVME_IDENTIFY_DEVICE* nvmeIdentify = (NVME_IDENTIFY_DEVICE*)dataBuffer;
				if (MmIsAddressValid(nvmeIdentify)) {
					char serialBuf[21] = { 0 };
					RtlCopyMemory(serialBuf, nvmeIdentify->SerialNumber, 20);
					FindFakeDiskSerial(serialBuf);
					RtlCopyMemory(nvmeIdentify->SerialNumber, serialBuf, 20);
					FindFakeDiskModel(nvmeIdentify->Model, 40);
				}
			}
		}

	_sptex_end:
		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

NTSTATUS SRBIOC(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (!NT_SUCCESS(irp->IoStatus.Status)) goto _srb_end;

		if (request.BufferLength >= sizeof(SRB_IO_CONTROL)) {
			SRB_IO_CONTROL* srbCtrl = (SRB_IO_CONTROL*)request.Buffer;
			ULONG ctrlCode = srbCtrl->ControlCode;

			if (ctrlCode == 0x001b0502 || ctrlCode == 0x001b0503) {
				// SMART READ ATTRIBS / SMART READ LOG — zero POH/PCC
				const auto data = (SENDCMDOUTPARAMS*)((PUCHAR)request.Buffer + sizeof(SRB_IO_CONTROL));
				if (MmIsAddressValid(data) && MmIsAddressValid(data->bBuffer)) {
					ZeroSmartAttributes(data->bBuffer, 512);
				}
			}
			else {
				// IDENTIFY (0x001b0501) or other — spoof serial/model
				const auto data = (SENDCMDOUTPARAMS*)((PUCHAR)request.Buffer + sizeof(SRB_IO_CONTROL));
				if (MmIsAddressValid(data)) {
					const auto info = reinterpret_cast<IDINFO*>(data->bBuffer);
					if (MmIsAddressValid(info)) {
						FindFakeDiskSerialAta(info->sSerialNumber);
						FindFakeDiskModelAta(info->sModelNumber, 40);
					}
				}
			}
		}

	_srb_end:
		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

NTSTATUS SmartDataIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (NT_SUCCESS(irp->IoStatus.Status) && request.BufferLength >= sizeof(SENDCMDOUTPARAMS)) {
			PSENDCMDOUTPARAMS cmdParams = (PSENDCMDOUTPARAMS)request.Buffer;

			if (request.BufferLength >= (sizeof(SENDCMDOUTPARAMS) - 1 + 512)) {
				ata_identify_device* aid = (ata_identify_device*)cmdParams->bBuffer;
				if (MmIsAddressValid(aid) && MmIsAddressValid(aid->serial_no)) {
					FindFakeDiskSerialAta((char*)aid->serial_no);
					SmartFixupSerial((char*)aid->serial_no);
					FindFakeDiskModelAta((char*)aid->model, 40);

					WWN* pWwn = (WWN*)&aid->words088_255[20];
					if (MmIsAddressValid(pWwn))
						FindFakeWWN(pWwn);
				}
			}
			else {
				PIDSECTOR idSector = (PIDSECTOR)cmdParams->bBuffer;
				if (MmIsAddressValid(idSector)) {
					FindFakeDiskSerialAta(idSector->sSerialNumber);
					SmartFixupSerial(idSector->sSerialNumber);
					FindFakeDiskModelAta(idSector->sModelNumber, 40);
				}
			}
		}

		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

// ============================================================================
// NVMe Protocol-Specific (SQP PropertyId 49/50) completion routine
// ============================================================================

NTSTATUS NvmeProtocolSpecificIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (!NT_SUCCESS(irp->IoStatus.Status) || !MmIsAddressValid(request.Buffer))
			goto _nvme_proto_end;

		__try {
			ULONG respSize = (ULONG)irp->IoStatus.Information;
			if (respSize < sizeof(KMDF_PROTO_DATA_DESCRIPTOR))
				goto _nvme_proto_end;

			KMDF_PROTO_DATA_DESCRIPTOR* desc = (KMDF_PROTO_DATA_DESCRIPTOR*)request.Buffer;
			KMDF_PROTO_SPECIFIC_DATA* proto = &desc->ProtocolSpecificData;

			if (proto->ProtocolType != 3) // ProtocolTypeNvme
				goto _nvme_proto_end;

			ULONG dataOffset = proto->ProtocolDataOffset;
			ULONG dataLength = proto->ProtocolDataLength;
			if (dataOffset == 0 || dataLength == 0)
				goto _nvme_proto_end;

			PBYTE protoData = (PBYTE)proto + dataOffset;
			if (!MmIsAddressValid(protoData) || (PBYTE)protoData + dataLength > (PBYTE)request.Buffer + respSize)
				goto _nvme_proto_end;

			if (proto->DataType == 1) { // NVMeDataTypeIdentify
				if (proto->ProtocolDataRequestValue == 1) {
					// Controller Identify (CNS=1): serial at offset 4, model at offset 24, fw at offset 64
					if (dataLength >= 72) {
						NVME_IDENTIFY_DEVICE* ctrl = (NVME_IDENTIFY_DEVICE*)protoData;
						char serialBuf[21] = { 0 };
						RtlCopyMemory(serialBuf, ctrl->SerialNumber, 20);
						FindFakeDiskSerial(serialBuf);
						RtlCopyMemory(ctrl->SerialNumber, serialBuf, 20);
						FindFakeDiskModel(ctrl->Model, 40);
					}
				}
				else if (proto->ProtocolDataRequestValue == 0) {
					// Namespace Identify (CNS=0): NGUID at offset 104, EUI64 at offset 120
					if (dataLength >= 128) {
						UCHAR* nguid = protoData + 104; // 16 bytes
						UCHAR* eui64 = protoData + 120; // 8 bytes

						// Spoof NGUID via binary spoofing
						SpoofBinaryIdentifier(nguid, 16, kmdf_settings::hwid_seed ^ 0x4E475549);

						// Spoof EUI64 via serial cache for cross-IOCTL consistency
						const char hc[] = "0123456789ABCDEF";
						char serialBuf[21];
						int p = 0;
						for (int j = 0; j < 8; j++) {
							serialBuf[p++] = hc[(eui64[j] >> 4) & 0xF];
							serialBuf[p++] = hc[eui64[j] & 0xF];
							if (j == 1 || j == 3 || j == 5) serialBuf[p++] = '_';
						}
						serialBuf[p++] = '.';
						serialBuf[p] = 0;
						FindFakeDiskSerial(serialBuf, p);
						int ri = 0;
						for (int j = 0; j < 20 && ri < 8; j++) {
							char c = serialBuf[j];
							if (c == '_' || c == '.') continue;
							UCHAR hi = (c >= 'A') ? (c - 'A' + 10) : ((c >= 'a') ? (c - 'a' + 10) : (c - '0'));
							j++;
							if (j >= 20) break;
							c = serialBuf[j];
							UCHAR lo = (c >= 'A') ? (c - 'A' + 10) : ((c >= 'a') ? (c - 'a' + 10) : (c - '0'));
							eui64[ri++] = (hi << 4) | lo;
						}
					}
				}
			}
			else if (proto->DataType == 2) { // NVMeDataTypeLogPage
				if (proto->ProtocolDataRequestValue == 3) {
					// Firmware Slot Info (Log Page 3)
					// Slots at offsets 8, 16, 24, 32, 40, 48, 56 — each 8 bytes
					for (int slot = 0; slot < 7; slot++) {
						int off = 8 + slot * 8;
						if ((ULONG)(off + 8) > dataLength) break;
						SpoofFirmwareRevision((char*)(protoData + off), 8, kmdf_settings::hwid_seed ^ (0xFE000000 | slot));
					}
				}
				else if (proto->ProtocolDataRequestValue == 2) {
					// SMART/Health Log (Log Page 2) - NVMe spec offsets:
					// 32-47: Data Units Read, 48-63: Data Units Written
					// 112-127: Power Cycles, 128-143: Power On Hours
					if (dataLength >= 48)
						RtlZeroMemory(protoData + 32, 16); // Data Units Read
					if (dataLength >= 64)
						RtlZeroMemory(protoData + 48, 16); // Data Units Written
					if (dataLength >= 128)
						RtlZeroMemory(protoData + 112, 16); // Power Cycle Count
					if (dataLength >= 144)
						RtlZeroMemory(protoData + 128, 16); // Power On Hours
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}

	_nvme_proto_end:
		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

// ============================================================================
// SQP PropertyId 57 (Adapter Serial Number) completion routine
// ============================================================================

NTSTATUS AdapterSerialIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (!NT_SUCCESS(irp->IoStatus.Status) || !MmIsAddressValid(request.Buffer))
			goto _adapter_serial_end;

		__try {
			// Response: Version(ULONG), Size(ULONG), then Unicode serial string
			ULONG respSize = (ULONG)irp->IoStatus.Information;
			if (respSize <= 8) goto _adapter_serial_end;

			wchar_t* wSerial = (wchar_t*)((PBYTE)request.Buffer + 8);
			ULONG serialBytes = respSize - 8;
			int serialChars = (int)(serialBytes / sizeof(wchar_t));
			if (serialChars < 3 || serialChars > 128 || !MmIsAddressValid(wSerial))
				goto _adapter_serial_end;

			// Convert to narrow, spoof, write back
			char narrowSerial[129] = { 0 };
			int narrowLen = 0;
			for (int i = 0; i < serialChars && i < 128; i++) {
				if (wSerial[i] == 0) break;
				narrowSerial[narrowLen++] = (char)wSerial[i];
			}
			if (narrowLen >= 3) {
				FindFakeDiskSerial(narrowSerial, narrowLen);
				for (int i = 0; i < narrowLen; i++)
					wSerial[i] = (wchar_t)narrowSerial[i];
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}

	_adapter_serial_end:
		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

// ============================================================================
// SQP PropertyId 3 (Unique ID) completion routine
// ============================================================================

NTSTATUS UniqueIdPropertyIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (!NT_SUCCESS(irp->IoStatus.Status) || !MmIsAddressValid(request.Buffer))
			goto _uniqueid_end;

		__try {
			ULONG respSize = (ULONG)irp->IoStatus.Information;
			if (respSize < 8) goto _uniqueid_end;

			// STORAGE_DEVICE_UNIQUE_IDENTIFIER: Version(ULONG), Size(ULONG), then data
			ULONG* pSize = (ULONG*)((PBYTE)request.Buffer + 4);
			ULONG dataSize = *pSize;
			if (dataSize == 0 || dataSize > respSize - 8) goto _uniqueid_end;

			PBYTE data = (PBYTE)request.Buffer + 8;
			if (!MmIsAddressValid(data)) goto _uniqueid_end;

			// The unique ID often contains embedded serial/WWN data
			// Randomize the binary data using LCG seeded by hwid_seed XOR hash
			ULONG seed = kmdf_settings::hwid_seed ^ HashSerialBytes((const char*)data, (int)(dataSize > 64 ? 64 : dataSize));
			for (ULONG i = 0; i < dataSize; i++) {
				if (data[i] == 0) continue;
				ULONG r = DiskLCG(seed);
				data[i] = (UCHAR)(r & 0xFF);
				if (data[i] == 0) data[i] = 1;
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}

	_uniqueid_end:
		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

// ============================================================================
// IOCTL_STORAGE_GET_MEDIA_SERIAL_NUMBER completion routine
// ============================================================================

NTSTATUS MediaSerialIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (!NT_SUCCESS(irp->IoStatus.Status) || !MmIsAddressValid(request.Buffer))
			goto _media_serial_end;

		__try {
			// STORAGE_MEDIA_SERIAL_NUMBER_DATA: Reserved[2](USHORT), SerialNumberLength(ULONG), SerialNumber[]
			ULONG respSize = (ULONG)irp->IoStatus.Information;
			if (respSize < 8) goto _media_serial_end;

			ULONG* pSerialLen = (ULONG*)((PBYTE)request.Buffer + 4);
			ULONG serialLen = *pSerialLen;
			if (serialLen == 0 || serialLen > respSize - 8) goto _media_serial_end;

			PCHAR serial = (PCHAR)request.Buffer + 8;
			if (!MmIsAddressValid(serial)) goto _media_serial_end;

			if (serialLen >= 3 && serialLen <= 128)
				FindFakeDiskSerial(serial, (int)serialLen);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}

	_media_serial_end:
		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

// ============================================================================
// IOCTL_STORAGE_GET_DEVICE_NUMBER_EX completion routine
// ============================================================================

NTSTATUS DeviceNumberExIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (!NT_SUCCESS(irp->IoStatus.Status) || !MmIsAddressValid(request.Buffer))
			goto _devnumex_end;

		__try {
			ULONG respSize = (ULONG)irp->IoStatus.Information;
			// STORAGE_DEVICE_NUMBER_EX: Flags(ULONG), Type(ULONG), Number(ULONG), DeviceGuid(GUID @ offset 16), PartNum(ULONG)
			if (respSize < 32) goto _devnumex_end;

			// DeviceGuid at offset 16 (16 bytes)
			wchar_t* guidData = (wchar_t*)((PBYTE)request.Buffer + 16);
			if (MmIsAddressValid(guidData)) {
				// Randomize the GUID
				ULONG seed = kmdf_settings::hwid_seed ^ HashSerialBytes((const char*)guidData, 16);
				UCHAR* rawGuid = (UCHAR*)guidData;
				for (int i = 0; i < 16; i++) {
					ULONG r = DiskLCG(seed);
					rawGuid[i] = (UCHAR)(r & 0xFF);
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}

	_devnumex_end:
		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

// ============================================================================
// IOCTL_STORAGE_FIRMWARE_GET_INFO completion routine
// ============================================================================

NTSTATUS FirmwareInfoIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (!NT_SUCCESS(irp->IoStatus.Status) || !MmIsAddressValid(request.Buffer))
			goto _fwinfo_end;

		__try {
			ULONG respSize = (ULONG)irp->IoStatus.Information;
			// STORAGE_FIRMWARE_INFO_V2:
			// Version(ULONG), Size(ULONG), UpgradeSupport(BOOL), SlotCount(UCHAR),
			// ActiveSlot(UCHAR), PendingActivateSlot(UCHAR), FirmwareShared(BOOL),
			// ImagePayloadAlignment(ULONG), ImagePayloadMaxSize(ULONG),
			// Slot[] — each STORAGE_FIRMWARE_SLOT_INFO_V2 is 16 bytes (SlotNumber, ReadOnly, Reserved[6], Revision[8])
			if (respSize < 24) goto _fwinfo_end;

			UCHAR slotCount = *((UCHAR*)request.Buffer + 9);
			if (slotCount == 0 || slotCount > 7) goto _fwinfo_end;

			ULONG slotsOffset = 24; // After header
			for (UCHAR i = 0; i < slotCount; i++) {
				ULONG slotOff = slotsOffset + i * 16;
				if (slotOff + 16 > respSize) break;
				char* fwRevision = (char*)request.Buffer + slotOff + 8; // 8-byte revision
				if (MmIsAddressValid(fwRevision))
					SpoofFirmwareRevision(fwRevision, 8, kmdf_settings::hwid_seed ^ (0xFE000000 | i));
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}

	_fwinfo_end:
		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

// ============================================================================
// IOCTL_SCSI_GET_INQUIRY_DATA completion routine
// ============================================================================

NTSTATUS ScsiAdapterInquiryIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (!NT_SUCCESS(irp->IoStatus.Status) || !MmIsAddressValid(request.Buffer))
			goto _scsi_adapter_end;

		__try {
			ULONG respSize = (ULONG)irp->IoStatus.Information;
			if (respSize < sizeof(KMDF_SCSI_ADAPTER_BUS_INFO)) goto _scsi_adapter_end;

			KMDF_SCSI_ADAPTER_BUS_INFO* adapterInfo = (KMDF_SCSI_ADAPTER_BUS_INFO*)request.Buffer;
			for (UCHAR bus = 0; bus < adapterInfo->NumberOfBuses; bus++) {
				ULONG inquiryOffset = adapterInfo->BusData[bus].InquiryDataOffset;
				if (inquiryOffset == 0) continue;

				while (inquiryOffset != 0 && inquiryOffset + sizeof(KMDF_SCSI_INQUIRY_DATA) <= respSize) {
					KMDF_SCSI_INQUIRY_DATA* inquiryData = (KMDF_SCSI_INQUIRY_DATA*)((PBYTE)request.Buffer + inquiryOffset);
					if (!MmIsAddressValid(inquiryData)) break;

					// Standard INQUIRY data: vendor at 8, product at 16, revision at 32
					if (inquiryData->InquiryDataLength >= 36) {
						SpoofStandardInquiry(inquiryData->InquiryData, inquiryData->InquiryDataLength);
					}

					if (inquiryData->NextInquiryDataOffset == 0) break;
					inquiryOffset = inquiryData->NextInquiryDataOffset;
				}
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}

	_scsi_adapter_end:
		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

// ============================================================================
// IOCTL_STORAGE_PREDICT_FAILURE completion routine
// ============================================================================

NTSTATUS PredictFailureIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (!NT_SUCCESS(irp->IoStatus.Status) || !MmIsAddressValid(request.Buffer))
			goto _predict_end;

		__try {
			// STORAGE_PREDICT_FAILURE: PredictFailure(ULONG=4) + VendorSpecific[512]
			ULONG respSize = (ULONG)irp->IoStatus.Information;
			if (respSize < 4 + 362) goto _predict_end;

			PVOID smartData = (PBYTE)request.Buffer + 4; // VendorSpecific
			ZeroSmartAttributes(smartData, 512);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {}

	_predict_end:
		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

// ============================================================================
// Helper: set up MDL for DIRECT IOCTL user-mode buffer
// ============================================================================

void SetupDirectMdl(PIO_STACK_LOCATION ioc, PVOID userBuffer, ULONG bufferLength) {
	if (!userBuffer
		|| (ULONG_PTR)userBuffer >= (ULONG_PTR)MmHighestUserAddress
		|| bufferLength == 0
		|| bufferLength >= 0x10000)
		return;

	kmdf_utils::PIOC_REQUEST req = (kmdf_utils::PIOC_REQUEST)ioc->Context;
	if (!req) return;

	PMDL mdl = IoAllocateMdl(userBuffer, bufferLength, FALSE, FALSE, NULL);
	if (mdl) {
		__try {
			MmProbeAndLockPages(mdl, UserMode, IoModifyAccess);
			req->DataMdl = mdl;
		} __except (EXCEPTION_EXECUTE_HANDLER) {
			IoFreeMdl(mdl);
		}
	}
}

// ============================================================================
// Dispatch: routes IOCTLs to completion routines (shared by all disk drivers)
// ============================================================================

NTSTATUS DiskDispatchCommon(PDEVICE_OBJECT device, PIRP irp, PDRIVER_DISPATCH pOriginal) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	if (!ioc) return pOriginal(device, irp);

	const unsigned long code = ioc->Parameters.DeviceIoControl.IoControlCode;
	PSTORAGE_PROPERTY_QUERY pQuery = nullptr;

	const char* ioctlName = nullptr;
	switch (code) {
	case IOCTL_SCSI_PASS_THROUGH:
		ioctlName = "SCSI_PASS_THROUGH";
		kmdf_utils::change_ioc(ioc, irp, ScSlPassIoc);
		break;

	case IOCTL_STORAGE_QUERY_PROPERTY:
		pQuery = (PSTORAGE_PROPERTY_QUERY)irp->AssociatedIrp.SystemBuffer;
		if (MmIsAddressValid(pQuery)) {
			if (pQuery->PropertyId == StorageDeviceProperty) {
				ioctlName = "SQP_DeviceProperty";
				kmdf_utils::change_ioc(ioc, irp, StorageQueryIoc);
			}
			else if (pQuery->PropertyId == StorageDeviceIdProperty) {
				ioctlName = "SQP_DeviceIdProperty";
				kmdf_utils::change_ioc(ioc, irp, StorageDeviceIdIoc);
			}
			else if (pQuery->PropertyId == 49 || pQuery->PropertyId == 50) {
				ioctlName = "SQP_NvmeProtocol";
				kmdf_utils::change_ioc(ioc, irp, NvmeProtocolSpecificIoc);
			}
			else if (pQuery->PropertyId == 57) {
				ioctlName = "SQP_AdapterSerial";
				kmdf_utils::change_ioc(ioc, irp, AdapterSerialIoc);
			}
			else if (pQuery->PropertyId == 3) {
				ioctlName = "SQP_UniqueId";
				kmdf_utils::change_ioc(ioc, irp, UniqueIdPropertyIoc);
			}
			else {
				ioctlName = "SQP_Other";
				kmdf_utils::change_ioc(ioc, irp, StorageQueryIoc);
			}
		}
		break;

	case IOCTL_ATA_PASS_THROUGH_DIRECT:
	{
		PATA_PASS_THROUGH_DIRECT aptd = (PATA_PASS_THROUGH_DIRECT)irp->AssociatedIrp.SystemBuffer;
		if (MmIsAddressValid(aptd) && aptd->CurrentTaskFile[6] == 0xB0 && aptd->CurrentTaskFile[0] == 0xD0) {
			ioctlName = "ATA_SMART_Direct";
			kmdf_utils::change_ioc(ioc, irp, AtaSmartDirectIoc);
		} else {
			ioctlName = "ATA_PassThru_Direct";
			kmdf_utils::change_ioc(ioc, irp, ATAPass_DirectIoc);
		}
		ioc->Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
		if (MmIsAddressValid(aptd))
			SetupDirectMdl(ioc, aptd->DataBuffer, aptd->DataTransferLength);
		break;
	}

	case IOCTL_ATA_PASS_THROUGH:
	{
		PATA_PASS_THROUGH_EX pte = (PATA_PASS_THROUGH_EX)irp->AssociatedIrp.SystemBuffer;
		if (MmIsAddressValid(pte) && pte->CurrentTaskFile[6] == 0xB0 && pte->CurrentTaskFile[0] == 0xD0) {
			ioctlName = "ATA_SMART";
			kmdf_utils::change_ioc(ioc, irp, AtaSmartIoc);
		} else {
			ioctlName = "ATA_PassThru";
			kmdf_utils::change_ioc(ioc, irp, AtaPassIoc);
		}
		break;
	}

	case IOCTL_SCSI_PASS_THROUGH_DIRECT:
	{
		ioctlName = "SCSI_PassThru_Direct";
		kmdf_utils::change_ioc(ioc, irp, ScSlPass_DirectIoc);
		ioc->Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
		PSCSI_PASS_THROUGH_DIRECT sptd = (PSCSI_PASS_THROUGH_DIRECT)irp->AssociatedIrp.SystemBuffer;
		if (MmIsAddressValid(sptd))
			SetupDirectMdl(ioc, sptd->DataBuffer, sptd->DataTransferLength);
		break;
	}

	case IOCTL_SCSI_PASS_THROUGH_DIRECT_EX:
	{
		ioctlName = "SCSI_PassThru_DirectEX";
		kmdf_utils::change_ioc(ioc, irp, ScSlPass_DirectIocEX);
		ioc->Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
		PSCSI_PASS_THROUGH_DIRECT_EX sptdex = (PSCSI_PASS_THROUGH_DIRECT_EX)irp->AssociatedIrp.SystemBuffer;
		if (MmIsAddressValid(sptdex))
			SetupDirectMdl(ioc, sptdex->DataInBuffer, sptdex->DataInTransferLength);
		break;
	}

	case IOCTL_SCSI_PASS_THROUGH_EX:
		ioctlName = "SCSI_PassThru_EX";
		kmdf_utils::change_ioc(ioc, irp, ScSlPassIocEX);
		break;

	case IOCTL_SCSI_MINIPORT:
	case IOCTL_SCSI_MINIPORT_IDENTIFY:
		ioctlName = "SCSI_Miniport";
		kmdf_utils::change_ioc(ioc, irp, SRBIOC);
		break;

	case IOCTL_INTEL_NVME_PASS_THROUGH:
	case NVME_PASS_THROUGH_SRB_IO_CODE:
		ioctlName = "NVMe_PassThru";
		kmdf_utils::change_ioc(ioc, irp, NVME_Pass_Through);
		break;

	case SMART_RCV_DRIVE_DATA:
	{
		PSENDCMDINPARAMS cmdIn = (PSENDCMDINPARAMS)irp->AssociatedIrp.SystemBuffer;
		if (MmIsAddressValid(cmdIn) && cmdIn->irDriveRegs.bCommandReg == 0xB0) {
			ioctlName = "SMART_SmartData";
			kmdf_utils::change_ioc(ioc, irp, SmartSmartDataIoc);
		} else {
			ioctlName = "SMART_DriveData";
			kmdf_utils::change_ioc(ioc, irp, SmartDataIoc);
		}
		break;
	}

	case 0x002D0C10:
		ioctlName = "MediaSerial";
		kmdf_utils::change_ioc(ioc, irp, MediaSerialIoc);
		break;

	case 0x002D1118:
		ioctlName = "DeviceNumberEX";
		kmdf_utils::change_ioc(ioc, irp, DeviceNumberExIoc);
		break;

	case 0x002D1C00:
		ioctlName = "FirmwareInfo";
		kmdf_utils::change_ioc(ioc, irp, FirmwareInfoIoc);
		break;

	case 0x00050010:
		ioctlName = "ScsiAdapterInquiry";
		kmdf_utils::change_ioc(ioc, irp, ScsiAdapterInquiryIoc);
		break;

	case 0x002D1100:
		ioctlName = "PredictFailure";
		kmdf_utils::change_ioc(ioc, irp, PredictFailureIoc);
		break;

	case IOCTL_ATA_MINIPORT:
	case IOCTL_IDE_PASS_THROUGH:
	case IOCTL_MPIO_PASS_THROUGH_PATH:
	case IOCTL_MPIO_PASS_THROUGH_PATH_DIRECT:
		DbgPrintEx(0, 0, "[SPOOF] IOCTL blocked: 0x%08X\n", code);
		irp->IoStatus.Information = 0;
		irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
		IofCompleteRequest(irp, 0);
		return STATUS_NOT_SUPPORTED;
	}

	if (ioctlName)
		DbgPrintEx(0, 0, "[SPOOF] Intercepted %s (0x%08X)\n", ioctlName, code);

	return pOriginal(device, irp);
}

// disk.sys handler (legacy compatibility wrapper)
NTSTATUS HDD_Disk_Handle(PDEVICE_OBJECT device, PIRP irp) {
	return DiskDispatchCommon(device, irp, HDD_Disk_Control);
}

// storahci handler
NTSTATUS StorahciHandle(PDEVICE_OBJECT device, PIRP irp) {
	return DiskDispatchCommon(device, irp, g_original_storahci_control);
}

// stornvme handler
NTSTATUS StornvmeHandle(PDEVICE_OBJECT device, PIRP irp) {
	return DiskDispatchCommon(device, irp, g_original_stornvme_control);
}

// Multi-driver dispatch: used for dynamically hooked drivers (ScsiPort etc.)
NTSTATUS MultiDiskHandle(PDEVICE_OBJECT device, PIRP irp) {
	PDRIVER_DISPATCH orig = nullptr;
	for (int i = 0; i < g_diskHookCount; i++) {
		if (g_diskHooks[i].driverObject == device->DriverObject) {
			orig = g_diskHooks[i].original;
			break;
		}
	}
	if (!orig) {
		irp->IoStatus.Status = STATUS_SUCCESS;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_SUCCESS;
	}
	return DiskDispatchCommon(device, irp, orig);
}

// ============================================================================
// Partition handlers
// ============================================================================

NTSTATUS my_part_info_ioc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
{
	if (context)
	{
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (NT_SUCCESS(irp->IoStatus.Status) && request.BufferLength >= sizeof(PARTITION_INFORMATION_EX))
		{
			PPARTITION_INFORMATION_EX info = (PPARTITION_INFORMATION_EX)request.Buffer;
			if (info->PartitionStyle == PARTITION_STYLE_GPT) {
				Random::random_string((char*)&info->Gpt.PartitionId, sizeof(GUID));
			}
			else if (info->PartitionStyle == PARTITION_STYLE_MBR)
			{
				Random::random_string((char*)&info->Mbr.PartitionId, sizeof(GUID));
			}
		}
		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

NTSTATUS my_part_layout_ioc(PDEVICE_OBJECT device, PIRP irp, PVOID context)
{
	if (context)
	{
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);
		if (NT_SUCCESS(irp->IoStatus.Status) && request.BufferLength >= sizeof(DRIVE_LAYOUT_INFORMATION_EX))
		{
			PDRIVE_LAYOUT_INFORMATION_EX info = (PDRIVE_LAYOUT_INFORMATION_EX)request.Buffer;
			if (info->PartitionStyle == PARTITION_STYLE_GPT) {
				Random::random_string((char*)&info->Gpt.DiskId, sizeof(GUID));
			}
		}
		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

// ============================================================================
// Volume GUID spoofing (Phase 5: completion routine instead of blocking)
// ============================================================================

static void GenerateRandomHexWChar(wchar_t* buf, int count, ULONG& seed) {
	static const wchar_t hexChars[] = L"0123456789abcdef";
	for (int i = 0; i < count; i++) {
		ULONG r = DiskLCG(seed);
		buf[i] = hexChars[r % 16];
	}
}

bool FindFakeVolumeGUID(wchar_t* pOriginal) {
	if (!pOriginal || !MmIsAddressValid(pOriginal))
		return false;

	// Check cache
	for (int i = 0; i < g_volGuidCount; i++) {
		if (!memcmp(g_volGuidCache[i].orig, pOriginal, 4 * sizeof(wchar_t))) {
			RtlCopyMemory(pOriginal, g_volGuidCache[i].spoofed, VOLUME_GUID_MAX_LENGTH * sizeof(wchar_t));
			return true;
		}
	}

	if (g_volGuidCount >= MAX_VOL_GUID_CACHE) return false;

	VolumeGuidCacheEntry* entry = &g_volGuidCache[g_volGuidCount];
	RtlCopyMemory(entry->orig, pOriginal, VOLUME_GUID_MAX_LENGTH * sizeof(wchar_t));
	entry->orig[VOLUME_GUID_MAX_LENGTH] = 0;
	RtlCopyMemory(entry->spoofed, pOriginal, VOLUME_GUID_MAX_LENGTH * sizeof(wchar_t));
	entry->spoofed[VOLUME_GUID_MAX_LENGTH] = 0;

	// Randomize GUID segments (preserve structure: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
	ULONG seed = kmdf_settings::hwid_seed ^ HashSerialBytes((const char*)pOriginal, 8);
	// Spoof first 8 hex digits (positions 0-7)
	GenerateRandomHexWChar(entry->spoofed, 8, seed);
	// Spoof after first dash (positions 9-12)
	GenerateRandomHexWChar(entry->spoofed + 9, 4, seed);
	// Spoof after second dash (positions 14-17)
	GenerateRandomHexWChar(entry->spoofed + 14, 4, seed);
	// Spoof after third dash (positions 19-22)
	GenerateRandomHexWChar(entry->spoofed + 19, 4, seed);
	// Spoof last segment (positions 24-35)
	GenerateRandomHexWChar(entry->spoofed + 24, 12, seed);

	DbgPrintEx(0, 0, "[SPOOF] VolumeGUID [%d]: <%.*ws> -> <%.*ws>\n",
		g_volGuidCount, VOLUME_GUID_MAX_LENGTH, entry->orig, VOLUME_GUID_MAX_LENGTH, entry->spoofed);
	g_volGuidCount++;
	RtlCopyMemory(pOriginal, entry->spoofed, VOLUME_GUID_MAX_LENGTH * sizeof(wchar_t));
	return true;
}

NTSTATUS MountPointsIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (MmIsAddressValid(context)) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (NT_SUCCESS(irp->IoStatus.Status) && request.BufferLength >= sizeof(MOUNTMGR_MOUNT_POINTS)) {
			PMOUNTMGR_MOUNT_POINTS points = (PMOUNTMGR_MOUNT_POINTS)request.Buffer;
			if (MmIsAddressValid(points)) {
				for (DWORD32 i = 0; i < points->NumberOfMountPoints; ++i) {
					volatile PMOUNTMGR_MOUNT_POINT point = points->MountPoints + i;
						// Spoof volume GUID paths (\\?\Volume{GUID})
					// Symbolic links are pre-created in CreateSpoofedVolumeSymlinks()
					// so MSFT_Volume can still resolve the spoofed paths.
					if (point->SymbolicLinkNameLength >= GUID_OFFSET + VOLUME_GUID_MAX_LENGTH * (USHORT)sizeof(wchar_t) &&
						point->SymbolicLinkNameOffset + GUID_OFFSET + VOLUME_GUID_MAX_LENGTH * sizeof(wchar_t) <= request.BufferLength) {
						wchar_t* symLink = (wchar_t*)((char*)points + point->SymbolicLinkNameOffset);
						// Check for \\?\Volume{ or \??\Volume{ prefix (GUID_OFFSET/2 = 11 wchars past start)
						if (symLink[0] == L'\\' && symLink[3] == L'\\' && symLink[4] == L'V' &&
							symLink[10] == L'{') {
							FindFakeVolumeGUID(symLink + GUID_OFFSET / 2);
						}
					}
					// Handle DMIO binary UniqueId
					if (point->UniqueIdLength >= 24 &&
						point->UniqueIdOffset + 24 <= request.BufferLength) {
						UCHAR* uid = (UCHAR*)((char*)points + point->UniqueIdOffset);
						if (uid[0] == 'D' && uid[1] == 'M' && uid[2] == 'I' && uid[3] == 'O' &&
							uid[4] == ':' && uid[5] == 'I' && uid[6] == 'D' && uid[7] == ':') {
							SpoofBinaryIdentifier(uid + 8, 16, kmdf_settings::hwid_seed ^ 0x444D494F);
						}
					}
				}
			}
		}

		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

NTSTATUS MountUniqueIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (MmIsAddressValid(context)) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (NT_SUCCESS(irp->IoStatus.Status) && request.BufferLength >= sizeof(MOUNTDEV_UNIQUE_ID)) {
			PMOUNTDEV_UNIQUE_ID point = (PMOUNTDEV_UNIQUE_ID)request.Buffer;
			if (MmIsAddressValid(point)) {
				// Spoof volume GUID UniqueId format (\\?\Volume{GUID})
				if (point->UniqueIdLength >= GUID_OFFSET + VOLUME_GUID_MAX_LENGTH * (int)sizeof(wchar_t)) {
					wchar_t* uidW = (wchar_t*)point->UniqueId;
					if (uidW[0] == L'\\' && uidW[3] == L'\\' && uidW[4] == L'V' && uidW[10] == L'{') {
						FindFakeVolumeGUID(uidW + GUID_OFFSET / 2);
					}
				}
				// Spoof DMIO binary format
				if (point->UniqueIdLength >= 24 &&
					point->UniqueId[0] == 'D' && point->UniqueId[1] == 'M' &&
					point->UniqueId[2] == 'I' && point->UniqueId[3] == 'O' &&
					point->UniqueId[4] == ':' && point->UniqueId[5] == 'I' &&
					point->UniqueId[6] == 'D' && point->UniqueId[7] == ':') {
					// DMIO format: "DMIO:ID:" + 16-byte binary GUID
					UCHAR* guid = (UCHAR*)point->UniqueId + 8;
					UCHAR origDmio[8];
					RtlCopyMemory(origDmio, guid, 8);
					SpoofBinaryIdentifier(guid, 16, kmdf_settings::hwid_seed ^ 0x444D494F);
					DbgPrintEx(0, 0, "[SPOOF] MountUniqueId DMIO: <%02X%02X%02X%02X%02X%02X%02X%02X> -> <%02X%02X%02X%02X%02X%02X%02X%02X>\n",
						origDmio[0], origDmio[1], origDmio[2], origDmio[3], origDmio[4], origDmio[5], origDmio[6], origDmio[7],
						guid[0], guid[1], guid[2], guid[3], guid[4], guid[5], guid[6], guid[7]);
				}
			}
		}

		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

NTSTATUS my_mountmgr_handle_control(PDEVICE_OBJECT device, PIRP irp)
{
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	unsigned long code = ioc->Parameters.DeviceIoControl.IoControlCode;
	switch (code)
	{
	case IOCTL_MOUNTMGR_QUERY_POINTS:
		kmdf_utils::change_ioc(ioc, irp, MountPointsIoc);
		break;
	case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
		kmdf_utils::change_ioc(ioc, irp, MountUniqueIoc);
		break;
	}
	return g_original_mountmgr_control(device, irp);
}

NTSTATUS my_partmgr_handle_control(PDEVICE_OBJECT device, PIRP irp)
{
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	unsigned long code = ioc->Parameters.DeviceIoControl.IoControlCode;
	switch (code)
	{
	//case IOCTL_DISK_GET_PARTITION_INFO_EX:
	//	kmdf_utils::change_ioc(ioc, irp, my_part_info_ioc);
	//	break;
	//case IOCTL_DISK_GET_DRIVE_LAYOUT_EX:
	//	kmdf_utils::change_ioc(ioc, irp, my_part_layout_ioc);
	//	break;
	}
	return g_original_partmgr_control(device, irp);
}

// Forward declarations for functions defined later
static bool SpoofBufferContentAscii(char* buf, int bufLen);
static bool SpoofBufferContentWchar(char* buf, int bufLen);
static void RegisterEuiFromBuffer(char* buf, int bufLen);
static NTSTATUS SpaceportGenericIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context);

// ============================================================================
// Fix 2: SpacePort handler — routes through DiskDispatchCommon for MSFT_PhysicalDisk
// ============================================================================

NTSTATUS SpaceportHandle(PDEVICE_OBJECT device, PIRP irp) {
	// Set up generic completion routine on ALL spaceport IOCTLs to do
	// find-and-replace on response buffers (covers MSFT_PhysicalDisk)
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	if (ioc && ioc->Parameters.DeviceIoControl.OutputBufferLength > 0) {
		kmdf_utils::change_ioc(ioc, irp, SpaceportGenericIoc);
	}
	return g_original_spaceport_control(device, irp);
}

// ============================================================================
// Fix 2b: SpacePort generic IOC — catches ALL spaceport IOCTL responses and
// does find-and-replace for known original serial/model strings (ASCII + Unicode).
// This covers MSFT_PhysicalDisk data that flows through spaceport.
// ============================================================================

NTSTATUS SpaceportGenericIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (NT_SUCCESS(irp->IoStatus.Status) && request.Buffer && request.BufferLength > 0) {
			__try {
				char* buf = (char*)request.Buffer;
				int bufLen = (int)request.BufferLength;
				if (MmIsAddressValid(buf)) {
					RegisterEuiFromBuffer(buf, bufLen);
					SpoofBufferContentAscii(buf, bufLen);
					SpoofBufferContentWchar(buf, bufLen);
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {}
		}

		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

// ============================================================================
// Fix 3: volmgr handler — intercepts IOCTL_MOUNTDEV_QUERY_UNIQUE_ID on volumes
// ============================================================================

NTSTATUS VolmgrHandle(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	if (ioc) {
		ULONG code = ioc->Parameters.DeviceIoControl.IoControlCode;
		if (code == IOCTL_MOUNTDEV_QUERY_UNIQUE_ID) {
			DbgPrintEx(0, 0, "[SPOOF] Intercepted volmgr MOUNTDEV_QUERY_UNIQUE_ID\n");
			kmdf_utils::change_ioc(ioc, irp, MountUniqueIoc);
		}
	}
	return g_original_volmgr_control(device, irp);
}

// ============================================================================
// Fix 4: Ntfs volume serial number hook
// ============================================================================

NTSTATUS NtfsVolumeInfoIoc(PDEVICE_OBJECT device, PIRP irp, PVOID context) {
	if (context) {
		kmdf_utils::IOC_REQUEST request = *(kmdf_utils::PIOC_REQUEST)context;
		ExFreePool(context);

		if (NT_SUCCESS(irp->IoStatus.Status) && request.Buffer) {
			// FILE_FS_VOLUME_INFORMATION layout:
			// LARGE_INTEGER VolumeCreationTime (8 bytes)
			// ULONG VolumeSerialNumber (4 bytes @ offset 8)
			if (request.BufferLength >= 12) {
				ULONG* pSerial = (ULONG*)((UCHAR*)request.Buffer + 8);
				if (MmIsAddressValid(pSerial) && *pSerial != 0) {
					ULONG orig = *pSerial;
					ULONG seed = kmdf_settings::hwid_seed ^ orig;
					*pSerial = DiskLCG(seed);
					DbgPrintEx(0, 0, "[SPOOF] VolSerial: <%08X> -> <%08X>\n", orig, *pSerial);
				}
			}
		}

		if (request.OldRoutine)
			return request.OldRoutine(device, irp, request.OldContext);
	}
	return STATUS_SUCCESS;
}

NTSTATUS NtfsVolumeInfoHandle(PDEVICE_OBJECT device, PIRP irp) {
	PIO_STACK_LOCATION ioc = IoGetCurrentIrpStackLocation(irp);
	if (ioc && ioc->Parameters.QueryVolume.FsInformationClass == FileFsVolumeInformation) {
		// Manual IOC_REQUEST setup — change_ioc reads DeviceIoControl.OutputBufferLength
		// which is wrong for IRP_MJ_QUERY_VOLUME_INFORMATION
		auto* req = (kmdf_utils::PIOC_REQUEST)ExAllocatePool(NonPagedPool, sizeof(kmdf_utils::IOC_REQUEST));
		if (req) {
			req->Buffer = irp->AssociatedIrp.SystemBuffer;
			req->BufferLength = ioc->Parameters.QueryVolume.Length;
			req->OldContext = ioc->Context;
			req->OldRoutine = ioc->CompletionRoutine;
			req->DataMdl = nullptr;
			ioc->Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
			ioc->Context = req;
			ioc->CompletionRoutine = NtfsVolumeInfoIoc;
		}
	}
	return g_original_ntfs_volinfo(device, irp);
}

// ============================================================================
// Fix 1: Registry spoofing helpers
// ============================================================================

static KEY_VALUE_PARTIAL_INFORMATION* RegReadVal(HANDLE hKey, const wchar_t* name) {
	UNICODE_STRING uName;
	RtlInitUnicodeString(&uName, name);
	ULONG resultLen = 0;
	NTSTATUS st = ZwQueryValueKey(hKey, &uName, KeyValuePartialInformation, NULL, 0, &resultLen);
	if (st != STATUS_BUFFER_TOO_SMALL || resultLen == 0) return nullptr;
	auto* p = (KEY_VALUE_PARTIAL_INFORMATION*)ExAllocatePoolWithTag(NonPagedPool, resultLen, 'RegR');
	if (!p) return nullptr;
	st = ZwQueryValueKey(hKey, &uName, KeyValuePartialInformation, p, resultLen, &resultLen);
	if (!NT_SUCCESS(st)) { ExFreePoolWithTag(p, 'RegR'); return nullptr; }
	return p;
}

static NTSTATUS RegWriteVal(HANDLE hKey, const wchar_t* name, ULONG type, void* data, ULONG dataLen) {
	UNICODE_STRING uName;
	RtlInitUnicodeString(&uName, name);
	return ZwSetValueKey(hKey, &uName, 0, type, data, dataLen);
}

// Spoof a REG_SZ value in-place using FindFakeDiskModel
static void SpoofRegSzModel(HANDLE hKey, const wchar_t* valueName) {
	auto* pInfo = RegReadVal(hKey, valueName);
	if (!pInfo || pInfo->Type != REG_SZ) { if (pInfo) ExFreePoolWithTag(pInfo, 'RegR'); return; }

	wchar_t* wData = (wchar_t*)pInfo->Data;
	int wLen = (int)(pInfo->DataLength / sizeof(wchar_t));
	if (wLen > 0 && wData[wLen - 1] == L'\0') wLen--;
	if (wLen <= 0) { ExFreePoolWithTag(pInfo, 'RegR'); return; }

	// Convert to ASCII
	char charBuf[256] = { 0 };
	int charLen = wLen < 255 ? wLen : 255;
	for (int i = 0; i < charLen; i++)
		charBuf[i] = (char)(wData[i] & 0x7F);

	// Find and strip known suffixes to isolate model portion
	char* suffix = nullptr;
	const char* suffixStr = "";
	const char* suffixes[] = { " SCSI Disk Device", " NVMe Disk Device", " Disk Device", " SCSI Disk", " NVMe Disk" };
	for (int s = 0; s < 5; s++) {
		int slen = (int)strlen(suffixes[s]);
		if (charLen > slen && !memcmp(charBuf + charLen - slen, suffixes[s], slen)) {
			suffix = charBuf + charLen - slen;
			suffixStr = suffixes[s];
			break;
		}
	}

	int modelLen = suffix ? (int)(suffix - charBuf) : charLen;
	while (modelLen > 0 && charBuf[modelLen - 1] == ' ') modelLen--;
	if (modelLen <= 0 || modelLen > 40) { ExFreePoolWithTag(pInfo, 'RegR'); return; }

	char modelBuf[41] = { 0 };
	RtlCopyMemory(modelBuf, charBuf, modelLen);
	if (FindFakeDiskModel(modelBuf, modelLen > 40 ? 40 : modelLen)) {
		int spoofedLen = 40;
		while (spoofedLen > 0 && (modelBuf[spoofedLen - 1] == ' ' || modelBuf[spoofedLen - 1] == '\0')) spoofedLen--;

		wchar_t newVal[256] = { 0 };
		int pos = 0;
		for (int i = 0; i < spoofedLen && pos < 254; i++)
			newVal[pos++] = (wchar_t)modelBuf[i];
		for (int i = 0; suffixStr[i] && pos < 254; i++)
			newVal[pos++] = (wchar_t)suffixStr[i];
		newVal[pos] = L'\0';

		RegWriteVal(hKey, valueName, REG_SZ, newVal, (ULONG)((pos + 1) * sizeof(wchar_t)));
		DbgPrintEx(0, 0, "[SPOOF] Registry %ws: <%.*s> -> <%.*s>\n", valueName, charLen, charBuf, spoofedLen, modelBuf);
	}
	ExFreePoolWithTag(pInfo, 'RegR');
}

// Spoof a REG_SZ serial value
static void SpoofRegSzSerial(HANDLE hKey, const wchar_t* valueName) {
	auto* pInfo = RegReadVal(hKey, valueName);
	if (!pInfo || pInfo->Type != REG_SZ) { if (pInfo) ExFreePoolWithTag(pInfo, 'RegR'); return; }

	wchar_t* wData = (wchar_t*)pInfo->Data;
	int wLen = (int)(pInfo->DataLength / sizeof(wchar_t));
	if (wLen > 0 && wData[wLen - 1] == L'\0') wLen--;
	if (wLen <= 0 || wLen > 48) { ExFreePoolWithTag(pInfo, 'RegR'); return; }

	char charBuf[64] = { 0 };
	for (int i = 0; i < wLen; i++)
		charBuf[i] = (char)(wData[i] & 0x7F);

	char origSerial[64] = { 0 };
	RtlCopyMemory(origSerial, charBuf, wLen);
	if (FindFakeDiskSerial(charBuf, wLen)) {
		wchar_t wBuf[64] = { 0 };
		for (int i = 0; i < wLen; i++)
			wBuf[i] = (wchar_t)charBuf[i];
		wBuf[wLen] = L'\0';
		RegWriteVal(hKey, valueName, REG_SZ, wBuf, (ULONG)((wLen + 1) * sizeof(wchar_t)));
		DbgPrintEx(0, 0, "[SPOOF] Registry %ws: <%.*s> -> <%.*s>\n", valueName, wLen, origSerial, wLen, charBuf);
	}
	ExFreePoolWithTag(pInfo, 'RegR');
}

// Extract the embedded model from a SCSI HardwareID by stripping prefix and converting underscores.
// Input:  "SCSI\DiskWDC_____WD10SPSX-08A6W__01.0" or "SCSI\WDC_____WD10SPSX-08A6W__0"
// Output: "WDC     WD10SPSX-08A6W  01.0" (underscores→spaces, SCSI\Disk prefix removed)
// Returns length of extracted model, or 0 if not a SCSI/NVMe HardwareID.
static int ExtractModelFromHardwareId(const char* hwid, int hwidLen, char* outModel, int outMax) {
	int skip = 0;
	// Strip known prefixes
	const char* prefixes[] = { "SCSI\\Disk", "SCSI\\NVMe", "SCSI\\", "NVMe\\", "IDE\\Disk" };
	const int prefixLens[] = { 9, 9, 5, 5, 8 };
	for (int p = 0; p < 5; p++) {
		if (hwidLen > prefixLens[p] && !memcmp(hwid, prefixes[p], prefixLens[p])) {
			skip = prefixLens[p];
			break;
		}
	}
	if (skip == 0) return 0; // Not a hardware ID we recognize

	int modelLen = hwidLen - skip;
	if (modelLen <= 0 || modelLen >= outMax) return 0;

	// Copy and convert underscores to spaces
	for (int i = 0; i < modelLen; i++) {
		outModel[i] = (hwid[skip + i] == '_') ? ' ' : hwid[skip + i];
	}
	outModel[modelLen] = '\0';

	// Trim trailing spaces
	while (modelLen > 0 && outModel[modelLen - 1] == ' ') modelLen--;
	return modelLen;
}

// Reconstruct a HardwareID with spoofed model.
// Takes the original prefix and the spoofed model, outputs the reconstructed string.
static int ReconstructHardwareId(const char* origHwid, int origLen,
	const char* spoofedModel, int spoofedLen,
	char* outBuf, int outMax) {
	// Find prefix length
	int prefixLen = 0;
	const char* prefixes[] = { "SCSI\\Disk", "SCSI\\NVMe", "SCSI\\", "NVMe\\", "IDE\\Disk" };
	const int prefixLens[] = { 9, 9, 5, 5, 8 };
	for (int p = 0; p < 5; p++) {
		if (origLen > prefixLens[p] && !memcmp(origHwid, prefixes[p], prefixLens[p])) {
			prefixLen = prefixLens[p];
			break;
		}
	}

	int totalLen = prefixLen + spoofedLen;
	if (totalLen >= outMax) totalLen = outMax - 1;

	// Copy prefix
	RtlCopyMemory(outBuf, origHwid, prefixLen);
	// Copy spoofed model with spaces→underscores
	int copyModel = totalLen - prefixLen;
	for (int i = 0; i < copyModel && i < spoofedLen; i++) {
		outBuf[prefixLen + i] = (spoofedModel[i] == ' ') ? '_' : spoofedModel[i];
	}
	// Pad rest of original length with underscores if spoofed is shorter
	for (int i = totalLen; i < origLen && i < outMax - 1; i++) {
		outBuf[i] = '_';
	}

	return origLen < outMax ? origLen : outMax - 1;
}

// Spoof a REG_MULTI_SZ value by processing each string for model/serial matches
static void SpoofRegMultiSz(HANDLE hKey, const wchar_t* valueName) {
	auto* pInfo = RegReadVal(hKey, valueName);
	if (!pInfo || pInfo->Type != REG_MULTI_SZ) { if (pInfo) ExFreePoolWithTag(pInfo, 'RegR'); return; }

	wchar_t* wData = (wchar_t*)pInfo->Data;
	int totalBytes = (int)pInfo->DataLength;
	int totalChars = totalBytes / (int)sizeof(wchar_t);
	bool changed = false;

	int pos = 0;
	while (pos < totalChars) {
		int strLen = 0;
		while (pos + strLen < totalChars && wData[pos + strLen] != L'\0') strLen++;
		if (strLen == 0) break;

		char charBuf[512] = { 0 };
		int cLen = strLen < 511 ? strLen : 511;
		for (int i = 0; i < cLen; i++)
			charBuf[i] = (char)(wData[pos + i] & 0x7F);

		// Try to parse as a HardwareID (SCSI\Disk..., NVMe\..., etc.)
		char extractedModel[128] = { 0 };
		int extractedLen = ExtractModelFromHardwareId(charBuf, cLen, extractedModel, 128);

		if (extractedLen > 3) {
			// Use the extracted model for cache lookup (consistent with IOCTL paths)
			char modelBuf[41] = { 0 };
			int mLen = extractedLen < 40 ? extractedLen : 40;
			RtlCopyMemory(modelBuf, extractedModel, mLen);
			if (FindFakeDiskModel(modelBuf, mLen)) {
				// Reconstruct the HardwareID with the spoofed model
				int spoofTrim = 40;
				while (spoofTrim > 0 && (modelBuf[spoofTrim - 1] == ' ' || modelBuf[spoofTrim - 1] == '\0')) spoofTrim--;
				char rebuilt[512] = { 0 };
				int rebuiltLen = ReconstructHardwareId(charBuf, cLen, modelBuf, spoofTrim, rebuilt, 511);
				for (int i = 0; i < rebuiltLen && (pos + i) < totalChars; i++)
					wData[pos + i] = (wchar_t)rebuilt[i];
				changed = true;
			}
		} else if (cLen <= 40 && cLen > 3) {
			// Short string (e.g., "GenDisk", "SCSI\\RAW") — try direct model spoof
			char modelBuf[41] = { 0 };
			int mLen = cLen;
			RtlCopyMemory(modelBuf, charBuf, mLen);
			if (FindFakeDiskModel(modelBuf, mLen)) {
				for (int i = 0; i < mLen; i++)
					wData[pos + i] = (wchar_t)modelBuf[i];
				changed = true;
			}
		}

		pos += strLen + 1;
	}

	if (changed) {
		RegWriteVal(hKey, valueName, REG_MULTI_SZ, pInfo->Data, (ULONG)totalBytes);
		DbgPrintEx(0, 0, "[SPOOF] Registry %ws (multi-sz) spoofed\n", valueName);
	}
	ExFreePoolWithTag(pInfo, 'RegR');
}

// Extract the real product model from an Enum\SCSI class key name.
// The key name is PnP-set at device enumeration and is NEVER modified by our
// registry spoofing, so it always contains the original vendor/product.
// Input:  L"Disk&Ven_NVMe&Prod_KINGSTON_SNV2S100" or L"Disk&Ven_WDC_____&Prod_WD10SPSX-08A6W"
// Output: product portion with underscores->spaces, trailing spaces trimmed
// Returns length of extracted model, or 0 if not parseable.
static int ExtractModelFromEnumKeyName(const wchar_t* keyName, int keyNameChars, char* outModel, int outMax) {
	char name[256] = { 0 };
	int nameLen = keyNameChars < 255 ? keyNameChars : 255;
	for (int i = 0; i < nameLen; i++)
		name[i] = (char)(keyName[i] & 0x7F);

	// Find &Prod_ marker
	char* prodStart = nullptr;
	for (int i = 0; i + 6 <= nameLen; i++) {
		if (name[i] == '&' && name[i + 1] == 'P' && name[i + 2] == 'r' &&
			name[i + 3] == 'o' && name[i + 4] == 'd' && name[i + 5] == '_') {
			prodStart = name + i + 6;
			break;
		}
	}
	if (!prodStart) return 0;

	// Find end of product (next & or end of string)
	int prodLen = 0;
	while (prodStart + prodLen < name + nameLen && prodStart[prodLen] != '&')
		prodLen++;

	// Copy with underscores -> spaces
	int pos = 0;
	for (int i = 0; i < prodLen && pos < outMax - 1; i++)
		outModel[pos++] = (prodStart[i] == '_') ? ' ' : prodStart[i];

	// Trim trailing spaces
	while (pos > 0 && outModel[pos - 1] == ' ') pos--;
	outModel[pos] = '\0';
	return pos;
}

// Write spoofed model to FriendlyName, preserving the bus type suffix
static void WriteSpoofedFriendlyName(HANDLE hKey, const char* spoofedModel, int spoofedLen) {
	auto* pInfo = RegReadVal(hKey, L"FriendlyName");
	if (!pInfo) return;
	if (pInfo->Type != REG_SZ) { ExFreePoolWithTag(pInfo, 'RegR'); return; }

	wchar_t* wData = (wchar_t*)pInfo->Data;
	int wLen = (int)(pInfo->DataLength / sizeof(wchar_t));
	if (wLen > 0 && wData[wLen - 1] == L'\0') wLen--;

	// Convert to ASCII to find suffix
	char charBuf[256] = { 0 };
	int charLen = wLen < 255 ? wLen : 255;
	for (int i = 0; i < charLen; i++)
		charBuf[i] = (char)(wData[i] & 0x7F);

	// Find bus type suffix to preserve
	const char* suffixStr = "";
	const char* suffixes[] = { " SCSI Disk Device", " NVMe Disk Device", " Disk Device", " SCSI Disk", " NVMe Disk" };
	for (int s = 0; s < 5; s++) {
		int slen = (int)strlen(suffixes[s]);
		if (charLen > slen && !memcmp(charBuf + charLen - slen, suffixes[s], slen)) {
			suffixStr = suffixes[s];
			break;
		}
	}

	// Build new FriendlyName: spoofed model + suffix
	wchar_t newVal[256] = { 0 };
	int pos = 0;
	for (int i = 0; i < spoofedLen && pos < 254; i++)
		newVal[pos++] = (wchar_t)spoofedModel[i];
	for (int i = 0; suffixStr[i] && pos < 254; i++)
		newVal[pos++] = (wchar_t)suffixStr[i];
	newVal[pos] = L'\0';

	RegWriteVal(hKey, L"FriendlyName", REG_SZ, newVal, (ULONG)((pos + 1) * sizeof(wchar_t)));
	DbgPrintEx(0, 0, "[SPOOF] Registry FriendlyName: <%.*s> -> <%.*s%s>\n",
		charLen, charBuf, spoofedLen, spoofedModel, suffixStr);
	ExFreePoolWithTag(pInfo, 'RegR');
}

// Rebuild a REG_MULTI_SZ HardwareID/CompatibleIDs using one consistent spoofed model
// instead of per-entry FindFakeDiskModel (which could generate different models per entry)
static void RebuildHardwareIdsWithModel(HANDLE hKey, const wchar_t* valueName,
	const char* spoofedModel, int spoofedLen) {
	auto* pInfo = RegReadVal(hKey, valueName);
	if (!pInfo || pInfo->Type != REG_MULTI_SZ) { if (pInfo) ExFreePoolWithTag(pInfo, 'RegR'); return; }

	wchar_t* wData = (wchar_t*)pInfo->Data;
	int totalBytes = (int)pInfo->DataLength;
	int totalChars = totalBytes / (int)sizeof(wchar_t);
	bool changed = false;

	int pos = 0;
	while (pos < totalChars) {
		int strLen = 0;
		while (pos + strLen < totalChars && wData[pos + strLen] != L'\0') strLen++;
		if (strLen == 0) break;

		char charBuf[512] = { 0 };
		int cLen = strLen < 511 ? strLen : 511;
		for (int i = 0; i < cLen; i++)
			charBuf[i] = (char)(wData[pos + i] & 0x7F);

		// Check if this is a SCSI/NVMe hardware ID with extractable model
		char extractedModel[128] = { 0 };
		int extractedLen = ExtractModelFromHardwareId(charBuf, cLen, extractedModel, 128);

		if (extractedLen > 8) {
			// Reconstruct with the SAME spoofed model (consistent across all entries)
			// Minimum 8 chars to skip generic entries like "Disk" (4), "RAW" (3), etc.
			char rebuilt[512] = { 0 };
			int rebuiltLen = ReconstructHardwareId(charBuf, cLen, spoofedModel, spoofedLen, rebuilt, 511);
			for (int i = 0; i < rebuiltLen && (pos + i) < totalChars; i++)
				wData[pos + i] = (wchar_t)rebuilt[i];
			changed = true;
		}

		pos += strLen + 1;
	}

	if (changed) {
		RegWriteVal(hKey, valueName, REG_MULTI_SZ, pInfo->Data, (ULONG)totalBytes);
		DbgPrintEx(0, 0, "[SPOOF] Registry %ws (multi-sz) rebuilt with consistent model\n", valueName);
	}
	ExFreePoolWithTag(pInfo, 'RegR');
}

// Spoof Enum\SCSI\Disk* FriendlyName and HardwareID
// Uses the REAL model from the class key NAME (PnP-set, never spoofed by us)
// instead of reading the FriendlyName VALUE (which may be stale-spoofed from
// a previous session). This ensures model consistency across all query methods.
static void SpoofScsiEnumRegistry() {
	UNICODE_STRING basePath = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Enum\\SCSI");
	OBJECT_ATTRIBUTES oa;
	HANDLE hBase;

	InitializeObjectAttributes(&oa, &basePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	if (!NT_SUCCESS(ZwOpenKey(&hBase, KEY_READ, &oa))) return;

	ULONG idx = 0;
	BYTE keyInfoBuf[512];
	while (true) {
		ULONG resultLen;
		NTSTATUS st = ZwEnumerateKey(hBase, idx++, KeyBasicInformation, keyInfoBuf, sizeof(keyInfoBuf), &resultLen);
		if (st == STATUS_NO_MORE_ENTRIES) break;
		if (!NT_SUCCESS(st)) continue;

		PKEY_BASIC_INFORMATION keyInfo = (PKEY_BASIC_INFORMATION)keyInfoBuf;
		// Only process Disk* subkeys
		if (keyInfo->NameLength < 8 || _wcsnicmp(keyInfo->Name, L"Disk", 4) != 0)
			continue;

		// Extract REAL model from class key name (e.g., "Disk&Ven_NVMe&Prod_KINGSTON_SNV2S100")
		// The key name is set by PnP enumeration and is never modified by our spoofing.
		char realModel[41] = { 0 };
		int realModelLen = ExtractModelFromEnumKeyName(
			keyInfo->Name, (int)(keyInfo->NameLength / sizeof(wchar_t)), realModel, 40);

		// Get spoofed model via FindFakeDiskModel (populates cache with real->spoofed mapping)
		char spoofedModel[41] = { 0 };
		int spoofedModelLen = 0;
		bool hasSpoofedModel = false;
		if (realModelLen > 3) {
			RtlCopyMemory(spoofedModel, realModel, realModelLen);
			// Pad with spaces to 40 so FindFakeDiskModel writes back the FULL spoofed
			// model (not truncated to the key name's SCSI product field length)
			for (int i = realModelLen; i < 40; i++) spoofedModel[i] = ' ';
			hasSpoofedModel = FindFakeDiskModel(spoofedModel, 40);
			if (hasSpoofedModel) {
				spoofedModelLen = 40;
				while (spoofedModelLen > 0 && (spoofedModel[spoofedModelLen - 1] == ' ' ||
					spoofedModel[spoofedModelLen - 1] == '\0'))
					spoofedModelLen--;
			}
			DbgPrintEx(0, 0, "[SPOOF] Enum\\SCSI key: <%.*s> -> <%.*s>\n",
				realModelLen, realModel, spoofedModelLen, spoofedModel);
		}

		// Open the disk class key
		UNICODE_STRING subName;
		subName.Length = (USHORT)keyInfo->NameLength;
		subName.MaximumLength = (USHORT)keyInfo->NameLength;
		subName.Buffer = keyInfo->Name;

		HANDLE hClass;
		InitializeObjectAttributes(&oa, &subName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hBase, NULL);
		if (!NT_SUCCESS(ZwOpenKey(&hClass, KEY_READ, &oa))) continue;

		// Enumerate instances under this disk class
		ULONG instIdx = 0;
		BYTE instBuf[512];
		while (true) {
			st = ZwEnumerateKey(hClass, instIdx++, KeyBasicInformation, instBuf, sizeof(instBuf), &resultLen);
			if (st == STATUS_NO_MORE_ENTRIES) break;
			if (!NT_SUCCESS(st)) continue;

			PKEY_BASIC_INFORMATION instInfo = (PKEY_BASIC_INFORMATION)instBuf;
			UNICODE_STRING instName;
			instName.Length = (USHORT)instInfo->NameLength;
			instName.MaximumLength = (USHORT)instInfo->NameLength;
			instName.Buffer = instInfo->Name;

			HANDLE hInst;
			InitializeObjectAttributes(&oa, &instName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hClass, NULL);
			if (!NT_SUCCESS(ZwOpenKey(&hInst, KEY_ALL_ACCESS, &oa))) continue;

			if (hasSpoofedModel) {
				// Write spoofed model to FriendlyName (preserves bus suffix)
				WriteSpoofedFriendlyName(hInst, spoofedModel, spoofedModelLen);
				// Rebuild HardwareID with the SAME spoofed model
				// NOTE: CompatibleIDs are NOT spoofed — they contain generic class IDs
				// like "SCSI\Disk", "GenDisk" which should not be modified
				RebuildHardwareIdsWithModel(hInst, L"HardwareID", spoofedModel, spoofedModelLen);
			}
			ZwClose(hInst);
		}
		ZwClose(hClass);
	}
	ZwClose(hBase);
	DbgPrintEx(0, 0, "[SPOOF] Registry: Enum\\SCSI enumeration complete\n");
}

// Spoof HARDWARE\DEVICEMAP\Scsi hierarchy (SerialNumber, Identifier)
static void SpoofDeviceMapRegistry() {
	UNICODE_STRING basePath = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\HARDWARE\\DEVICEMAP\\Scsi");
	OBJECT_ATTRIBUTES oa;
	HANDLE hBase;
	InitializeObjectAttributes(&oa, &basePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	if (!NT_SUCCESS(ZwOpenKey(&hBase, KEY_READ, &oa))) return;

	// Walk Port -> Bus -> Target -> LUN
	BYTE buf[512];
	ULONG portIdx = 0;
	while (true) {
		ULONG resultLen;
		if (ZwEnumerateKey(hBase, portIdx++, KeyBasicInformation, buf, sizeof(buf), &resultLen) != STATUS_SUCCESS) break;
		PKEY_BASIC_INFORMATION pi = (PKEY_BASIC_INFORMATION)buf;
		UNICODE_STRING portName = { (USHORT)pi->NameLength, (USHORT)pi->NameLength, pi->Name };
		HANDLE hPort;
		InitializeObjectAttributes(&oa, &portName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hBase, NULL);
		if (!NT_SUCCESS(ZwOpenKey(&hPort, KEY_READ, &oa))) continue;

		ULONG busIdx = 0;
		while (true) {
			if (ZwEnumerateKey(hPort, busIdx++, KeyBasicInformation, buf, sizeof(buf), &resultLen) != STATUS_SUCCESS) break;
			pi = (PKEY_BASIC_INFORMATION)buf;
			UNICODE_STRING busName = { (USHORT)pi->NameLength, (USHORT)pi->NameLength, pi->Name };
			HANDLE hBus;
			InitializeObjectAttributes(&oa, &busName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hPort, NULL);
			if (!NT_SUCCESS(ZwOpenKey(&hBus, KEY_READ, &oa))) continue;

			ULONG tgtIdx = 0;
			while (true) {
				if (ZwEnumerateKey(hBus, tgtIdx++, KeyBasicInformation, buf, sizeof(buf), &resultLen) != STATUS_SUCCESS) break;
				pi = (PKEY_BASIC_INFORMATION)buf;
				UNICODE_STRING tgtName = { (USHORT)pi->NameLength, (USHORT)pi->NameLength, pi->Name };
				HANDLE hTgt;
				InitializeObjectAttributes(&oa, &tgtName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hBus, NULL);
				if (!NT_SUCCESS(ZwOpenKey(&hTgt, KEY_READ, &oa))) continue;

				ULONG lunIdx = 0;
				while (true) {
					if (ZwEnumerateKey(hTgt, lunIdx++, KeyBasicInformation, buf, sizeof(buf), &resultLen) != STATUS_SUCCESS) break;
					pi = (PKEY_BASIC_INFORMATION)buf;
					UNICODE_STRING lunName = { (USHORT)pi->NameLength, (USHORT)pi->NameLength, pi->Name };
					HANDLE hLun;
					InitializeObjectAttributes(&oa, &lunName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hTgt, NULL);
					if (!NT_SUCCESS(ZwOpenKey(&hLun, KEY_ALL_ACCESS, &oa))) continue;

					SpoofRegSzSerial(hLun, L"SerialNumber");
					SpoofRegSzModel(hLun, L"Identifier");
					ZwClose(hLun);
				}
				ZwClose(hTgt);
			}
			ZwClose(hBus);
		}
		ZwClose(hPort);
	}
	ZwClose(hBase);
	DbgPrintEx(0, 0, "[SPOOF] Registry: DEVICEMAP\\Scsi enumeration complete\n");
}

// Spoof MountedDevices binary DMIO values
static void SpoofMountedDevicesRegistry() {
	UNICODE_STRING path = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\MountedDevices");
	OBJECT_ATTRIBUTES oa;
	HANDLE hKey;
	InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	if (!NT_SUCCESS(ZwOpenKey(&hKey, KEY_ALL_ACCESS, &oa))) return;

	BYTE valBuf[1024];
	ULONG valIdx = 0;
	while (true) {
		ULONG resultLen;
		NTSTATUS st = ZwEnumerateValueKey(hKey, valIdx++, KeyValueFullInformation, valBuf, sizeof(valBuf), &resultLen);
		if (st == STATUS_NO_MORE_ENTRIES) break;
		if (!NT_SUCCESS(st)) continue;

		PKEY_VALUE_FULL_INFORMATION vfi = (PKEY_VALUE_FULL_INFORMATION)valBuf;
		if (vfi->Type != REG_BINARY || vfi->DataLength < 24) continue;

		UCHAR* data = (UCHAR*)vfi + vfi->DataOffset;
		// Check for "DMIO:ID:" prefix (444D494F3A49443A)
		if (data[0] == 'D' && data[1] == 'M' && data[2] == 'I' && data[3] == 'O' &&
			data[4] == ':' && data[5] == 'I' && data[6] == 'D' && data[7] == ':') {
			// Spoof the 16-byte GUID at offset 8
			UCHAR origGuid[16];
			RtlCopyMemory(origGuid, data + 8, 16);
			UCHAR guidCopy[16];
			RtlCopyMemory(guidCopy, data + 8, 16);
			SpoofBinaryIdentifier(guidCopy, 16, kmdf_settings::hwid_seed ^ 0x444D494F);

			// Only write if changed
			if (memcmp(guidCopy, data + 8, 16) != 0) {
				RtlCopyMemory(data + 8, guidCopy, 16);
				UNICODE_STRING valName;
				valName.Length = (USHORT)vfi->NameLength;
				valName.MaximumLength = (USHORT)vfi->NameLength;
				valName.Buffer = vfi->Name;
				ZwSetValueKey(hKey, &valName, 0, REG_BINARY, data, vfi->DataLength);
				DbgPrintEx(0, 0, "[SPOOF] MountedDevices DMIO: <%02X%02X%02X%02X%02X%02X%02X%02X> -> <%02X%02X%02X%02X%02X%02X%02X%02X>\n",
					origGuid[0], origGuid[1], origGuid[2], origGuid[3], origGuid[4], origGuid[5], origGuid[6], origGuid[7],
					guidCopy[0], guidCopy[1], guidCopy[2], guidCopy[3], guidCopy[4], guidCopy[5], guidCopy[6], guidCopy[7]);
			}
		}
	}
	ZwClose(hKey);
}

// Master registry spoofing function
static void SpoofDiskRegistry() {
	DbgPrintEx(0, 0, "[SPOOF] === Registry spoofing start ===\n");
	SpoofScsiEnumRegistry();
	SpoofDeviceMapRegistry();
	SpoofMountedDevicesRegistry();
	DbgPrintEx(0, 0, "[SPOOF] === Registry spoofing complete ===\n");
}

// ============================================================================
// Comprehensive registry cleanup - removes forensic traces
// ============================================================================

static void DeleteRegistryKeySafe(const wchar_t* keyPath) {
	UNICODE_STRING uPath;
	RtlInitUnicodeString(&uPath, keyPath);
	HANDLE hKey;
	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	if (NT_SUCCESS(ZwOpenKey(&hKey, KEY_ALL_ACCESS, &oa))) {
		// Delete all values first
		ULONG idx = 0;
		BYTE valBuf[512];
		while (true) {
			ULONG resultLen;
			NTSTATUS st = ZwEnumerateValueKey(hKey, idx, KeyValueFullInformation, valBuf, sizeof(valBuf), &resultLen);
			if (st == STATUS_NO_MORE_ENTRIES) break;
			if (!NT_SUCCESS(st)) { idx++; continue; }
			PKEY_VALUE_FULL_INFORMATION vfi = (PKEY_VALUE_FULL_INFORMATION)valBuf;
			UNICODE_STRING valName;
			valName.Length = (USHORT)vfi->NameLength;
			valName.MaximumLength = (USHORT)vfi->NameLength;
			valName.Buffer = vfi->Name;
			ZwDeleteValueKey(hKey, &valName);
			// Don't increment idx since we deleted
		}
		ZwClose(hKey);
	}
	// Now delete the key itself
	kmdf_utils::DeleteRegistryKey(&uPath);
}

static void DeleteRegistryValue(const wchar_t* keyPath, const wchar_t* valueName) {
	UNICODE_STRING uPath, uValue;
	RtlInitUnicodeString(&uPath, keyPath);
	RtlInitUnicodeString(&uValue, valueName);
	HANDLE hKey;
	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	if (NT_SUCCESS(ZwOpenKey(&hKey, KEY_ALL_ACCESS, &oa))) {
		ZwDeleteValueKey(hKey, &uValue);
		ZwClose(hKey);
	}
}

static void SpoofMachineGuid() {
	UNICODE_STRING keyPath;
	RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Cryptography");
	HANDLE hKey;
	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	if (!NT_SUCCESS(ZwOpenKey(&hKey, KEY_ALL_ACCESS, &oa))) return;

	UNICODE_STRING valueName;
	RtlInitUnicodeString(&valueName, L"MachineGuid");

	// Read current value
	ULONG resultLen = 0;
	NTSTATUS st = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, NULL, 0, &resultLen);
	if (st != STATUS_BUFFER_TOO_SMALL || resultLen == 0) { ZwClose(hKey); return; }

	auto* pInfo = (KEY_VALUE_PARTIAL_INFORMATION*)ExAllocatePoolWithTag(NonPagedPool, resultLen, 'GuId');
	if (!pInfo) { ZwClose(hKey); return; }

	st = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, pInfo, resultLen, &resultLen);
	if (NT_SUCCESS(st) && pInfo->Type == REG_SZ && pInfo->DataLength >= 36) {
		wchar_t* guidStr = (wchar_t*)pInfo->Data;
		// Generate new GUID string: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
		ULONG seed = kmdf_settings::hwid_seed;
		static const wchar_t hexChars[] = L"0123456789abcdef";
		wchar_t newGuid[37] = { 0 };
		for (int i = 0; i < 36; i++) {
			if (i == 8 || i == 13 || i == 18 || i == 23) {
				newGuid[i] = L'-';
			} else {
				ULONG r = DiskLCG(seed);
				newGuid[i] = hexChars[r % 16];
			}
		}
		newGuid[36] = L'\0';

		DbgPrintEx(0, 0, "[SPOOF] MachineGuid: <%ws> -> <%ws>\n", guidStr, newGuid);
		ZwSetValueKey(hKey, &valueName, 0, REG_SZ, newGuid, 37 * sizeof(wchar_t));
	}
	ExFreePoolWithTag(pInfo, 'GuId');
	ZwClose(hKey);
}

static void SpoofMMDevicesAudio() {
	// Spoof MMDevices Audio Render properties
	UNICODE_STRING basePath;
	RtlInitUnicodeString(&basePath, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MMDevices\\Audio\\Render");
	HANDLE hBase;
	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, &basePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	if (!NT_SUCCESS(ZwOpenKey(&hBase, KEY_READ, &oa))) return;

	ULONG idx = 0;
	BYTE keyBuf[512];
	while (true) {
		ULONG resultLen;
		NTSTATUS st = ZwEnumerateKey(hBase, idx++, KeyBasicInformation, keyBuf, sizeof(keyBuf), &resultLen);
		if (st == STATUS_NO_MORE_ENTRIES) break;
		if (!NT_SUCCESS(st)) continue;

		PKEY_BASIC_INFORMATION keyInfo = (PKEY_BASIC_INFORMATION)keyBuf;
		UNICODE_STRING subName;
		subName.Length = (USHORT)keyInfo->NameLength;
		subName.MaximumLength = (USHORT)keyInfo->NameLength;
		subName.Buffer = keyInfo->Name;

		HANDLE hSub;
		InitializeObjectAttributes(&oa, &subName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hBase, NULL);
		if (!NT_SUCCESS(ZwOpenKey(&hSub, KEY_ALL_ACCESS, &oa))) continue;

		// Spoof Properties subkey
		UNICODE_STRING propsName;
		RtlInitUnicodeString(&propsName, L"Properties");
		HANDLE hProps;
		InitializeObjectAttributes(&oa, &propsName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hSub, NULL);
		if (NT_SUCCESS(ZwOpenKey(&hProps, KEY_ALL_ACCESS, &oa))) {
			// Delete device description and other identifying values
			DeleteRegistryValue(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\MMDevices\\Audio\\Render", L"DeviceState");
			ZwClose(hProps);
		}

		// Randomize the device GUID in the key name by modifying embedded data
		ULONG propIdx = 0;
		BYTE valBuf[1024];
		while (true) {
			ULONG valResultLen;
			NTSTATUS vst = ZwEnumerateValueKey(hSub, propIdx, KeyValueFullInformation, valBuf, sizeof(valBuf), &valResultLen);
			if (vst == STATUS_NO_MORE_ENTRIES) break;
			if (!NT_SUCCESS(vst)) { propIdx++; continue; }

			PKEY_VALUE_FULL_INFORMATION vfi = (PKEY_VALUE_FULL_INFORMATION)valBuf;
			if (vfi->Type == REG_BINARY && vfi->DataLength >= 16) {
				UCHAR* data = (UCHAR*)vfi + vfi->DataOffset;
				// Check if it contains a GUID-like structure
				ULONG seed = kmdf_settings::hwid_seed ^ HashSerialBytes((const char*)data, 16);
				for (ULONG b = 0; b < vfi->DataLength && b < 64; b++) {
					if (data[b] != 0) {
						ULONG r = DiskLCG(seed);
						data[b] = (UCHAR)(r & 0xFF);
					}
				}
				UNICODE_STRING valName;
				valName.Length = (USHORT)vfi->NameLength;
				valName.MaximumLength = (USHORT)vfi->NameLength;
				valName.Buffer = vfi->Name;
				ZwSetValueKey(hSub, &valName, 0, vfi->Type, data, vfi->DataLength);
			}
			propIdx++;
		}
		ZwClose(hSub);
	}
	ZwClose(hBase);
	DbgPrintEx(0, 0, "[SPOOF] MMDevices Audio Render spoofed\n");
}

static void CleanHostsFile() {
	// Clear the hosts file to remove any custom entries
	const wchar_t* hostsPath = L"\\??\\C:\\Windows\\System32\\drivers\\etc\\hosts";
	UNICODE_STRING uPath;
	RtlInitUnicodeString(&uPath, hostsPath);

	OBJECT_ATTRIBUTES oa;
	IO_STATUS_BLOCK iosb;
	HANDLE hFile;

	InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	NTSTATUS st = ZwCreateFile(&hFile, FILE_GENERIC_WRITE, &oa, &iosb, NULL,
		FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OVERWRITE_IF,
		FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if (NT_SUCCESS(st)) {
		// Write default hosts content
		const char* defaultHosts = "# Copyright (c) 1993-2009 Microsoft Corp.\r\n#\r\n# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.\r\n#\r\n# localhost name resolution is handled within DNS itself.\r\n#\t127.0.0.1       localhost\r\n#\t::1             localhost\r\n";
		ULONG written = 0;
		ZwWriteFile(hFile, NULL, NULL, NULL, &iosb, (PVOID)defaultHosts, (ULONG)strlen(defaultHosts), NULL, NULL);
		ZwClose(hFile);
		DbgPrintEx(0, 0, "[SPOOF] Hosts file cleared\n");
	}
}

static void CleanForensicTraces() {
	DbgPrintEx(0, 0, "[SPOOF] === Forensic trace cleanup start (SPOOF mode) ===\n");

	// Clear hosts file
	CleanHostsFile();

	// MSLicensing (safe to delete - will be recreated)
	DeleteRegistryKeySafe(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\MSLicensing\\HardwareID");
	DeleteRegistryKeySafe(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\MSLicensing\\Store");

	// WinRAR history (safe to delete)
	DeleteRegistryKeySafe(L"\\Registry\\User\\Software\\WinRAR\\ArcHistory");

	// BAM - spoof values instead of deleting
	{
		UNICODE_STRING bamBase;
		RtlInitUnicodeString(&bamBase, L"\\Registry\\Machine\\SYSTEM\\ControlSet001\\Services\\bam\\State\\UserSettings");
		HANDLE hBam;
		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(&oa, &bamBase, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		if (NT_SUCCESS(ZwOpenKey(&hBam, KEY_READ, &oa))) {
			ULONG idx = 0;
			BYTE keyBuf[512];
			while (true) {
				ULONG resultLen;
				NTSTATUS st = ZwEnumerateKey(hBam, idx++, KeyBasicInformation, keyBuf, sizeof(keyBuf), &resultLen);
				if (st == STATUS_NO_MORE_ENTRIES) break;
				if (!NT_SUCCESS(st)) continue;

				PKEY_BASIC_INFORMATION keyInfo = (PKEY_BASIC_INFORMATION)keyBuf;
				wchar_t fullPath[512];
				RtlStringCchPrintfW(fullPath, 512, L"\\Registry\\Machine\\SYSTEM\\ControlSet001\\Services\\bam\\State\\UserSettings\\%.*ws",
					keyInfo->NameLength / sizeof(wchar_t), keyInfo->Name);

				UNICODE_STRING uFullPath;
				RtlInitUnicodeString(&uFullPath, fullPath);
				HANDLE hSid;
				InitializeObjectAttributes(&oa, &uFullPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
				if (NT_SUCCESS(ZwOpenKey(&hSid, KEY_ALL_ACCESS, &oa))) {
					// Spoof all values instead of deleting
					ULONG valIdx = 0;
					while (true) {
						ULONG valResultLen;
						NTSTATUS vst = ZwEnumerateValueKey(hSid, valIdx, KeyValueBasicInformation, keyBuf, sizeof(keyBuf), &valResultLen);
						if (vst == STATUS_NO_MORE_ENTRIES) break;
						if (!NT_SUCCESS(vst)) { valIdx++; continue; }
						PKEY_VALUE_BASIC_INFORMATION vbi = (PKEY_VALUE_BASIC_INFORMATION)keyBuf;
						
						// Read and spoof the value
						UNICODE_STRING valName;
						valName.Length = (USHORT)vbi->NameLength;
						valName.MaximumLength = (USHORT)vbi->NameLength;
						valName.Buffer = vbi->Name;
						
						ULONG dataLen = 0;
						NTSTATUS vst2 = ZwQueryValueKey(hSid, &valName, KeyValuePartialInformation, NULL, 0, &dataLen);
						if (vst2 == STATUS_BUFFER_TOO_SMALL && dataLen > 0) {
							PKEY_VALUE_PARTIAL_INFORMATION pvpi = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolWithTag(PagedPool, dataLen, 'naLC');
							if (pvpi) {
								vst2 = ZwQueryValueKey(hSid, &valName, KeyValuePartialInformation, pvpi, dataLen, &dataLen);
								if (NT_SUCCESS(vst2) && pvpi->DataLength >= 4) {
									// Randomize the data
									ULONG seed = kmdf_settings::hwid_seed;
									UCHAR* data = (UCHAR*)pvpi->Data;
									for (ULONG d = 0; d < pvpi->DataLength; d++) {
										if (data[d] != 0) {
											ULONG r = DiskLCG(seed);
											data[d] = (UCHAR)(r & 0xFF);
										}
									}
									ZwSetValueKey(hSid, &valName, 0, pvpi->Type, pvpi->Data, pvpi->DataLength);
								}
								ExFreePoolWithTag(pvpi, 'naLC');
							}
						}
						valIdx++;
					}
					ZwClose(hSid);
				}
			}
			ZwClose(hBam);
		}
	}

	// FeatureUsage - spoof
	{
		UNICODE_STRING fuPath;
		RtlInitUnicodeString(&fuPath, L"\\Registry\\User\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage");
		HANDLE hFu;
		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(&oa, &fuPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		if (NT_SUCCESS(ZwOpenKey(&hFu, KEY_ALL_ACCESS, &oa))) {
			// Spoof ShowJumpView and AppSwitched subkeys
			const wchar_t* subKeys[] = { L"ShowJumpView", L"AppSwitched" };
			for (int s = 0; s < 2; s++) {
				UNICODE_STRING subName;
				RtlInitUnicodeString(&subName, subKeys[s]);
				HANDLE hSub;
				InitializeObjectAttributes(&oa, &subName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, hFu, NULL);
				if (NT_SUCCESS(ZwOpenKey(&hSub, KEY_ALL_ACCESS, &oa))) {
					ULONG valIdx = 0;
					BYTE valBuf[512];
					while (true) {
						ULONG resultLen;
						NTSTATUS vst = ZwEnumerateValueKey(hSub, valIdx, KeyValueFullInformation, valBuf, sizeof(valBuf), &resultLen);
						if (vst == STATUS_NO_MORE_ENTRIES) break;
						if (!NT_SUCCESS(vst)) { valIdx++; continue; }
						PKEY_VALUE_FULL_INFORMATION vfi = (PKEY_VALUE_FULL_INFORMATION)valBuf;
						if (vfi->Type == REG_DWORD && vfi->DataLength >= 4) {
							ULONG* val = (ULONG*)((UCHAR*)vfi + vfi->DataOffset);
							ULONG seed = kmdf_settings::hwid_seed ^ *val;
							*val = DiskLCG(seed);
							UNICODE_STRING vn;
							vn.Length = (USHORT)vfi->NameLength;
							vn.MaximumLength = (USHORT)vfi->NameLength;
							vn.Buffer = vfi->Name;
							ZwSetValueKey(hSub, &vn, 0, REG_DWORD, val, sizeof(ULONG));
						}
						valIdx++;
					}
					ZwClose(hSub);
				}
			}
			ZwClose(hFu);
		}
	}

	// MUI Cache - spoof
	{
		UNICODE_STRING muiPath;
		RtlInitUnicodeString(&muiPath, L"\\Registry\\User\\Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache");
		HANDLE hMui;
		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(&oa, &muiPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		if (NT_SUCCESS(ZwOpenKey(&hMui, KEY_ALL_ACCESS, &oa))) {
			ULONG valIdx = 0;
			BYTE valBuf[1024];
			while (true) {
				ULONG resultLen;
				NTSTATUS vst = ZwEnumerateValueKey(hMui, valIdx, KeyValueFullInformation, valBuf, sizeof(valBuf), &resultLen);
				if (vst == STATUS_NO_MORE_ENTRIES) break;
				if (!NT_SUCCESS(vst)) { valIdx++; continue; }
				PKEY_VALUE_FULL_INFORMATION vfi = (PKEY_VALUE_FULL_INFORMATION)valBuf;
				if (vfi->Type == REG_SZ && vfi->DataLength >= 4) {
					wchar_t* data = (wchar_t*)((UCHAR*)vfi + vfi->DataOffset);
					ULONG len = vfi->DataLength / sizeof(wchar_t);
					ULONG seed = kmdf_settings::hwid_seed;
					for (ULONG i = 0; i < len && data[i]; i++) {
						if (data[i] >= L'0' && data[i] <= L'9') {
							ULONG r = DiskLCG(seed);
							data[i] = L'0' + (r % 10);
						} else if (data[i] >= L'A' && data[i] <= L'Z') {
							ULONG r = DiskLCG(seed);
							data[i] = L'A' + (r % 26);
						} else if (data[i] >= L'a' && data[i] <= L'z') {
							ULONG r = DiskLCG(seed);
							data[i] = L'a' + (r % 26);
						}
					}
					UNICODE_STRING vn;
					vn.Length = (USHORT)vfi->NameLength;
					vn.MaximumLength = (USHORT)vfi->NameLength;
					vn.Buffer = vfi->Name;
					ZwSetValueKey(hMui, &vn, 0, REG_SZ, data, vfi->DataLength);
				}
				valIdx++;
			}
			ZwClose(hMui);
		}
	}

	// AppCompatFlags - spoof
	{
		UNICODE_STRING acPath;
		RtlInitUnicodeString(&acPath, L"\\Registry\\User\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store");
		HANDLE hAc;
		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(&oa, &acPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		if (NT_SUCCESS(ZwOpenKey(&hAc, KEY_ALL_ACCESS, &oa))) {
			ULONG valIdx = 0;
			BYTE valBuf[1024];
			while (true) {
				ULONG resultLen;
				NTSTATUS vst = ZwEnumerateValueKey(hAc, valIdx, KeyValueFullInformation, valBuf, sizeof(valBuf), &resultLen);
				if (vst == STATUS_NO_MORE_ENTRIES) break;
				if (!NT_SUCCESS(vst)) { valIdx++; continue; }
				PKEY_VALUE_FULL_INFORMATION vfi = (PKEY_VALUE_FULL_INFORMATION)valBuf;
				if (vfi->Type == REG_BINARY && vfi->DataLength >= 4) {
					UCHAR* data = (UCHAR*)vfi + vfi->DataOffset;
					ULONG seed = kmdf_settings::hwid_seed;
					for (ULONG i = 0; i < vfi->DataLength; i++) {
						if (data[i] != 0) {
							ULONG r = DiskLCG(seed);
							data[i] = (UCHAR)(r & 0xFF);
						}
					}
					UNICODE_STRING vn;
					vn.Length = (USHORT)vfi->NameLength;
					vn.MaximumLength = (USHORT)vfi->NameLength;
					vn.Buffer = vfi->Name;
					ZwSetValueKey(hAc, &vn, 0, REG_BINARY, data, vfi->DataLength);
				}
				valIdx++;
			}
			ZwClose(hAc);
		}
	}

	// IE Audio - spoof
	{
		UNICODE_STRING iePath;
		RtlInitUnicodeString(&iePath, L"\\Registry\\User\\Software\\Microsoft\\Internet Explorer\\LowRegistry\\Audio\\PolicyConfig\\PropertyStore");
		HANDLE hIe;
		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(&oa, &iePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		if (NT_SUCCESS(ZwOpenKey(&hIe, KEY_ALL_ACCESS, &oa))) {
			ULONG valIdx = 0;
			BYTE valBuf[1024];
			while (true) {
				ULONG resultLen;
				NTSTATUS vst = ZwEnumerateValueKey(hIe, valIdx, KeyValueFullInformation, valBuf, sizeof(valBuf), &resultLen);
				if (vst == STATUS_NO_MORE_ENTRIES) break;
				if (!NT_SUCCESS(vst)) { valIdx++; continue; }
				PKEY_VALUE_FULL_INFORMATION vfi = (PKEY_VALUE_FULL_INFORMATION)valBuf;
				if (vfi->DataLength >= 4) {
					UCHAR* data = (UCHAR*)vfi + vfi->DataOffset;
					ULONG seed = kmdf_settings::hwid_seed;
					for (ULONG i = 0; i < vfi->DataLength; i++) {
						if (data[i] != 0) {
							ULONG r = DiskLCG(seed);
							data[i] = (UCHAR)(r & 0xFF);
						}
					}
					UNICODE_STRING vn;
					vn.Length = (USHORT)vfi->NameLength;
					vn.MaximumLength = (USHORT)vfi->NameLength;
					vn.Buffer = vfi->Name;
					ZwSetValueKey(hIe, &vn, 0, vfi->Type, data, vfi->DataLength);
				}
				valIdx++;
			}
			ZwClose(hIe);
		}
	}

	// IFEO - delete only specific VMP entries (safe)
	DeleteRegistryKeySafe(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\VMP.exe");
	DeleteRegistryKeySafe(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\VMP_b3095_GameProcess.exe");
	DeleteRegistryKeySafe(L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\VMP_ChromeBrowser.exe");

	// MachineGuid (spoof)
	SpoofMachineGuid();

	// MMDevices Audio (spoof)
	SpoofMMDevicesAudio();

	// Recent/UserAssist/TypedPaths/TypedURLs/RunMRU - spoof
	const wchar_t* userKeys[] = {
		L"\\Registry\\User\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
		L"\\Registry\\User\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist",
		L"\\Registry\\User\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths",
		L"\\Registry\\User\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedURLs",
		L"\\Registry\\User\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU",
	};
	for (int i = 0; i < sizeof(userKeys) / sizeof(userKeys[0]); i++) {
		UNICODE_STRING uPath;
		RtlInitUnicodeString(&uPath, userKeys[i]);
		HANDLE hKey;
		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(&oa, &uPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		if (NT_SUCCESS(ZwOpenKey(&hKey, KEY_ALL_ACCESS, &oa))) {
			ULONG valIdx = 0;
			BYTE valBuf[1024];
			while (true) {
				ULONG resultLen;
				NTSTATUS vst = ZwEnumerateValueKey(hKey, valIdx, KeyValueFullInformation, valBuf, sizeof(valBuf), &resultLen);
				if (vst == STATUS_NO_MORE_ENTRIES) break;
				if (!NT_SUCCESS(vst)) { valIdx++; continue; }
				PKEY_VALUE_FULL_INFORMATION vfi = (PKEY_VALUE_FULL_INFORMATION)valBuf;
				if (vfi->DataLength >= 4) {
					UCHAR* data = (UCHAR*)vfi + vfi->DataOffset;
					ULONG seed = kmdf_settings::hwid_seed;
					for (ULONG d = 0; d < vfi->DataLength; d++) {
						if (data[d] != 0) {
							ULONG r = DiskLCG(seed);
							data[d] = (UCHAR)(r & 0xFF);
						}
					}
					UNICODE_STRING vn;
					vn.Length = (USHORT)vfi->NameLength;
					vn.MaximumLength = (USHORT)vfi->NameLength;
					vn.Buffer = vfi->Name;
					ZwSetValueKey(hKey, &vn, 0, vfi->Type, data, vfi->DataLength);
				}
				valIdx++;
			}
			ZwClose(hKey);
		}
	}

	DbgPrintEx(0, 0, "[SPOOF] === Forensic trace cleanup complete (SPOOF mode) ===\n");
}
		}
	}

	// Replace model names
	for (int i = 0; i < g_modelCount; i++) {
		ModelCacheEntry* e = &g_modelCache[i];
		int trimLen = e->len;
		while (trimLen > 0 && (e->orig[trimLen - 1] == ' ' || e->orig[trimLen - 1] == '\0')) trimLen--;
		if (trimLen < 3) continue;

		for (int pos = 0; pos + trimLen <= bufLen; pos++) {
			if (!memcmp(buf + pos, e->orig, trimLen)) {
				int spoofTrim = e->len;
				while (spoofTrim > 0 && (e->spoofed[spoofTrim - 1] == ' ' || e->spoofed[spoofTrim - 1] == '\0')) spoofTrim--;
				int copyLen = spoofTrim < trimLen ? spoofTrim : trimLen;
				RtlCopyMemory(buf + pos, e->spoofed, copyLen);
				// Pad rest with spaces if spoofed is shorter
				for (int k = copyLen; k < trimLen; k++) buf[pos + k] = ' ';
				changed = true;
			}
		}
	}
	return changed;
}

// Scan a memory region for WCHAR versions of known serials/models and replace
static bool SpoofBufferContentWchar(char* buf, int bufLen) {
	if (!buf || bufLen < 6) return false;
	bool changed = false;

	// WCHAR serial replacement
	for (int i = 0; i < g_serialCount; i++) {
		SerialCacheEntry* e = &g_serialCache[i];
		int trimStart = 0;
		while (trimStart < e->sz && (e->orig[trimStart] == ' ' || e->orig[trimStart] == '\0')) trimStart++;
		int trimEnd = e->sz;
		while (trimEnd > trimStart && (e->orig[trimEnd - 1] == ' ' || e->orig[trimEnd - 1] == '\0')) trimEnd--;
		int trimLen = trimEnd - trimStart;
		if (trimLen < 3) continue;

		int wideBytes = trimLen * 2;
		if (wideBytes > bufLen) continue;

		for (int pos = 0; pos + wideBytes <= bufLen; pos += 2) {
			bool match = true;
			for (int c = 0; c < trimLen; c++) {
				WCHAR wc = *(WCHAR*)(buf + pos + c * 2);
				if (wc != (WCHAR)(UCHAR)e->orig[trimStart + c]) { match = false; break; }
			}
			if (match) {
				for (int c = 0; c < trimLen; c++)
					*(WCHAR*)(buf + pos + c * 2) = (WCHAR)(UCHAR)e->spoofed[trimStart + c];
				changed = true;
			}
		}
	}

	// WCHAR model replacement
	for (int i = 0; i < g_modelCount; i++) {
		ModelCacheEntry* e = &g_modelCache[i];
		int trimLen = e->len;
		while (trimLen > 0 && (e->orig[trimLen - 1] == ' ' || e->orig[trimLen - 1] == '\0')) trimLen--;
		if (trimLen < 3) continue;

		int wideBytes = trimLen * 2;
		if (wideBytes > bufLen) continue;

		int spoofTrim = e->len;
		while (spoofTrim > 0 && (e->spoofed[spoofTrim - 1] == ' ' || e->spoofed[spoofTrim - 1] == '\0')) spoofTrim--;

		for (int pos = 0; pos + wideBytes <= bufLen; pos += 2) {
			bool match = true;
			for (int c = 0; c < trimLen; c++) {
				WCHAR wc = *(WCHAR*)(buf + pos + c * 2);
				if (wc != (WCHAR)(UCHAR)e->orig[c]) { match = false; break; }
			}
			if (match) {
				int copyLen = spoofTrim < trimLen ? spoofTrim : trimLen;
				for (int c = 0; c < copyLen; c++)
					*(WCHAR*)(buf + pos + c * 2) = (WCHAR)(UCHAR)e->spoofed[c];
				for (int c = copyLen; c < trimLen; c++)
					*(WCHAR*)(buf + pos + c * 2) = L' ';
				changed = true;
			}
		}
	}
	return changed;
}

// Scan a buffer for "eui." identifier strings and register them in serial cache
static void RegisterEuiFromBuffer(char* buf, int bufLen) {
	for (int off = 0; off + 20 <= bufLen; off++) {
		char* s = buf + off;
		if (s[0] == 'e' && s[1] == 'u' && s[2] == 'i' && s[3] == '.') {
			char* hex = s + 4;
			bool validHex = true;
			for (int h = 0; h < 16; h++) {
				char c = hex[h];
				if (!((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')))
				{ validHex = false; break; }
			}
			if (validHex && g_serialCount + 1 < MAX_SERIAL_CACHE) {
				// Check if already registered (avoid duplicates)
				bool found = false;
				for (int i = 0; i < g_serialCount; i++) {
					SerialCacheEntry* e = &g_serialCache[i];
					if (e->sz == 16 && !memcmp(e->orig, hex, 16)) { found = true; break; }
				}
				if (found) { off += 19; continue; }

				// Register as serial with underscores (matches our EUI format in IOCTL handlers)
				char serialBuf[21];
				serialBuf[0]  = hex[0];  serialBuf[1]  = hex[1];
				serialBuf[2]  = hex[2];  serialBuf[3]  = hex[3];
				serialBuf[4]  = '_';
				serialBuf[5]  = hex[4];  serialBuf[6]  = hex[5];
				serialBuf[7]  = hex[6];  serialBuf[8]  = hex[7];
				serialBuf[9]  = '_';
				serialBuf[10] = hex[8];  serialBuf[11] = hex[9];
				serialBuf[12] = hex[10]; serialBuf[13] = hex[11];
				serialBuf[14] = '_';
				serialBuf[15] = hex[12]; serialBuf[16] = hex[13];
				serialBuf[17] = hex[14]; serialBuf[18] = hex[15];
				serialBuf[19] = '.';
				serialBuf[20] = 0;
				DbgPrintEx(0, 0, "[SPOOF] SpCache: found eui: %.16s\n", hex);
				FindFakeDiskSerial(serialBuf, 20);

				// Also register plain 16-char hex alias (no separators)
				if (g_serialCount > 0 && g_serialCount < MAX_SERIAL_CACHE) {
					SerialCacheEntry* prev = &g_serialCache[g_serialCount - 1];
					SerialCacheEntry* alias = &g_serialCache[g_serialCount];
					RtlZeroMemory(alias, sizeof(*alias));
					int ai = 0;
					for (int j = 0; j < prev->sz && ai < 16; j++) {
						if (prev->orig[j] != '_' && prev->orig[j] != '.') {
							alias->orig[ai] = prev->orig[j];
							alias->spoofed[ai] = prev->spoofed[j];
							ai++;
						}
					}
					if (ai == 16) {
						alias->sz = 16;
						DbgPrintEx(0, 0, "[SPOOF] SpCache: EUI hex alias <%.16s> -> <%.16s>\n", alias->orig, alias->spoofed);
						g_serialCount++;
					}
				}
				off += 19;
			}
		}
	}
}

// Patch spaceport device extension memory in-place
static void PatchSpacePortCache() {
	UNICODE_STRING spName;
	RtlInitUnicodeString(&spName, L"\\Driver\\spaceport");

	PDRIVER_OBJECT drvObj = nullptr;
	NTSTATUS status = ObReferenceObjectByName(&spName, OBJ_CASE_INSENSITIVE, 0, 0,
		*IoDriverObjectType, KernelMode, 0, (void**)&drvObj);
	if (!NT_SUCCESS(status) || !drvObj) {
		DbgPrintEx(0, 0, "[SPOOF] PatchSpacePortCache: could not get spaceport driver object\n");
		return;
	}

	int patchCount = 0;
	int devCount = 0;
	PDEVICE_OBJECT devObj = drvObj->DeviceObject;
	while (devObj) {
		devCount++;
		if (devObj->DeviceExtension) {
			__try {
				char* ext = (char*)devObj->DeviceExtension;

				// Probe pages to find actual valid extent (device extension may be < 16KB)
				ULONG extSize = 0;
				for (ULONG page = 0; page < 0x10000; page += PAGE_SIZE) {
					if (!MmIsAddressValid(ext + page)) break;
					extSize = page + PAGE_SIZE;
				}
				if (extSize < 64) { devObj = devObj->NextDevice; continue; }
				if (extSize > 0x10000) extSize = 0x10000;

				DbgPrintEx(0, 0, "[SPOOF] PatchSpacePortCache: scanning dev ext %p size 0x%X\n", ext, extSize);

				if (MmIsAddressValid(ext)) {
					// Phase 1: Scan for STORAGE_DEVICE_DESCRIPTOR structures
					for (ULONG off = 0; off + sizeof(STORAGE_DEVICE_DESCRIPTOR) <= extSize; off += sizeof(PVOID)) {
						PVOID* pPtr = (PVOID*)(ext + off);
						if (!MmIsAddressValid(pPtr)) continue;
						PVOID ptr = *pPtr;
						if (!ptr || (ULONG_PTR)ptr < 0xFFFF000000000000ULL) continue;
						if (!MmIsAddressValid(ptr)) continue;

						__try {
							PSTORAGE_DEVICE_DESCRIPTOR desc = (PSTORAGE_DEVICE_DESCRIPTOR)ptr;
							if (desc->Version != sizeof(STORAGE_DEVICE_DESCRIPTOR)) continue;
							if (desc->Size < sizeof(STORAGE_DEVICE_DESCRIPTOR) || desc->Size > 0x1000) continue;
							if (desc->BusType == 0 || desc->BusType > 0x1E) continue;

							DbgPrintEx(0, 0, "[SPOOF] SpCache: SDD at %p Size=%u Bus=%d\n", desc, desc->Size, desc->BusType);

							// Validate and patch serial
							if (desc->SerialNumberOffset > 0 && desc->SerialNumberOffset < desc->Size) {
								char* serial = (char*)desc + desc->SerialNumberOffset;
								if (MmIsAddressValid(serial)) {
									int sLen = (int)strlen(serial);
									DbgPrintEx(0, 0, "[SPOOF] SpCache: serial=<%.40s> len=%d\n", serial, sLen);
									if (sLen >= 3 && sLen <= 40) {
										FindFakeDiskSerial(serial, sLen);
										patchCount++;
									}
								}
							}

							// Validate and patch model
							if (desc->ProductIdOffset > 0 && desc->ProductIdOffset < desc->Size) {
								char* product = (char*)desc + desc->ProductIdOffset;
								if (MmIsAddressValid(product)) {
									int pLen = (int)strlen(product);
									DbgPrintEx(0, 0, "[SPOOF] SpCache: model=<%.40s> len=%d\n", product, pLen);
									if (pLen >= 3 && pLen <= 40) {
										FindFakeDiskModel(product, pLen);
										patchCount++;
									}
								}
							}

							// Patch vendor
							if (desc->VendorIdOffset > 0 && desc->VendorIdOffset < desc->Size) {
								char* vendor = (char*)desc + desc->VendorIdOffset;
								if (MmIsAddressValid(vendor)) {
									int vLen = (int)strlen(vendor);
									if (vLen >= 3 && vLen <= 8) {
										// Replace vendor with first word of spoofed model
										for (int m = 0; m < g_modelCount; m++) {
											if (desc->ProductIdOffset > 0) {
												char* prod = (char*)desc + desc->ProductIdOffset;
												int spoofTrim = g_modelCache[m].len;
												while (spoofTrim > 0 && g_modelCache[m].spoofed[spoofTrim - 1] == ' ') spoofTrim--;
												if (spoofTrim > 0 && !memcmp(prod, g_modelCache[m].spoofed, spoofTrim < (int)strlen(prod) ? spoofTrim : (int)strlen(prod))) {
													// Clear vendor to spaces
													memset(vendor, ' ', vLen);
													break;
												}
											}
										}
									}
								}
							}
						}
						__except (EXCEPTION_EXECUTE_HANDLER) {
							continue;
						}
					}

					// Phase 1b: Pre-scan for "eui." identifiers and register in serial cache
					RegisterEuiFromBuffer(ext, extSize);

					// Phase 2: ASCII find-and-replace on raw extension memory
					if (SpoofBufferContentAscii(ext, extSize))
						DbgPrintEx(0, 0, "[SPOOF] SpCache: Phase2 ASCII patched ext %p\n", ext);

					// Phase 3: WCHAR find-and-replace on raw extension memory
					if (SpoofBufferContentWchar(ext, extSize))
						DbgPrintEx(0, 0, "[SPOOF] SpCache: Phase3 WCHAR patched ext %p\n", ext);

					// Phase 4: DISABLED — following arbitrary kernel pointers from the
				// device extension and writing to them can corrupt unrelated pool
				// allocations (object headers, IRPs, etc.), causing
				// REFERENCE_BY_POINTER (0x18) or other bugchecks.
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DbgPrintEx(0, 0, "[SPOOF] PatchSpacePortCache: exception scanning device extension\n");
			}
		}
		devObj = devObj->NextDevice;
	}

	ObDereferenceObject(drvObj);
	DbgPrintEx(0, 0, "[SPOOF] PatchSpacePortCache: scanned %d devices, patched %d fields\n", devCount, patchCount);
}

// ============================================================================
// Pre-create symbolic links for spoofed volume GUIDs so MSFT_Volume can
// resolve the spoofed paths. Must run at PASSIVE_LEVEL before hooks are active.
// ============================================================================

static void CreateSpoofedVolumeSymlinks() {
	// Open mount manager device to query mount points
	UNICODE_STRING mmName = RTL_CONSTANT_STRING(L"\\Device\\MountPointManager");
	PFILE_OBJECT fileObj = nullptr;
	PDEVICE_OBJECT devObj = nullptr;
	NTSTATUS st = IoGetDeviceObjectPointer(&mmName, FILE_READ_DATA, &fileObj, &devObj);
	if (!NT_SUCCESS(st)) {
		DbgPrintEx(0, 0, "[SPOOF] CreateSpoofedVolumeSymlinks: can't open MountPointManager\n");
		return;
	}

	// Build IOCTL_MOUNTMGR_QUERY_POINTS with empty input (returns all)
	MOUNTMGR_MOUNT_POINT input = { 0 };
	ULONG outSize = 4096;
	PMOUNTMGR_MOUNT_POINTS output = (PMOUNTMGR_MOUNT_POINTS)ExAllocatePoolWithTag(NonPagedPool, outSize, 'VlSp');
	if (!output) { ObDereferenceObject(fileObj); return; }

	KEVENT event;
	KeInitializeEvent(&event, NotificationEvent, FALSE);
	IO_STATUS_BLOCK iosb = { 0 };
	PIRP irp = IoBuildDeviceIoControlRequest(
		IOCTL_MOUNTMGR_QUERY_POINTS, devObj,
		&input, sizeof(input), output, outSize,
		FALSE, &event, &iosb);
	if (!irp) { ExFreePoolWithTag(output, 'VlSp'); ObDereferenceObject(fileObj); return; }

	st = IoCallDriver(devObj, irp);
	if (st == STATUS_PENDING)
		KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
	// STATUS_BUFFER_OVERFLOW means we need more space
	if (iosb.Status == STATUS_BUFFER_OVERFLOW && output->Size > outSize) {
		outSize = output->Size;
		ExFreePoolWithTag(output, 'VlSp');
		output = (PMOUNTMGR_MOUNT_POINTS)ExAllocatePoolWithTag(NonPagedPool, outSize, 'VlSp');
		if (!output) { ObDereferenceObject(fileObj); return; }
		KeInitializeEvent(&event, NotificationEvent, FALSE);
		RtlZeroMemory(&iosb, sizeof(iosb));
		irp = IoBuildDeviceIoControlRequest(
			IOCTL_MOUNTMGR_QUERY_POINTS, devObj,
			&input, sizeof(input), output, outSize,
			FALSE, &event, &iosb);
		if (!irp) { ExFreePoolWithTag(output, 'VlSp'); ObDereferenceObject(fileObj); return; }
		st = IoCallDriver(devObj, irp);
		if (st == STATUS_PENDING)
			KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
	}

	if (!NT_SUCCESS(iosb.Status)) {
		DbgPrintEx(0, 0, "[SPOOF] CreateSpoofedVolumeSymlinks: query failed 0x%X\n", iosb.Status);
		ExFreePoolWithTag(output, 'VlSp');
		ObDereferenceObject(fileObj);
		return;
	}

	int linkCount = 0;
	for (DWORD32 i = 0; i < output->NumberOfMountPoints; i++) {
		PMOUNTMGR_MOUNT_POINT pt = &output->MountPoints[i];
		ULONG symOff = pt->SymbolicLinkNameOffset;
		USHORT symLen = pt->SymbolicLinkNameLength;
		if (symLen < GUID_OFFSET + VOLUME_GUID_MAX_LENGTH * (USHORT)sizeof(wchar_t))
			continue;
		wchar_t* sym = (wchar_t*)((char*)output + symOff);
		if (sym[0] != L'\\' || sym[3] != L'\\' || sym[4] != L'V' || sym[10] != L'{')
			continue;

		// Build the original volume path: \??\Volume{GUID}
		wchar_t origPath[64] = { 0 };
		int pathChars = symLen / (int)sizeof(wchar_t);
		if (pathChars > 60) pathChars = 60;
		RtlCopyMemory(origPath, sym, pathChars * sizeof(wchar_t));
		// Ensure \??\ prefix (kernel format)
		origPath[0] = L'\\'; origPath[1] = L'?'; origPath[2] = L'?'; origPath[3] = L'\\';

		// Generate spoofed GUID (same algorithm as FindFakeVolumeGUID)
		wchar_t spoofedPath[64] = { 0 };
		RtlCopyMemory(spoofedPath, origPath, pathChars * sizeof(wchar_t));
		FindFakeVolumeGUID(spoofedPath + GUID_OFFSET / 2);

		// Check if spoofed path differs from original
		if (!memcmp(origPath, spoofedPath, pathChars * sizeof(wchar_t)))
			continue;

		// Create symbolic link: \??\Volume{spoofed-GUID} -> \??\Volume{real-GUID}
		UNICODE_STRING uSpoofed, uOriginal;
		RtlInitUnicodeString(&uSpoofed, spoofedPath);
		RtlInitUnicodeString(&uOriginal, origPath);

		// Delete existing if present (from previous session)
		IoDeleteSymbolicLink(&uSpoofed);
		st = IoCreateSymbolicLink(&uSpoofed, &uOriginal);
		if (NT_SUCCESS(st)) {
			linkCount++;
			DbgPrintEx(0, 0, "[SPOOF] VolumeSymlink: %wZ -> %wZ\n", &uSpoofed, &uOriginal);
		}
	}

	DbgPrintEx(0, 0, "[SPOOF] CreateSpoofedVolumeSymlinks: created %d symlinks\n", linkCount);
	ExFreePoolWithTag(output, 'VlSp');
	ObDereferenceObject(fileObj);
}

// ============================================================================
// disk_ struct: hooks disk, partmgr, mountmgr, storahci, stornvme, spaceport, volmgr, ntfs
// ============================================================================

struct disk_
{
	auto spoof() -> bool
	{
		// Pre-create symbolic links for spoofed volume GUIDs BEFORE hooks are installed
		// so MSFT_Volume can resolve the spoofed paths when mount manager is hooked
		CreateSpoofedVolumeSymlinks();

		HDD_Disk_Control = kmdf_utils::add_irp_hook(hide_string(L"\\Driver\\disk"), HDD_Disk_Handle);
		g_original_partmgr_control = kmdf_utils::add_irp_hook(hide_string(L"\\Driver\\partmgr"), my_partmgr_handle_control);
		g_original_mountmgr_control = kmdf_utils::add_irp_hook(hide_string(L"\\Driver\\mountmgr"), my_mountmgr_handle_control);

		// Hook storahci and stornvme for additional coverage
		PDRIVER_DISPATCH ahci = kmdf_utils::add_irp_hook(hide_string(L"\\Driver\\storahci"), StorahciHandle);
		if (ahci) {
			g_original_storahci_control = ahci;
			DbgPrintEx(0, 0, "[SPOOF] Hook installed: \\Driver\\storahci\n");
		}

		PDRIVER_DISPATCH nvme = kmdf_utils::add_irp_hook(hide_string(L"\\Driver\\stornvme"), StornvmeHandle);
		if (nvme) {
			g_original_stornvme_control = nvme;
			DbgPrintEx(0, 0, "[SPOOF] Hook installed: \\Driver\\stornvme\n");
		}

		// Fix 2: Hook spaceport for MSFT_PhysicalDisk coverage (IOCTL + WMI)
		PDRIVER_DISPATCH sp = kmdf_utils::add_irp_hook(hide_string(L"\\Driver\\spaceport"), SpaceportHandle);
		if (sp) {
			g_original_spaceport_control = sp;
			DbgPrintEx(0, 0, "[SPOOF] Hook installed: \\Driver\\spaceport\n");
		}

		// Fix 3: Hook volmgr for MOUNTDEV_UNIQUE_ID on volume devices (DMIO only, no GUID spoofing)
		g_original_volmgr_control = kmdf_utils::add_irp_hook(hide_string(L"\\Driver\\volmgr"), VolmgrHandle);
		if (g_original_volmgr_control)
			DbgPrintEx(0, 0, "[SPOOF] Hook installed: \\Driver\\volmgr\n");

		// Fix 4: Hook Ntfs for volume serial number spoofing
		g_original_ntfs_volinfo = kmdf_utils::add_irp_hook_ex(hide_string(L"\\Driver\\Ntfs"), IRP_MJ_QUERY_VOLUME_INFORMATION, NtfsVolumeInfoHandle);
		if (g_original_ntfs_volinfo)
			DbgPrintEx(0, 0, "[SPOOF] Hook installed: \\Driver\\Ntfs (IRP_MJ_QUERY_VOLUME_INFORMATION)\n");

		// Fix 1: Spoof registry values (FriendlyName, DEVICEMAP, MountedDevices)
		SpoofDiskRegistry();

		// Clean forensic traces (BAM, MUI Cache, FeatureUsage, etc.)
		CleanForensicTraces();

		// Fix 5: Patch spaceport's internal cache in-place (fixes MSFT_PhysicalDisk)
		// Must run AFTER SpoofDiskRegistry so serial/model caches are populated
		PatchSpacePortCache();

		return true;
	}
};

disk_ disk;
