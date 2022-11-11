#pragma once
#include "ntifs.h"
#include "ntddk.h"


typedef unsigned char       BYTE;
typedef BYTE* PBYTE;
typedef unsigned long       DWORD;
#define DLL_PROCESS_ATTACH   1   

typedef struct _FILETIME {
	DWORD dwLowDateTime;
	DWORD dwHighDateTime;
} FILETIME, * PFILETIME, * LPFILETIME;

extern "C" UCHAR * PsGetProcessImageFileName(__in PEPROCESS Process);

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0x0,
	SystemProcessorInformation = 0x1,
	SystemPerformanceInformation = 0x2,
	SystemTimeOfDayInformation = 0x3,
	SystemPathInformation = 0x4,
	SystemProcessInformation = 0x5,
	SystemCallCountInformation = 0x6,
	SystemDeviceInformation = 0x7,
	SystemProcessorPerformanceInformation = 0x8,
	SystemFlagsInformation = 0x9,
	SystemCallTimeInformation = 0xa,
	SystemModuleInformation = 0xb,
	SystemLocksInformation = 0xc,
	SystemStackTraceInformation = 0xd,
	SystemPagedPoolInformation = 0xe,
	SystemNonPagedPoolInformation = 0xf,
	SystemHandleInformation = 0x10,
	SystemObjectInformation = 0x11,
	SystemPageFileInformation = 0x12,
	SystemVdmInstemulInformation = 0x13,
	SystemVdmBopInformation = 0x14,
	SystemFileCacheInformation = 0x15,
	SystemPoolTagInformation = 0x16,
	SystemInterruptInformation = 0x17,
	SystemDpcBehaviorInformation = 0x18,
	SystemFullMemoryInformation = 0x19,
	SystemLoadGdiDriverInformation = 0x1a,
	SystemUnloadGdiDriverInformation = 0x1b,
	SystemTimeAdjustmentInformation = 0x1c,
	SystemSummaryMemoryInformation = 0x1d,
	SystemMirrorMemoryInformation = 0x1e,
	SystemPerformanceTraceInformation = 0x1f,
	SystemObsolete0 = 0x20,
	SystemExceptionInformation = 0x21,
	SystemCrashDumpStateInformation = 0x22,
	SystemKernelDebuggerInformation = 0x23,
	SystemContextSwitchInformation = 0x24,
	SystemRegistryQuotaInformation = 0x25,
	SystemExtendServiceTableInformation = 0x26,
	SystemPrioritySeperation = 0x27,
	SystemVerifierAddDriverInformation = 0x28,
	SystemVerifierRemoveDriverInformation = 0x29,
	SystemProcessorIdleInformation = 0x2a,
	SystemLegacyDriverInformation = 0x2b,
	SystemCurrentTimeZoneInformation = 0x2c,
	SystemLookasideInformation = 0x2d,
	SystemTimeSlipNotification = 0x2e,
	SystemSessionCreate = 0x2f,
	SystemSessionDetach = 0x30,
	SystemSessionInformation = 0x31,
	SystemRangeStartInformation = 0x32,
	SystemVerifierInformation = 0x33,
	SystemVerifierThunkExtend = 0x34,
	SystemSessionProcessInformation = 0x35,
	SystemLoadGdiDriverInSystemSpace = 0x36,
	SystemNumaProcessorMap = 0x37,
	SystemPrefetcherInformation = 0x38,
	SystemExtendedProcessInformation = 0x39,
	SystemRecommendedSharedDataAlignment = 0x3a,
	SystemComPlusPackage = 0x3b,
	SystemNumaAvailableMemory = 0x3c,
	SystemProcessorPowerInformation = 0x3d,
	SystemEmulationBasicInformation = 0x3e,
	SystemEmulationProcessorInformation = 0x3f,
	SystemExtendedHandleInformation = 0x40,
	SystemLostDelayedWriteInformation = 0x41,
	SystemBigPoolInformation = 0x42,
	SystemSessionPoolTagInformation = 0x43,
	SystemSessionMappedViewInformation = 0x44,
	SystemHotpatchInformation = 0x45,
	SystemObjectSecurityMode = 0x46,
	SystemWatchdogTimerHandler = 0x47,
	SystemWatchdogTimerInformation = 0x48,
	SystemLogicalProcessorInformation = 0x49,
	SystemWow64SharedInformationObsolete = 0x4a,
	SystemRegisterFirmwareTableInformationHandler = 0x4b,
	SystemFirmwareTableInformation = 0x4c,
	SystemModuleInformationEx = 0x4d,
	SystemVerifierTriageInformation = 0x4e,
	SystemSuperfetchInformation = 0x4f,
	SystemMemoryListInformation = 0x50,
	SystemFileCacheInformationEx = 0x51,
	SystemThreadPriorityClientIdInformation = 0x52,
	SystemProcessorIdleCycleTimeInformation = 0x53,
	SystemVerifierCancellationInformation = 0x54,
	SystemProcessorPowerInformationEx = 0x55,
	SystemRefTraceInformation = 0x56,
	SystemSpecialPoolInformation = 0x57,
	SystemProcessIdInformation = 0x58,
	SystemErrorPortInformation = 0x59,
	SystemBootEnvironmentInformation = 0x5a,
	SystemHypervisorInformation = 0x5b,
	SystemVerifierInformationEx = 0x5c,
	SystemTimeZoneInformation = 0x5d,
	SystemImageFileExecutionOptionsInformation = 0x5e,
	SystemCoverageInformation = 0x5f,
	SystemPrefetchPatchInformation = 0x60,
	SystemVerifierFaultsInformation = 0x61,
	SystemSystemPartitionInformation = 0x62,
	SystemSystemDiskInformation = 0x63,
	SystemProcessorPerformanceDistribution = 0x64,
	SystemNumaProximityNodeInformation = 0x65,
	SystemDynamicTimeZoneInformation = 0x66,
	SystemCodeIntegrityInformation = 0x67,
	SystemProcessorMicrocodeUpdateInformation = 0x68,
	SystemProcessorBrandString = 0x69,
	SystemVirtualAddressInformation = 0x6a,
	SystemLogicalProcessorAndGroupInformation = 0x6b,
	SystemProcessorCycleTimeInformation = 0x6c,
	SystemStoreInformation = 0x6d,
	SystemRegistryAppendString = 0x6e,
	SystemAitSamplingValue = 0x6f,
	SystemVhdBootInformation = 0x70,
	SystemCpuQuotaInformation = 0x71,
	SystemNativeBasicInformation = 0x72,
	SystemErrorPortTimeouts = 0x73,
	SystemLowPriorityIoInformation = 0x74,
	SystemBootEntropyInformation = 0x75,
	SystemVerifierCountersInformation = 0x76,
	SystemPagedPoolInformationEx = 0x77,
	SystemSystemPtesInformationEx = 0x78,
	SystemNodeDistanceInformation = 0x79,
	SystemAcpiAuditInformation = 0x7a,
	SystemBasicPerformanceInformation = 0x7b,
	SystemQueryPerformanceCounterInformation = 0x7c,
	SystemSessionBigPoolInformation = 0x7d,
	SystemBootGraphicsInformation = 0x7e,
	SystemScrubPhysicalMemoryInformation = 0x7f,
	SystemBadPageInformation = 0x80,
	SystemProcessorProfileControlArea = 0x81,
	SystemCombinePhysicalMemoryInformation = 0x82,
	SystemEntropyInterruptTimingInformation = 0x83,
	SystemConsoleInformation = 0x84,
	SystemPlatformBinaryInformation = 0x85,
	SystemThrottleNotificationInformation = 0x86,
	SystemHypervisorProcessorCountInformation = 0x87,
	SystemDeviceDataInformation = 0x88,
	SystemDeviceDataEnumerationInformation = 0x89,
	SystemMemoryTopologyInformation = 0x8a,
	SystemMemoryChannelInformation = 0x8b,
	SystemBootLogoInformation = 0x8c,
	SystemProcessorPerformanceInformationEx = 0x8d,
	SystemSpare0 = 0x8e,
	SystemSecureBootPolicyInformation = 0x8f,
	SystemPageFileInformationEx = 0x90,
	SystemSecureBootInformation = 0x91,
	SystemEntropyInterruptTimingRawInformation = 0x92,
	SystemPortableWorkspaceEfiLauncherInformation = 0x93,
	SystemFullProcessInformation = 0x94,
	SystemKernelDebuggerInformationEx = 0x95,
	SystemBootMetadataInformation = 0x96,
	SystemSoftRebootInformation = 0x97,
	SystemElamCertificateInformation = 0x98,
	SystemOfflineDumpConfigInformation = 0x99,
	SystemProcessorFeaturesInformation = 0x9a,
	SystemRegistryReconciliationInformation = 0x9b,
	MaxSystemInfoClass = 0x9c,
} SYSTEM_INFORMATION_CLASS;


typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	ULONG WaitReason;
	ULONG PadPadAlignment;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESSES
{
	ULONG NextEntryDelta; //构成结构序列的偏移量;
	ULONG ThreadCount; //线程数目;
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime; //创建时间;
	LARGE_INTEGER UserTime;//用户模式(Ring 3)的CPU时间;
	LARGE_INTEGER KernelTime; //内核模式(Ring 0)的CPU时间;
	UNICODE_STRING ProcessName; //进程名称;
	KPRIORITY BasePriority;//进程优先权;
	ULONG ProcessId; //进程标识符;
	ULONG InheritedFromProcessId; //父进程的标识符;
	ULONG HandleCount; //句柄数目;
	ULONG Reserved2[2];
	VM_COUNTERS  VmCounters; //虚拟存储器的结构，见下;
	IO_COUNTERS IoCounters; //IO计数结构，见下;
	SYSTEM_THREAD_INFORMATION Threads[1]; //进程相关线程的结构数组
}SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

//typedef enum _SYSTEM_INFORMATION_CLASS {
//	SystemBasicInformation, // 0 Y N
//	SystemProcessorInformation, // 1 Y N
//	SystemPerformanceInformation, // 2 Y N
//	SystemTimeOfDayInformation, // 3 Y N
//	SystemNotImplemented1, // 4 Y N
//	SystemProcessesAndThreadsInformation, // 5 Y N
//	SystemCallCounts, // 6 Y N
//	SystemConfigurationInformation, // 7 Y N
//	SystemProcessorTimes, // 8 Y N
//	SystemGlobalFlag, // 9 Y Y
//	SystemNotImplemented2, // 10 Y N
//	SystemModuleInformation, // 11 Y N
//	SystemLockInformation, // 12 Y N
//	SystemNotImplemented3, // 13 Y N
//	SystemNotImplemented4, // 14 Y N
//	SystemNotImplemented5, // 15 Y N
//	SystemHandleInformation, // 16 Y N
//	SystemObjectInformation, // 17 Y N
//	SystemPagefileInformation, // 18 Y N
//	SystemInstructionEmulationCounts, // 19 Y N
//	SystemInvalidInfoClass1, // 20
//	SystemCacheInformation, // 21 Y Y
//	SystemPoolTagInformation, // 22 Y N
//	SystemProcessorStatistics, // 23 Y N
//	SystemDpcInformation, // 24 Y Y
//	SystemNotImplemented6, // 25 Y N
//	SystemLoadImage, // 26 N Y
//	SystemUnloadImage, // 27 N Y
//	SystemTimeAdjustment, // 28 Y Y
//	SystemNotImplemented7, // 29 Y N
//	SystemNotImplemented8, // 30 Y N
//	SystemNotImplemented9, // 31 Y N
//	SystemCrashDumpInformation, // 32 Y N
//	SystemExceptionInformation, // 33 Y N
//	SystemCrashDumpStateInformation, // 34 Y Y/N
//	SystemKernelDebuggerInformation, // 35 Y N
//	SystemContextSwitchInformation, // 36 Y N
//	SystemRegistryQuotaInformation, // 37 Y Y
//	SystemLoadAndCallImage, // 38 N Y
//	SystemPrioritySeparation, // 39 N Y
//	SystemNotImplemented10, // 40 Y N
//	SystemNotImplemented11, // 41 Y N
//	SystemInvalidInfoClass2, // 42
//	SystemInvalidInfoClass3, // 43
//	SystemTimeZoneInformation, // 44 Y N
//	SystemLookasideInformation, // 45 Y N
//	SystemSetTimeSlipEvent, // 46 N Y
//	SystemCreateSession, // 47 N Y
//	SystemDeleteSession, // 48 N Y
//	SystemInvalidInfoClass4, // 49
//	SystemRangeStartInformation, // 50 Y N
//	SystemVerifierInformation, // 51 Y Y
//	SystemAddVerifier, // 52 N Y
//	SystemSessionProcessesInformation // 53 Y N
//}SYSTEM_INFORMATION_CLASS;

extern "C"
NTSTATUS
ZwQuerySystemInformation(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	ULONG * ReturnLength);

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	PVOID Section;
	PVOID MappedBase;
	PVOID ImageBase;            //映射基地址
	ULONG ImageSize;            //映射大小
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR FullPathName[0x0100];  //模块路径名称
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct  _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[ANYSIZE_ARRAY];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;



PEPROCESS GetEprocessByName(LPCWSTR exeName);
NTSTATUS ANSIToUNCODESTRING(LPCSTR source, PUNICODE_STRING dst);
PBYTE FindPattern_Wrapper(PUCHAR start, SIZE_T size, const char* Pattern);
NTSTATUS RemoteAllcateMemory(PEPROCESS process, SIZE_T size, PVOID* addr);
NTSTATUS RemoteFreeMemory(PEPROCESS process, PVOID addr, SIZE_T size);
bool GetNtoskrnlBase(PVOID* ntoskrnlBase, PULONG64 size);
HANDLE EnumProcessByZwQuerySysInfo(PUNICODE_STRING processName);