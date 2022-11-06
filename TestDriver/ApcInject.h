#pragma once

#include "ntifs.h"
#include "ntddk.h"
#include "utils.h"

typedef unsigned short      WORD;
typedef unsigned long       DWORD;
typedef unsigned char       BYTE;

#pragma region APC

//extern "C"  PVOID __stdcall PsGetThreadTeb(__in PETHREAD Thread);
typedef enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;

typedef
VOID
(*PKNORMAL_ROUTINE) (
    IN PVOID NormalContext,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2
    );


typedef
VOID
(*PKKERNEL_ROUTINE) (
    IN struct _KAPC* Apc,
    IN OUT PKNORMAL_ROUTINE* NormalRoutine,
    IN OUT PVOID* NormalContext,
    IN OUT PVOID* SystemArgument1,
    IN OUT PVOID* SystemArgument2
    );

typedef
VOID
(*PKRUNDOWN_ROUTINE) (
    IN struct _KAPC* Apc
    );

#pragma endregion




extern "C" {
    NTKERNELAPI
        PVOID
        NTAPI
        PsGetThreadTeb(IN PETHREAD Thread);

    NTKERNELAPI
        VOID
        KeInitializeApc(
            __out PRKAPC Apc, //KAPC指针
            __in PRKTHREAD Thread, //目标线程
            __in KAPC_ENVIRONMENT Environment, //插入环境
            __in PKKERNEL_ROUTINE KernelRoutine, //R3为销毁KAPC函数地址
            __in_opt PKRUNDOWN_ROUTINE RundownRoutine,
            __in_opt PKNORMAL_ROUTINE NormalRoutine, //用户APC总入口 / 内核APC函数
            __in_opt KPROCESSOR_MODE ProcessorMode, //0内核队列 / 1用户队列
            __in_opt PVOID NormalContext //用户APC执行函数
        );


    NTKERNELAPI
        BOOLEAN
        KeInsertQueueApc(
            __inout PRKAPC Apc,
            __in_opt PVOID SystemArgument1,
            __in_opt PVOID SystemArgument2,
            __in KPRIORITY Increment
        );

    NTKERNELAPI
    NTSTATUS
    NTAPI
    MmCopyVirtualMemory(
        _In_ PEPROCESS FromProcess,
        _In_ PVOID FromAddress,
        _In_ PEPROCESS ToProcess,
        _Out_ PVOID ToAddress,
        _In_ SIZE_T BufferSize,
        _In_ KPROCESSOR_MODE PreviousMode,
        _Out_ PSIZE_T NumberOfBytesCopied
    );

    NTKERNELAPI PPEB NTAPI PsGetProcessPeb
    (
        IN PEPROCESS Process
    );
}





//挑选合适的Apc线程
BOOLEAN SkipApcThread(PETHREAD pthread);

PETHREAD FindThreadInProcess(HANDLE pid);

bool APCExecuteFunction(PEPROCESS process, PVOID func, ULONG64 modulebase);