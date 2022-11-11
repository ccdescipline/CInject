#pragma once
#include "ntifs.h"
#include "ntddk.h"
#include "utils.h"
#include "ApcInject.h"



typedef ULONG(*FuncType)(PETHREAD Thread);

extern FuncType KeSuspendThread;
extern FuncType KeResumeThread;





//1909 +0x090 _KTHREAD _KTRAP_FRAME
#define OFFSET_KTRAP_FRAME 0x090



void EipExcuteFuntion(PEPROCESS process, PVOID func, ULONG64 modulebase, LONGLONG cleartimeSecond);
PETHREAD GetFirstThread(PEPROCESS tempep);
bool IsGuiThread(PETHREAD thread);
KTRAP_FRAME MyGetThreadContext(PETHREAD thread);
bool MySetThreadContext(PETHREAD thread, KTRAP_FRAME context);
void initKethreadFunc();