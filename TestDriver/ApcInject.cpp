#include "ApcInject.h"


typedef PVOID(__stdcall* MGetThreadTeb)(PETHREAD pEthread);
typedef UCHAR BYTE;

BOOLEAN SkipApcThread(PETHREAD pthread)
{
	PUCHAR pteb64 = (PUCHAR)PsGetThreadTeb(pthread);
	//DbgPrint("pteb64 : %p", pteb64);
	//DbgPrint("pteb64 + 0x78 : %p", pteb64 + 0x78);

	//if (!MmIsAddressValid(pteb64)) {
	//	DbgPrint("pteb64 地址错误");
	//}
	//else
	//{
	//	DbgPrint("pteb64 地址正确");
	//}

	if (!pteb64) {
		return TRUE;
	}

	

	if (*(PULONG64)(pteb64 + 0x78)!=0) {
		return TRUE;
	}

	if (*(PULONG64)(pteb64 + 0x2c8) == 0) {
		return TRUE;
	}

	if (*(PULONG64)(pteb64 + 0x58) == 0) {
		return TRUE;
	}


	return FALSE;
}


PETHREAD FindThreadInProcess(HANDLE pid)
{
	PEPROCESS pEpro = NULL;
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	ntStatus = PsLookupProcessByProcessId(pid, &pEpro);

	if (!NT_SUCCESS(ntStatus))
	{
		ObDereferenceObject(pEpro);
		return NULL;
	}

	KAPC_STATE kapc;
	//附加
	KeStackAttachProcess(pEpro,&kapc);

	PETHREAD pretthreadojb = NULL, ptempthreadobj = NULL;

	PLIST_ENTRY plisthead = NULL;

	PLIST_ENTRY plistflink = NULL;

	int i = 0;

	plisthead = (PLIST_ENTRY)((PUCHAR)pEpro + 0x30);

	plistflink = plisthead->Flink;

	//遍历
	for (plistflink; plistflink != plisthead; plistflink = plistflink->Flink)
	{
		ptempthreadobj = (PETHREAD)((PUCHAR)plistflink - 0x2f8);

		HANDLE threadId = PsGetThreadId(ptempthreadobj);

		DbgPrint("线程ID: %d", threadId);

		

		if (!MmIsAddressValid(ptempthreadobj)) {
			continue;
		}

		i++;

		if (!SkipApcThread(ptempthreadobj)) {
			pretthreadojb = ptempthreadobj;
			break;
		}
		
	}

	KeUnstackDetachProcess(&kapc);
	ObDereferenceObject(pEpro); //解引用
	return pretthreadojb;
}

VOID PKKERNEL_ROUTINE_CALLBACK(
	IN struct _KAPC* Apc,
	IN OUT PKNORMAL_ROUTINE* NormalRoutine,
	IN OUT PVOID* NormalContext,
	IN OUT PVOID* SystemArgument1,
	IN OUT PVOID* SystemArgument2
) {
	//释放Apc
	ExFreePool(Apc);
	DbgPrint("APC回调执行！");
}

bool APCExecuteFunction(PEPROCESS process , PVOID func,ULONG64 modulebase) {

	//挑选一个合适的线程
	PETHREAD thread = FindThreadInProcess(PsGetProcessId(process));
	if (!thread) {
		DbgPrint("挑选线程失败");
		return false;
	}

	PRKAPC kapc = (PRKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
	KeInitializeApc(
		kapc,
		thread,
		OriginalApcEnvironment,
		PKKERNEL_ROUTINE_CALLBACK,
		NULL,
		(PKNORMAL_ROUTINE)func,		//(PKNORMAL_ROUTINE)fun_addr
		UserMode,
		(PVOID)modulebase
	);

	BOOLEAN res = KeInsertQueueApc(kapc
		, (PVOID)DLL_PROCESS_ATTACH, NULL,			//PKKERNEL_ROUTINE 回调的参数
		IO_NO_INCREMENT			//优先级
	);



	if (!res) {

		return false;
		//DbgPrint("内核APC插入成功！");
	}

	DbgPrint("内核APC插入成功！,线程ID: %d", PsGetThreadId(thread));

	return true;
}