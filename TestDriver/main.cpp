#include "ntifs.h"
#include "ntddk.h"
#include "wdm.h"

#include "utils.h"
#include "filehelp.h"
#include "ApcInject.h"
#include "PeHelper.h"
#include "EipInject.h"

PDRIVER_OBJECT G_DriverObject = NULL;

typedef void (*LoopthreadCallback)(PETHREAD thread);

//遍历进程
PETHREAD LoopThreadInProcess(PEPROCESS tempep, LoopthreadCallback func)
{
	PETHREAD pretthreadojb = NULL, ptempthreadobj = NULL;

	PLIST_ENTRY plisthead = NULL;

	PLIST_ENTRY plistflink = NULL;

	int i = 0;

	plisthead = (PLIST_ENTRY)((PUCHAR)tempep + 0x30);

	plistflink = plisthead->Flink;

	//遍历
	for (plistflink; plistflink != plisthead; plistflink = plistflink->Flink)
	{
		ptempthreadobj = (PETHREAD)((PUCHAR)plistflink - 0x2f8);

		HANDLE threadId = PsGetThreadId(ptempthreadobj);

		func(ptempthreadobj);

		DbgPrint("线程ID: %d \r\n", threadId);

		i++;

	}

	return pretthreadojb;
}

void RemoteLoadPeData(PEPROCESS process, PVOID filebufeer, ULONG64 filesize,PVOID * entry,PVOID * moduleBase) {
	//附加
	KAPC_STATE KAPC;
	//PEPROCESS pEProc;
	//NTSTATUS GetPEPROCESSStatus = PsLookupProcessByProcessId((PsGetProcessId(process)), &pEProc);
	//if (!NT_SUCCESS(GetPEPROCESSStatus)) {
	//	DbgPrint("准备附加申请内存失败");
	//	ObDereferenceObject(pEProc);
	//	return;
	//}

	KeStackAttachProcess(process, &KAPC);

	//进程申请内存
	PVOID virtualbase = NULL;
	//ULONG64 imagesize = GetImageSize((PUCHAR)filebufeer);
	//NTSTATUS AllocateStatus = NtAllocateVirtualMemory(NtCurrentProcess(), &virtualbase, NULL, &imagesize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//memset(virtualbase, 0, imagesize);
	//if (!NT_SUCCESS(AllocateStatus)) {
	//	DbgPrint("进程申请内存申请失败 代码：%ullx", AllocateStatus);
	//	return;
	//}
	//DbgPrint("进程申请内存地址： %p 镜像大小：%llu", virtualbase, imagesize);

	NTSTATUS allocatePeStatus =  RemoteAllcateMemory(process, GetImageSize((PUCHAR)filebufeer), &virtualbase);
	if (!NT_SUCCESS(allocatePeStatus))
	{
		DbgPrint("进程申请内存申请失败");
		return;
	}
	DbgPrint("远程申请Pe内存成功！");

	PVOID Pebuffer = NULL;
	ULONG64 PEsize = NULL;
	PVOID entrypoint = NULL;
	PELoaderDLL((PUCHAR)filebufeer, (PUCHAR)virtualbase, &Pebuffer, &PEsize, &entrypoint, (PsGetProcessId(process)));
	DbgPrint("PEbuffer 地址：%p  PEsize : %llu 入口点位置：%p", Pebuffer, PEsize, entrypoint);

	KeUnstackDetachProcess(&KAPC);
	//ObDereferenceObject(pEProc);

	//拷贝处理好的Pe到进程空间
	size_t bytes = 0;
	MmCopyVirtualMemory(IoGetCurrentProcess(), Pebuffer, process, virtualbase, filesize, KernelMode, &bytes);

	*entry = entrypoint;
	*moduleBase = virtualbase;

	//释放Pebuffer
	ExFreePool(Pebuffer);

}

void injectDll(LPCWSTR procName, PVOID filebuffer, ULONG64 filesize) {
	//找目标进程
	//r5apex.exe
	//mspaint.exe
	PEPROCESS process =  GetEprocessByName(procName);
	if (!process) {
		DbgPrint("进程未找到");
		return;
	}

	LoopThreadInProcess(process, [](PETHREAD thread) {});

	//拉伸PE
	PVOID entrypoint = NULL;
	PVOID moduleBase = NULL;
	RemoteLoadPeData(process, filebuffer,filesize,&entrypoint,&moduleBase);

	//APC执行函数
	//APCExecuteFunction(process, entrypoint,(ULONG64)moduleBase);


	//Eip执行函数
	EipExcuteFuntion(process, entrypoint,(ULONG64)moduleBase,30);
	
}

//卸载函数
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
	DbgPrint("驱动卸载成功！");
}

//void LoopSSDT() {
//	//dq KeServiceDescriptorTable
//
//	//获取 Ntoskrnl
//	PVOID  ntoskrnlBase = NULL;
//	ULONG64 size = NULL;
//	GetNtoskrnlBase(&ntoskrnlBase, &size);
//	PUCHAR ModuleStart = (PUCHAR)ntoskrnlBase;
//	PUCHAR ModuleEnd = ModuleStart + size;
//
//	//找  u KiSystemServiceRepeat
//	PUCHAR KiSystemServiceRepeat =   FindPattern_Wrapper(ModuleStart, size,"4C 8D 15 ? ? ? ? 4C 8D 1D");
//	DbgPrint("KiSystemServiceRepeat : %p", KiSystemServiceRepeat);
//	//定位KeServiceDescriptorTable
//	PUCHAR KeServiceDescriptorTable = *(PULONG)(KiSystemServiceRepeat + 3)+(KiSystemServiceRepeat + 7);
//	DbgPrint("KeServiceDescriptorTable : %p", KeServiceDescriptorTable);
//
//	ULONG index = *(PULONG)(KeServiceDescriptorTable + 0x10);
//	ULONG64 SSDT = *(PULONG64)KeServiceDescriptorTable;
//	for (size_t i = 0; i < index; i++)
//	{
//		PUCHAR func = (PUCHAR)(((PLONG)SSDT)[i] >> 4) + SSDT;
//		DbgPrint("index : %d  func : %p",i,func);
//	}
//}

//加载函数
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	DriverObject->DriverUnload = DriverUnload;
	G_DriverObject = DriverObject;

	//初始化函数
	initKethreadFunc();

	//读文件
	//C:\Users\admin\Desktop
	//\\??\\C:\\Users\\admin\\Desktop\\TestDLL.dll
	PVOID filebuffer = NULL;
	ULONG64 filesize = NULL;
	ReadFile(L"\\??\\C:\\Users\\admin\\Desktop\\TestDLL.dll", &filebuffer, &filesize);
	DbgPrint("文件流地址： %p 大小：%d", filebuffer, filesize);

	//注入
	injectDll(L"notepad.exe", filebuffer, filesize);

	//释放filebuffer
	ExFreePool(filebuffer);

	DbgPrint("驱动加载成功！");
	return STATUS_SUCCESS;
}