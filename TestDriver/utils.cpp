#include "utils.h"

HANDLE EnumProcessByZwQuerySysInfo(PUNICODE_STRING processName)
{
    PVOID	pBuftmp = NULL;
    ULONG	 dwRetSize = 0;
    NTSTATUS status = STATUS_SUCCESS;
    PSYSTEM_PROCESS_INFORMATION	pSysProcInfo = NULL;
    PEPROCESS	pEproc;

    //获取大小
    status = ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &dwRetSize);
    //申请内存
    pBuftmp = ExAllocatePool(NonPagedPool, dwRetSize);		//dwRetSize 需要的大小
    if (pBuftmp != NULL)
    {
        //再次执行,将枚举结果放到指定的内存区域
        status = ZwQuerySystemInformation(SystemProcessInformation, pBuftmp, dwRetSize, NULL);
        if (NT_SUCCESS(status))
        {
            pSysProcInfo = (PSYSTEM_PROCESS_INFORMATION)pBuftmp;
            //循环遍历
            while (TRUE)
            {
                pEproc = NULL;

                DbgPrint("processname :%ws pid:%d", pSysProcInfo->ImageName.Buffer, pSysProcInfo->UniqueProcessId);

                if (!RtlCompareUnicodeString(&(pSysProcInfo->ImageName), processName ,TRUE )) {
                    DbgPrint("找到！ %d", pSysProcInfo->UniqueProcessId);
                    ExFreePool(pBuftmp);
                    return pSysProcInfo->UniqueProcessId;
                }

                //ptagProc->NextEntryOffset==0 即遍历到了链表尾部
                if (pSysProcInfo->NextEntryOffset == 0)
                    break;

                //下一个结构
                pSysProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG64)pSysProcInfo + pSysProcInfo->NextEntryOffset);
            }
        }

        ExFreePool(pBuftmp);
    }


    return NULL;
}


PEPROCESS GetEprocessByName(LPCWSTR exeName)
{
    //for (int i = 4; i < 2147483648; i += 4)
    //{
    //    PEPROCESS pEpro = NULL;
    //    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    //    ntStatus = PsLookupProcessByProcessId((HANDLE)i, &pEpro);

    //    if (!NT_SUCCESS(ntStatus))
    //    {
    //        continue;
    //    }


    //    UCHAR* currentName = PsGetProcessImageFileName(pEpro);

    //    if (strcmp((const char*)currentName, exeName)) {
    //        ObDereferenceObject(pEpro); //解引用
    //        continue;
    //    }

    //    DbgPrint("进程名字为: %s 进程PID = %d \r\n",
    //        PsGetProcessImageFileName(pEpro),
    //        PsGetProcessId(pEpro));

    //    ObDereferenceObject(pEpro); //解引用

    //    return pEpro;
    //}
    UNICODE_STRING proc_name = { 0 };
    RtlInitUnicodeString(&proc_name, exeName);
    HANDLE pid =  EnumProcessByZwQuerySysInfo(&proc_name);

    PEPROCESS pEpro = NULL;
    NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
    ntStatus = PsLookupProcessByProcessId(pid, &pEpro);

    ObDereferenceObject(pEpro); //解引用
    if (!NT_SUCCESS(ntStatus))
    {
        return NULL;
    }


    return pEpro;
}

//lpcstr转lpcwstr
NTSTATUS ANSIToUNCODESTRING(LPCSTR source, PUNICODE_STRING  dst) {

    UNICODE_STRING wchar = {0};
    //RtlInitUnicodeString(wchar, L"");

    ANSI_STRING cchar = { 0 };
    RtlInitAnsiString(&cchar,source);
    RtlAnsiStringToUnicodeString(&wchar, &cchar,TRUE);

    *dst = wchar;
    
    return STATUS_SUCCESS;
}

PBYTE FindPattern_Wrapper(PUCHAR start, SIZE_T size, const char* Pattern)
{
    //find pattern utils
    #define InRange(x, a, b) (x >= a && x <= b) 
    #define GetBits(x) (InRange(x, '0', '9') ? (x - '0') : ((x - 'A') + 0xA))
    #define GetByte(x) ((BYTE)(GetBits(x[0]) << 4 | GetBits(x[1])))

    //get module range
    PBYTE ModuleStart = start;
    PBYTE ModuleEnd = (PBYTE)(ModuleStart + size);

    //scan pattern main
    PBYTE FirstMatch = nullptr;
    const char* CurPatt = Pattern;
    for (; ModuleStart < ModuleEnd; ++ModuleStart)
    {
        bool SkipByte = (*CurPatt == '\?');
        if (SkipByte || *ModuleStart == GetByte(CurPatt)) {
            if (!FirstMatch) FirstMatch = ModuleStart;
            SkipByte ? CurPatt += 2 : CurPatt += 3;
            if (CurPatt[-1] == 0) return FirstMatch;
        }

        else if (FirstMatch) {
            ModuleStart = FirstMatch;
            FirstMatch = nullptr;
            CurPatt = Pattern;
        }
    }

    return NULL;
}

NTSTATUS RemoteAllcateMemory(PEPROCESS process, SIZE_T size,PVOID * addr) {
    //附加
    KAPC_STATE KAPC;
    if (!process) {
        DbgPrint("准备附加申请内存失败");
        return STATUS_UNSUCCESSFUL;
    }

    KeStackAttachProcess(process, &KAPC);

    //申请
    PVOID virtualbase = NULL;
    NTSTATUS AllocateStatus = NtAllocateVirtualMemory(NtCurrentProcess(), &virtualbase, NULL, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (!NT_SUCCESS(AllocateStatus)) {
        return STATUS_UNSUCCESSFUL;
    }
    //内存归0
    memset(virtualbase, 0, size);

    DbgPrint("进程申请内存地址： %p 镜像大小：%llu", virtualbase, size);

    KeUnstackDetachProcess(&KAPC);
    //ObDereferenceObject(process);

    *addr = virtualbase;

    return STATUS_SUCCESS;
}

NTSTATUS RemoteFreeMemory(PEPROCESS process,PVOID addr,SIZE_T size) {
    //附加
    KAPC_STATE KAPC;
    if (!process) {
        DbgPrint("准备附加申请内存失败");
        return STATUS_UNSUCCESSFUL;
    }

    KeStackAttachProcess(process, &KAPC);

    memset(addr, 0, size);
    NTSTATUS freestatus =  NtFreeVirtualMemory(NtCurrentProcess(),&addr, &size, MEM_RELEASE);

    if (!NT_SUCCESS(freestatus)) {
        DbgPrint("释放失败");
        return STATUS_UNSUCCESSFUL;
    }

    DbgPrint("释放内存 !");

    KeUnstackDetachProcess(&KAPC);

    return STATUS_SUCCESS;
}

bool GetNtoskrnlBase(PVOID* ntoskrnlBase, PULONG64 size) {
    //PVOID 
    ULONG bytes = 0;
    NTSTATUS QuerySystemInformationstatus = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);
    if (bytes == 0)
    {
        DbgPrint("QuerySystemInformationstatus 第一次失败");
        return false;
    }

    PRTL_PROCESS_MODULES pMods = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPoolNx, bytes);
    RtlZeroMemory(pMods, bytes);

    QuerySystemInformationstatus = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);
    if (!NT_SUCCESS(QuerySystemInformationstatus)) {
        DbgPrint("QuerySystemInformationstatus 第二次失败");
        return false;
    }

    //Ntoskrnl肯定是第一个
    PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

    DbgPrint("模块： %s 大小：%d", pMod->FullPathName, pMod->ImageSize);
    *ntoskrnlBase = pMod->ImageBase;
    *size = pMod->ImageSize;

    return true;
}


