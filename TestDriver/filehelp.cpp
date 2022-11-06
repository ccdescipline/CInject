#include "filehelp.h"

NTSTATUS ReadFile(const WCHAR* path, PVOID * buffer, PULONG64 size)
{
	OBJECT_ATTRIBUTES obj = { 0 };
	HANDLE readHandle = NULL;
	IO_STATUS_BLOCK ioStackblock = { 0 };

	UNICODE_STRING filepath = { 0 };
	RtlUnicodeStringInit(&filepath, path);

	//初始化OBJECT_ATTRIBUTES
	InitializeObjectAttributes(&obj, &filepath,
		OBJ_KERNEL_HANDLE|OBJ_CASE_INSENSITIVE,
		NULL,NULL
		);

	//创建一个handle

	NTSTATUS creafileStatus = ZwCreateFile(
		&readHandle,	//文件句柄
		GENERIC_READ,   //读权限
		&obj,			//初始化的OBJECT_ATTRIBUTES
		&ioStackblock,	//该结构接收最终完成状态和有关所请求操作的其他信息
		NULL,			//创建或覆盖的文件的初始分配大小（以字节为单位）
		FILE_ATTRIBUTE_NORMAL,	//这些标志表示在创建或覆盖文件时要设置的文件属性
		FILE_SHARE_READ,		//共享权限
		FILE_OPEN_IF,			//指定在文件存在或不存在时要执行的操作
		FILE_NON_DIRECTORY_FILE | FILE_RANDOM_ACCESS | FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0
	);

	if (!NT_SUCCESS(creafileStatus)) {
		DbgPrint("ZwCreateFile失败");
		return STATUS_UNSUCCESSFUL;
	}

	//读取文件长度
	FILE_STANDARD_INFORMATION fsi = {0};
	NTSTATUS QueryInformationStatus = ZwQueryInformationFile(readHandle,
		&ioStackblock,
		&fsi,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);

	if (!NT_SUCCESS(QueryInformationStatus)) {
		DbgPrint("ZwQueryInformationFile 获取文件大小失败");
		return STATUS_UNSUCCESSFUL;
	}

	//申请缓冲区
	SIZE_T filesize = (LONG)fsi.EndOfFile.QuadPart;
	PVOID filebuffer = ExAllocatePool(NonPagedPool, filesize);
	memset(filebuffer,0, filesize);


	NTSTATUS ReadFilestatus =  ZwReadFile(
		readHandle,		//文件句柄
		NULL,NULL,NULL,
		&ioStackblock,	//该结构接收最终完成状态和有关所请求的读取操作的信息
		filebuffer,	//缓冲区
		filesize,	//大小
		NULL,
		0
	);

	if (!NT_SUCCESS(ReadFilestatus)) {
		DbgPrint("ZwReadFile 失败");
		return STATUS_UNSUCCESSFUL;
	}

	*buffer = filebuffer;
	*size = filesize;

	ZwClose(readHandle);

	return STATUS_SUCCESS;
}
