#pragma once

#include "ntifs.h"
#include "ntddk.h"
#include "ntstrsafe.h"

NTSTATUS ReadFile(const WCHAR* path, PVOID* buffer, PULONG64 size);
