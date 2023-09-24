/************************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       csmlib.c
*  VERSION:     1.000
*  DATE:        24 September 2023
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
************************************************************************************/

#include <ntifs.h>
#include <ntstrsafe.h>
#include <intrin.h>

#include "csmlib.h"

#ifndef GUID_METHOD_IMPLEMENTED
#define CSM_OBJECT_FILE_PATH L"\\SystemRoot\\CsmObject.dat"
#else
// {8587DA8A-2086-481E-8FD3-3AD9F3971859}
DEFINE_GUID(CSM_LIBRARY_GUID, 0x8587da8a, 0x2086, 0x481e, 0x8f, 0xd3, 0x3a, 0xd9, 0xf3, 0x97, 0x18, 0x59);
#endif

#define CSM_DEBUG_PRINT(Format, ...)     KdPrint((Format, __VA_ARGS__))
#define CSM_DEBUG_PRINT_NTSTATUS(Status) CSM_DEBUG_PRINT("[!] Status: 0x%08X.\r\n\tFile: %hs.\r\n\tLine: %d.", Status, __FILE__, __LINE__)

DECLSPEC_ALIGN(PAGE_SIZE) typedef struct _CSM_OBJECT_CONTEXT {
	NTSTATUS Status;
	ULONG Instruction;
	SIZE_T BufferSize;
	UCHAR Data[1];
} CSM_OBJECT_CONTEXT, * PCSM_OBJECT_CONTEXT;

typedef struct _CSM_HANDLE_CONTEXT {
	PCSM_PRE_CALLBACK PreCallback;
	PCSM_POST_CALLBACK PostCallback;
	PCSM_DISPATCH_CALLBACK DispatchCallback;
	LONG Running;
	PETHREAD Thread;
	PVOID BaseAddress;
	PMDL Mdl;
	PCSM_OBJECT_CONTEXT Object;
	PKEVENT Event;
} CSM_HANDLE_CONTEXT, * PCSM_HANDLE_CONTEXT;

FORCEINLINE PVOID CsmAllocateMemory(_In_ SIZE_T NumberOfBytes)
{
	PVOID Pointer = NULL;
	while ( Pointer == NULL )
		Pointer = ExAllocatePool2(POOL_FLAG_NON_PAGED, NumberOfBytes, ' MSC');
	return Pointer;
}

#define CsmFreeMemory(Pointer) ExFreePoolWithTag(Pointer, ' MSC')

NTSTATUS CsmpProcessConnection(_In_ LPWSTR EventName, _Out_ PKEVENT* EventObject);
NTSTATUS CsmpOpenOrCreateObject(_Out_ PVOID* BaseAddress, _Out_ PSIZE_T ViewSize);
NTSTATUS CsmpCreateNewObject(_Inout_ PCSM_HANDLE_CONTEXT Context);
NTSTATUS CsmpReleaseObject(_In_ PCSM_HANDLE_CONTEXT Context);
NTSTATUS CsmpRegisterNewObject(_Inout_ PCSM_HANDLE_CONTEXT Context);
NTSTATUS CsmpRegisterCallback(_Inout_ PCSM_HANDLE_CONTEXT Context, _In_ PCSM_DISPATCH_CALLBACK DispatchCallback, _In_opt_ PCSM_PRE_CALLBACK PreCallback, _In_opt_ PCSM_POST_CALLBACK PostCallback);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, CsmRegisterCallback)
#pragma alloc_text(PAGE, CsmUnregisterCallback)
#pragma alloc_text(PAGE, CsmpProcessConnection)
#pragma alloc_text(PAGE, CsmpOpenOrCreateObject)
#pragma alloc_text(PAGE, CsmpCreateNewObject)
#pragma alloc_text(PAGE, CsmpReleaseObject)
#pragma alloc_text(PAGE, CsmpRegisterNewObject)
#pragma alloc_text(PAGE, CsmpRegisterCallback)
#endif

// ================================================================================================================================
// Main Worker - Non-Paged Function.
// ================================================================================================================================

NTSTATUS CsmConnectionWorker(_In_ PCSM_HANDLE_CONTEXT Context)
{
	NTSTATUS Status;
	LARGE_INTEGER Timeout;
	LONG PrevState;
	PKEVENT Event;
	PCSM_OBJECT_CONTEXT Object;
	ASSERT(Context != NULL);

	Event = Context->Event;
	Object = Context->Object;
	ASSERT(Object != NULL);
	ASSERT(Event != NULL);

	Status = STATUS_SUCCESS;
	Timeout.QuadPart = -3'000'000'000LL; // 5 minutes 

	PrevState = KeSetEvent(Event, IO_NO_INCREMENT, TRUE);

	do {
		Status = KeWaitForSingleObject(Event, UserRequest, KernelMode, FALSE, &Timeout);
		if ( Status == STATUS_SUCCESS ) {
			ASSERT(&Object->Status != NULL);
			ASSERT(Context->DispatchCallback != NULL);

			Object->Status = Context->DispatchCallback(Object->Instruction, Object->Data, Object->BufferSize);

			PrevState = KeSetEvent(Event, IO_NO_INCREMENT, TRUE);
		}
	} while ( Status != STATUS_TIMEOUT && Context->Running == TRUE );

	PrevState = KeSetEvent(Event, IO_NO_INCREMENT, TRUE);
	return Status;
}

VOID CsmThreadWorker(_In_ PCSM_HANDLE_CONTEXT Context)
{
	NTSTATUS Status;
	LARGE_INTEGER TimeInterval;
	WCHAR EventNameSafe[MAXUCHAR];

	ASSERT(Context != NULL);

	Status = STATUS_SUCCESS;

	if ARGUMENT_PRESENT(Context->PreCallback)
	{
		ASSERT(Context->PreCallback != NULL);
		Status = Context->PreCallback(PsGetCurrentThreadId(), PsGetCurrentThread());

		if NT_ERROR(Status)
		{
			CSM_DEBUG_PRINT_NTSTATUS(Status);
			PsTerminateSystemThread(Status);
			return;
		}
	}

	TimeInterval.QuadPart = -1000'0000; // 1 seconds.

	do {
		if ( Context->Object->Status == STATUS_SUCCESS || Context->Object->Status != STATUS_WAIT_1 ) {
			KeDelayExecutionThread(KernelMode, FALSE, &TimeInterval);
			continue;
		}

		Status = RtlStringCchCopyW(EventNameSafe, MAXUCHAR, (LPWSTR)Context->Object->Data);
		if NT_ERROR(Status)
		{
			Context->Object->Status = STATUS_SUCCESS;

			CSM_DEBUG_PRINT_NTSTATUS(Status);
			continue;
		}

		Status = CsmpProcessConnection(EventNameSafe, &Context->Event);
		RtlSecureZeroMemory(EventNameSafe, MAXUCHAR);

		if NT_SUCCESS(Status)
		{
			Status = CsmConnectionWorker(Context);
			ObDereferenceObject(Context->Event);
		}

	} while ( Context->Running == TRUE );

	if ARGUMENT_PRESENT(Context->PostCallback)
	{
		ASSERT(Context->PostCallback != NULL);
		Status = Context->PostCallback(PsGetCurrentThreadId(), PsGetCurrentThread());
	}

	PsTerminateSystemThread(Status);
	return;
}

// ================================================================================================================================
// Private Function.
// ================================================================================================================================

NTSTATUS CsmpProcessConnection(_In_ LPWSTR EventName, _Out_ PKEVENT* EventObject)
{
	NTSTATUS Status;
	HANDLE EventHandle;
	OBJECT_ATTRIBUTES ObjectAttributes;
	UNICODE_STRING UnicodeString;
	PAGED_CODE();

	ASSERT(EventObject != NULL);
	*EventObject = NULL;

	RtlInitUnicodeString(&UnicodeString, EventName);
	InitializeObjectAttributes(&ObjectAttributes, &UnicodeString, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	Status = ZwOpenEvent(&EventHandle, EVENT_ALL_ACCESS, &ObjectAttributes);

	if NT_ERROR(Status)
	{
		CSM_DEBUG_PRINT_NTSTATUS(Status);
		return Status;
	}

	Status = ObReferenceObjectByHandle(EventHandle, EVENT_ALL_ACCESS, NULL, KernelMode, EventObject, NULL);
	ZwClose(EventHandle);

	if NT_ERROR(Status)
	{
		CSM_DEBUG_PRINT_NTSTATUS(Status);
		return Status;
	}

	return Status;
}

NTSTATUS CsmpOpenOrCreateObject(_Out_ PVOID* BaseAddress, _Out_ PSIZE_T ViewSize)
{
	UNICODE_STRING UnicodeString;
	OBJECT_ATTRIBUTES ObjectAttributes;
	NTSTATUS Status;
	HANDLE SectionHandle;
	LARGE_INTEGER AllocationSize;
	HANDLE FileHandle;
	IO_STATUS_BLOCK IoStatus;
	PAGED_CODE();

	ASSERT(BaseAddress != NULL);
	ASSERT(ViewSize != NULL);
	*BaseAddress = NULL;
	*ViewSize = 0;

	AllocationSize.QuadPart = sizeof(CSM_OBJECT_CONTEXT);

	RtlInitUnicodeString(&UnicodeString, CSM_OBJECT_FILE_PATH);
	InitializeObjectAttributes(&ObjectAttributes, &UnicodeString, (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), NULL, NULL);
	Status = ZwCreateFile(&FileHandle, FILE_ALL_ACCESS, &ObjectAttributes, &IoStatus, &AllocationSize, FILE_ATTRIBUTE_NORMAL, (FILE_SHARE_READ | FILE_SHARE_WRITE), FILE_SUPERSEDE, FILE_NON_DIRECTORY_FILE, NULL, 0);

	if NT_ERROR(Status)
	{
		CSM_DEBUG_PRINT_NTSTATUS(Status);
		return Status;
	}

	InitializeObjectAttributes(&ObjectAttributes, NULL, (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), NULL, NULL);
	Status = ZwCreateSection(&SectionHandle, SECTION_ALL_ACCESS, &ObjectAttributes, &AllocationSize, PAGE_READWRITE, SEC_RESERVE, FileHandle);

	if NT_ERROR(Status)
	{
		ZwClose(FileHandle);

		CSM_DEBUG_PRINT_NTSTATUS(Status);
		return Status;
	}

	Status = ZwMapViewOfSection(SectionHandle, NtCurrentProcess(), BaseAddress, 0, 0, NULL, ViewSize, ViewUnmap, 0, PAGE_READWRITE);

	ZwClose(SectionHandle);
	ZwClose(FileHandle);
	return Status;
}

NTSTATUS CsmpReleaseObject(_In_ PCSM_HANDLE_CONTEXT Context)
{
	NTSTATUS Status;
	UNICODE_STRING UnicodeString;
	OBJECT_ATTRIBUTES ObjectAttributes;
	PAGED_CODE();

	RtlSecureZeroMemory(Context->Object, sizeof(CSM_OBJECT_CONTEXT));
	MmUnmapLockedPages(Context->Object, Context->Mdl);
	MmUnlockPages(Context->Mdl);
	IoFreeMdl(Context->Mdl);
	Status = ZwUnmapViewOfSection(NtCurrentProcess(), Context->BaseAddress);
	ASSERT(NT_SUCCESS(Status));

	RtlInitUnicodeString(&UnicodeString, CSM_OBJECT_FILE_PATH);
	InitializeObjectAttributes(&ObjectAttributes, &UnicodeString, (OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE), NULL, NULL);
	Status = ZwDeleteFile(&ObjectAttributes);
	ASSERT(NT_SUCCESS(Status));

	return Status;
}

NTSTATUS CsmpCreateNewObject(_Inout_ PCSM_HANDLE_CONTEXT Context)
{
	SIZE_T ViewSize;
	NTSTATUS Status;
	PVOID BaseAddress;
	PMDL Mdl;
	PVOID MapSection;
	PAGED_CODE();

	Status = CsmpOpenOrCreateObject(&BaseAddress, &ViewSize);
	if NT_ERROR(Status)
	{
		CSM_DEBUG_PRINT_NTSTATUS(Status);
		return Status;
	}

	Mdl = IoAllocateMdl(BaseAddress, (ULONG)ViewSize, FALSE, FALSE, NULL);
	if ( Mdl == NULL ) {
		Status = STATUS_NO_MEMORY;
		CSM_DEBUG_PRINT_NTSTATUS(Status);
		return Status;
	}

	MmProbeAndLockPages(Mdl, KernelMode, IoModifyAccess);
	MapSection = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);
	if ( MapSection == NULL ) {
		MmUnlockPages(Mdl);
		IoFreeMdl(Mdl);

		Status = STATUS_NO_MEMORY;
		CSM_DEBUG_PRINT_NTSTATUS(Status);
		return Status;
	}

	Context->BaseAddress = BaseAddress;
	Context->Object = MapSection;
	Context->Mdl = Mdl;
	RtlSecureZeroMemory(MapSection, ViewSize);
	return Status;
}

NTSTATUS CsmpRegisterNewObject(_Inout_ PCSM_HANDLE_CONTEXT Context)
{
	NTSTATUS Status;
	HANDLE ThreadHandle;
	PAGED_CODE();

	InterlockedExchange(&Context->Running, TRUE);
	ASSERT(Context->Running == TRUE);

	Status = CsmpCreateNewObject(Context);

	if NT_ERROR(Status)
	{
		CSM_DEBUG_PRINT_NTSTATUS(Status);
		return Status;
	}

	Status = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL, CsmThreadWorker, Context);

	if NT_ERROR(Status)
	{
		CsmpReleaseObject(Context);

		CSM_DEBUG_PRINT_NTSTATUS(Status);
		return Status;
	}

	Status = ObReferenceObjectByHandle(ThreadHandle, THREAD_ALL_ACCESS, NULL, KernelMode, &Context->Thread, NULL);
	ASSERT(NT_SUCCESS(Status));

	Status = ZwClose(ThreadHandle);
	ASSERT(NT_SUCCESS(Status));

	return Status;
}

NTSTATUS CsmpRegisterCallback(_Inout_ PCSM_HANDLE_CONTEXT Context, _In_ PCSM_DISPATCH_CALLBACK DispatchCallback, _In_opt_ PCSM_PRE_CALLBACK PreCallback, _In_opt_ PCSM_POST_CALLBACK PostCallback)
{
	ASSERT(Context != NULL);
	ASSERT(DispatchCallback != NULL);
	PAGED_CODE();

	Context->DispatchCallback = DispatchCallback;
	Context->PreCallback = PreCallback;
	Context->PostCallback = PostCallback;
	return CsmpRegisterNewObject(Context);
}

// ================================================================================================================================
// Public Function.
// ================================================================================================================================

NTSTATUS CsmRegisterCallback(_In_ PCSM_DISPATCH_CALLBACK DispatchCallback, _In_opt_ PCSM_PRE_CALLBACK PreCallback, _In_opt_ PCSM_POST_CALLBACK PostCallback, _Out_ PVOID* RegistrationHandle)
{
	NTSTATUS Status;
	PCSM_HANDLE_CONTEXT RegistrationContext;
	PAGED_CODE();

	*RegistrationHandle = NULL;
	RegistrationContext = CsmAllocateMemory(sizeof(CSM_HANDLE_CONTEXT));

	Status = CsmpRegisterCallback(RegistrationContext, DispatchCallback, PreCallback, PostCallback);

	if NT_ERROR(Status)
	{
		CsmFreeMemory(RegistrationHandle);
		CSM_DEBUG_PRINT_NTSTATUS(Status);
		return Status;
	}

	ASSERT(NT_SUCCESS(Status));
	*RegistrationHandle = (PVOID)_rotl64((ULONGLONG)RegistrationContext, MAXLONG);
	return Status;
}

NTSTATUS CsmUnregisterCallback(_In_ PVOID RegistrationHandle)
{
	NTSTATUS Status;
	PCSM_HANDLE_CONTEXT RegistrationContext;
	PAGED_CODE();

	RegistrationContext = (PVOID)_rotr64((ULONGLONG)RegistrationHandle, MAXLONG);
	if ( MmIsAddressValid(RegistrationContext) == FALSE ) {
		Status = STATUS_INVALID_PARAMETER;
		CSM_DEBUG_PRINT_NTSTATUS(Status);
		return Status;
	}

	CSM_DEBUG_PRINT("[!] Waiting for Worker Terminated completely.");
	InterlockedExchange(&RegistrationContext->Running, FALSE);
	Status = KeWaitForSingleObject(RegistrationContext->Thread, Executive, KernelMode, FALSE, NULL);
	ASSERT(NT_SUCCESS(Status));

	ObDereferenceObject(RegistrationContext->Thread);

	Status = CsmpReleaseObject(RegistrationContext);
	ASSERT(NT_SUCCESS(Status));

	CsmFreeMemory(RegistrationContext);
	return Status;
}
