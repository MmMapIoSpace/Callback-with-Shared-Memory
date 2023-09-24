#include <ntifs.h>
#include <ntstrsafe.h>
#include <intrin.h>

#include "csmlib.h"

CSM_PRE_CALLBACK DriverPreCallback;
CSM_POST_CALLBACK DriverPostCallback;
CSM_DISPATCH_CALLBACK DriverDispatchCallback;
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

PVOID CallbackHandle;

NTSTATUS DriverPreCallback(_In_ HANDLE ThreadId, _In_ PETHREAD Thread)
{
	RTL_OSVERSIONINFOW WinVer;
	ULONGLONG CurrentThread;
	ULONGLONG CurrentProcess;
	KIRQL Irql;

	UNREFERENCED_PARAMETER(ThreadId);
	UNREFERENCED_PARAMETER(Thread);

	CurrentThread = (ULONGLONG)Thread;
	CurrentProcess = (ULONGLONG)PsGetCurrentProcess();

	//
	// TODO: do your thread bypass here.
	//

	DbgPrint("[+] DriverPreCallback.");
	if ( NT_SUCCESS(RtlGetVersion(&WinVer)) && WinVer.dwBuildNumber == 22621 ) {
		DbgPrint("[+] Build Version: %u.", WinVer.dwBuildNumber);

#pragma warning(push)
#pragma warning(disable:4047 4024)// Let's cast to any type.
		InterlockedDecrement(CurrentProcess + 0x5f0);
		*(PNTSTATUS)(CurrentProcess + 0x5fc) = STATUS_SUCCESS;
		*(PNTSTATUS)(CurrentThread + 0x598) = STATUS_SUCCESS;
		KeQuerySystemTime(CurrentThread + 0x488);

		KeAcquireSpinLock(CurrentThread + 0x4b0, &Irql);
		ExAcquirePushLockShared(CurrentThread + 0x550);

		RemoveEntryList(CurrentThread + 0x538);

		ExReleasePushLockShared(CurrentThread + 0x550);
		KeReleaseSpinLock(CurrentThread + 0x4b0, Irql);
#pragma warning(pop)

		DbgPrint("[+] Thread has been hidden from process list.");
	}

	return STATUS_SUCCESS;
}

NTSTATUS DriverPostCallback(_In_ HANDLE ThreadId, _In_ PETHREAD Thread)
{
	RTL_OSVERSIONINFOW WinVer;
	KIRQL Irql;
	ULONGLONG CurrentThread;
	ULONGLONG CurrentProcess;
	UNREFERENCED_PARAMETER(ThreadId);
	UNREFERENCED_PARAMETER(Thread);

	//
	// TODO: restore your thread bypass before thread terminated.
	//

	CurrentThread = (ULONGLONG)Thread;
	CurrentProcess = (ULONGLONG)PsGetCurrentProcess();

	DbgPrint("[+] DriverPostCallback.");
	if ( NT_SUCCESS(RtlGetVersion(&WinVer)) && WinVer.dwBuildNumber == 22621 ) {
		DbgPrint("[+] Build Version: %u.", WinVer.dwBuildNumber);

#pragma warning(push)
#pragma warning(disable:4047 4024)// Let's cast to any type.
		KeAcquireSpinLock(CurrentThread + 0x4b0, &Irql);
		ExAcquirePushLockShared(CurrentThread + 0x550);

		InterlockedIncrement(CurrentProcess + 0x5f0);
		InsertTailList(CurrentProcess + 0x5e0, CurrentThread + 0x538);

		ExReleasePushLockShared(CurrentThread + 0x550);
		KeReleaseSpinLock(CurrentThread + 0x4b0, Irql);
#pragma warning(pop)
		DbgPrint("[+] Thread has been restored to process list.");
	}

	return STATUS_SUCCESS;
}

NTSTATUS DriverDispatchCallback(_In_ ULONG Instruction, _In_reads_bytes_(BufferSize) PVOID Buffer, _In_ SIZE_T BufferSize)
{
	NTSTATUS Status;

	Status = STATUS_INFO_LENGTH_MISMATCH;
	switch ( Instruction ) {
	case 0:
	{
		struct { int a; int b; int c; }*data;
		if ( BufferSize == sizeof(*data) ) {
			data = Buffer;
			data->c = data->a + data->b;
			Status = STATUS_SUCCESS;
		}
	} break;

	case 1:
	{
		struct { int procid; __int64 process; }*data;
		if ( BufferSize == sizeof(*data) ) {
			data = Buffer;
			Status = PsLookupProcessByProcessId((HANDLE)data->procid, (PEPROCESS*)&data->process);
			if NT_SUCCESS(Status)
				ObDereferenceObject((PEPROCESS)data->process);
		}
	} break;

	default:
	Status = STATUS_INVALID_PARAMETER;
	break;
	}

	DbgPrint("[+] DriverDispatchCallback.");
	DbgPrint("[+] Instruction: 0x%08X.", Instruction);
	DbgPrint("[+] BufferSize: %llu.", BufferSize);
	DbgPrint("[+] Buffer: 0x%016p.", Buffer);
	DbgPrint("[+] Dispatching Result: 0x%08X.", Status);
	return Status;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = DriverUnload;
	DbgPrint("[+] Driver Loaded.");
	return CsmRegisterCallback(DriverDispatchCallback, DriverPreCallback, DriverPostCallback, &CallbackHandle);
}

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	CsmUnregisterCallback(CallbackHandle);
	DbgPrint("[+] Driver Unloaded.");
}