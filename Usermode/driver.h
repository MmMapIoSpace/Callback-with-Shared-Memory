#pragma once

class CsmDriver {
public:

	BOOL LoadDriver();
	BOOL UnloadDriver();

	int CalculateForMe(int a, int b);
	__int64 GetMyProcess();

private:

	DECLSPEC_ALIGN(0x1000) typedef struct _CSM_OBJECT_CONTEXT {
		NTSTATUS Status;
		ULONG Instruction;
		SIZE_T BufferSize;
		UCHAR Data[1];
	} CSM_OBJECT_CONTEXT, * PCSM_OBJECT_CONTEXT;

	PCSM_OBJECT_CONTEXT Context;
	HANDLE EventHandle;

	BOOL DeviceControl(ULONG Instruction, PVOID Buffer, SIZE_T BufferSize);
};

inline int CsmDriver::CalculateForMe(int a, int b)
{
	struct { int a; int b; int c; }simple_math{ a,b,0 };
	DeviceControl(0/*Instruction to request Math calculation*/, &simple_math, sizeof(simple_math));
	return simple_math.c;
}

inline __int64 CsmDriver::GetMyProcess()
{
	struct { int procid; __int64 process; }request{ GetCurrentProcessId(),0 };
	DeviceControl(1 /*Instruction to request Process Object Address*/, &request, sizeof(request));
	return request.process;
}

inline BOOL CsmDriver::DeviceControl(ULONG Instruction, PVOID Buffer, SIZE_T BufferSize)
{
	if ( BufferSize > 0x1000 - 16 /*limit buffer size is only limited only to CSM_OBJECT_CONTEXT->Data / PAGE_SIZE*/ )
		return FALSE;

	Context->Instruction = Instruction;
	Context->BufferSize = BufferSize;
	Context->Status = STATUS_UNSUCCESSFUL;
	memcpy(Context->Data, Buffer, BufferSize);
	if ( SetEvent(EventHandle) ) {
		WaitForSingleObject(EventHandle, INFINITE);

		if ( Context->Status == STATUS_SUCCESS ) {
			memcpy(Buffer, Context->Data, BufferSize);
			return TRUE;
		}
	}

	return FALSE;
}

inline BOOL CsmDriver::LoadDriver()
{
	// TODO: Fix the path you want to place the buffer file.
	// and sync it with csmlib.c
	const auto file = CreateFileW(L"C:\\Windows\\CsmObject.dat", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if ( file == nullptr || file == INVALID_HANDLE_VALUE ) {
		printf("[!] make sure driver has been loaded.\n");
		return FALSE;
	}

	const auto section = CreateFileMappingW(file, NULL, PAGE_READWRITE, 0, 0, NULL);
	if ( section == nullptr || section == INVALID_HANDLE_VALUE ) {
		CloseHandle(file);

		printf("[!] failed creating mapping.\n");
		return FALSE;
	}

	Context = reinterpret_cast<PCSM_OBJECT_CONTEXT>(MapViewOfFile(section, FILE_MAP_ALL_ACCESS, 0, 0, 0));
	CloseHandle(section);
	CloseHandle(file);

	if ( Context != nullptr ) {
		wchar_t kernel_event_name[] = L"\\BaseNamedObjects\\csm-event";
		StringCbCopyW(reinterpret_cast<LPWSTR>(Context->Data), sizeof(kernel_event_name), kernel_event_name);
		EventHandle = CreateEventW(NULL, FALSE, FALSE, L"Global\\csm-event");

		if ( EventHandle != nullptr && EventHandle != INVALID_HANDLE_VALUE ) {
			if ( Context->Status == STATUS_SUCCESS ) {
				Context->Status = STATUS_WAIT_1;
				WaitForSingleObject(EventHandle, INFINITE);
				return TRUE;
			}
		}
		UnmapViewOfFile(Context);
	}

	return 0;
}

inline BOOL CsmDriver::UnloadDriver()
{
	// Just wait till the worker timeout hitted,
	// and they will signal if worker going to exit.
	WaitForSingleObject(EventHandle, INFINITE);
	CloseHandle(EventHandle);

	return UnmapViewOfFile(Context);
}
