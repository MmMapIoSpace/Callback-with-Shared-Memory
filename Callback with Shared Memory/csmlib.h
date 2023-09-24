#pragma once

#ifndef CSMLIB_H
#define CSMLIB_H

_Function_class_(CSM_PRE_CALLBACK)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
typedef
NTSTATUS
CSM_PRE_CALLBACK(
	_In_ HANDLE ThreadId,
	_In_ PETHREAD Thread
);

_Function_class_(CSM_POST_CALLBACK)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
typedef
NTSTATUS
CSM_POST_CALLBACK(
	_In_ HANDLE ThreadId,
	_In_ PETHREAD Thread
);

_Function_class_(CSM_DISPATCH_CALLBACK)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
typedef
NTSTATUS
CSM_DISPATCH_CALLBACK(
	_In_ ULONG Instruction,
	_In_reads_bytes_(BufferSize) PVOID Buffer,
	_In_ SIZE_T BufferSize
);

typedef CSM_PRE_CALLBACK* PCSM_PRE_CALLBACK;
typedef CSM_POST_CALLBACK* PCSM_POST_CALLBACK;
typedef CSM_DISPATCH_CALLBACK* PCSM_DISPATCH_CALLBACK;

#ifdef __cplusplus
extern "C" {
#endif

	NTSTATUS CsmRegisterCallback(_In_ PCSM_DISPATCH_CALLBACK DispatchCallback, _In_opt_ PCSM_PRE_CALLBACK PreCallback, _In_opt_ PCSM_POST_CALLBACK PostCallback, _Out_ PVOID* RegistrationHandle);
	NTSTATUS CsmUnregisterCallback(_In_ PVOID RegistrationHandle);

#ifdef __cplusplus
}
#endif

#endif
