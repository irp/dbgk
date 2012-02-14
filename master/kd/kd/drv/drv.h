#ifndef __DRV_H__
#define __DRV_H__

#include <fltKernel.h>
#include <dontuse.h>
#include <ntddk.h>
#include <str.h>
#include <suppress.h>

typedef struct S{

	PDRIVER_OBJECT DriverObject;
	PFLT_FILTER filter;
	PFLT_PORT ServerPort;
	PFLT_PORT ClientPort;

}S, *PS; S s;

const _FLT_CONTEXT_REGISTRATION ContextRegistration[] = {

    { FLT_STREAMHANDLE_CONTEXT, 0, NULL, MAXUSHORT, 'dump' },
    { FLT_CONTEXT_END }

};

extern "C" VOID NTAPI FilterUnload
	(__in PDRIVER_OBJECT pDriverObject);

extern "C" NTSTATUS NTAPI DriverEntry 
	(__in PDRIVER_OBJECT pDriverObject,
	 __in PUNICODE_STRING pRegistryPath);

extern "C" NTSTATUS NTAPI ConnectNotifyCallback
	( __in PFLT_PORT ClientPort,
      __in PVOID ServerPortCookie,
      __in PVOID ConnectionContext,
      __in ULONG SizeOfContext,
      __out PVOID *ConnectionPortCookie);

extern "C" VOID NTAPI DisconnectNotifyCallback
	(__in_opt PVOID ConnectionCookie);

extern "C" NTSTATUS NTAPI MessageNotifyCallback
	(__in PVOID ConnectionCookie,
     __in PVOID InputBuffer,
     __in ULONG InputBufferSize,
     __out PULONG OutputBuffer,
     __in ULONG OutputBufferSize,
     __out PULONG ReturnOutputBufferLength);

const _FLT_OPERATION_REGISTRATION  OperationRegistration[] = {

	{ IRP_MJ_CREATE, 0, NULL, 0 },
    { IRP_MJ_WRITE, 0, NULL, 0 },
    { IRP_MJ_READ, 0, NULL, 0 },
    { IRP_MJ_OPERATION_END }
	
};

const _FLT_REGISTRATION FilterRegistration = {

    sizeof(FLT_REGISTRATION),         
    FLT_REGISTRATION_VERSION,           
    0,                                   
    ContextRegistration,                 
    OperationRegistration,                         
    (PFLT_FILTER_UNLOAD_CALLBACK)FilterUnload,                                    
    NULL, NULL, NULL, NULL, NULL, NULL, NULL       

};

#endif