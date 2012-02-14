#include <ntifs.h>
#include <fltKernel.h>
//#include <ndk\kdfuncs.h>
#include <str.h>
#include <drv.h>
/*
#include <ntddk.h>
#include <ndk\kdfuncs.h>
#include <fltKernel.h>
#include <ntifs.h>
*/
#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Controllo PREfast non valido per filter driver")

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, FilterUnload)
/*
#pragma alloc_text(PAGE, ConnectNotifyCallback)
#pragma alloc_text(PAGE, DisconnectNotifyCallback)
#pragma alloc_text(PAGE, MessageNotifyCallback)
*/
#pragma alloc_text(PAGE, SetPrivateCommunication)
#pragma alloc_text(PAGE, DeletePrivateCommunication)
#pragma alloc_text(PAGE, MjFunction)

#endif

#define KD_PRIVATE_CONTROL L"\\FileSystem\\Filters\\kd"

extern "C" NTSTATUS NTAPI DriverEntry 
	(__in PDRIVER_OBJECT pDriverObject,
	 __in PUNICODE_STRING pRegistryPath) {

		 //UNICODE_STRING uniS;
		 //PCWSTR portName;
		 //OBJECT_ATTRIBUTES InitializedAttributes;
         UNICODE_STRING ObjectName;
         //PSECURITY_DESCRIPTOR SecurityDescriptor;
		 NTSTATUS ntstatus;

		__try {

			 s.DriverObject = pDriverObject;
		     ntstatus = FltRegisterFilter(pDriverObject, &FilterRegistration, &s.filter);
			 RtlInitUnicodeString(&ObjectName, KD_PRIVATE_CONTROL);
			 /*
		     ntstatus = FltBuildDefaultSecurityDescriptor(&SecurityDescriptor, FLT_PORT_ALL_ACCESS);
             

		     InitializeObjectAttributes(&InitializedAttributes, &ObjectName,
								       OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,  
								       NULL,  SecurityDescriptor);

		     ntstatus = FltCreateCommunicationPort(s.filter, &s.ServerPort,   
											       &InitializedAttributes, NULL, 
												   ConnectNotifyCallback, DisconnectNotifyCallback, 
												   (PFLT_MESSAGE_NOTIFY)MessageNotifyCallback, 1);

	         FltFreeSecurityDescriptor(SecurityDescriptor);  	
			 */
			 ntstatus = SetPrivateCommunication(pDriverObject, ObjectName);
		     ntstatus = FltStartFiltering(s.filter);

		 }

		 __finally {

            if (!NT_SUCCESS(ntstatus)) {
				/*
                if (s.ServerPort != NULL) {
                    FltCloseCommunicationPort(s.ServerPort);
                } */
                if (s.filter != NULL) {
                    FltUnregisterFilter(s.filter);
					ClosePrivateCommunication();
                } 
            }
         }

		 return ntstatus; 
}

extern "C" VOID NTAPI FilterUnload
	(__in PDRIVER_OBJECT pDriverObject) {

		PAGED_CODE();
		FltCloseCommunicationPort(s.ServerPort);
		FltUnregisterFilter(s.filter);
}

/*
extern "C" NTSTATUS NTAPI ConnectNotifyCallback
	( __in PFLT_PORT ClientPort,
      __in PVOID ServerPortCookie,
      __in PVOID ConnectionContext,
      __in ULONG SizeOfContext,
      __out PVOID *ConnectionPortCookie) { 
	
		  PAGED_CODE();

		  ASSERT(s.ClientPort == NULL);
		  s.ClientPort = ClientPort;

		  return STATUS_SUCCESS;
}

extern "C" VOID NTAPI DisconnectNotifyCallback
	(__in_opt PVOID ConnectionCookie) {

		PAGED_CODE();

		FltCloseClientPort(s.filter, &s.ClientPort);

}

extern "C" NTSTATUS NTAPI MessageNotifyCallback
    (__in PVOID ConnectionCookie,
     __in PVOID InputBuffer,
     __in ULONG InputBufferSize,
     __out PULONG OutputBuffer,
     __in ULONG OutputBufferSize,
     __out PULONG ReturnOutputBufferLength) {

		STRUCT_COMMAND command;
		NTSTATUS ntstatus;
		KPROCESSOR_MODE PreviousMode;

		PAGED_CODE();

		DbgPrint("FltSendMessage() received\n");

		if(InputBuffer != NULL) {

			__try {
				command = ((PCOMMAND_MESSAGE)InputBuffer)->Command; }
		    __except(EXCEPTION_EXECUTE_HANDLER) {
            return GetExceptionCode(); }

			switch(command) {
			case about:
				DbgPrint("Calling KdSystemDebugControl\n");
		/*		PreviousMode = ExGetPreviousMode();
				ntstatus = KdSystemDebugControl(SysDbgEnableKernelDebugger, NULL, 0,
					                            NULL, 0, NULL, PreviousMode);
				if (!NT_SUCCESS(ntstatus)) DbgPrint("ntstatus %d\n", ntstatus);
				DbgPrint("KernelDebugger Enabled\n"); */
	/*			break;

			default:
				DbgPrint("Default\n");
				break;

			} 
		}
		else {

			DbgPrint("No input buffer!\n");
			ntstatus = STATUS_INVALID_PARAMETER; 
		}

		return ntstatus;

}
*/
extern "C" NTSTATUS NTAPI SetPrivateCommunication
	(__in PDRIVER_OBJECT pDriverObject,
	 __in UNICODE_STRING ControlDevice) {

		 NTSTATUS ntstatus;
		 int i;

		 PAGED_CODE();

		 ntstatus = IoCreateDevice(pDriverObject, 0, &ControlDevice, 
			                       FILE_DEVICE_DISK_FILE_SYSTEM,
                                   FILE_DEVICE_SECURE_OPEN,
								   FALSE, &s.DeviceObject);
		 if(!NT_SUCCESS(ntstatus)) {
			 DbgPrint("IoCreateDevice failed!\n");
			 return ntstatus;
		 }

		 for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
			 pDriverObject->MajorFunction[i] = MjFunction;
		 }

		 return ntstatus;

}

extern "C" VOID NTAPI DeletePrivateCommunication
	() {

		PAGED_CODE();
		IoDeleteDevice(s.DeviceObject);

}

extern "C" NTSTATUS NTAPI MjFunction
	(__in PDEVICE_OBJECT pDeviceObj,
	 __in PIRP pIrp) {

		 PIO_STACK_LOCATION pCurrStack;
		 NTSTATUS ntstatus = STATUS_SUCCESS;

		 /* driver specific informations for the io operation via i/o stack location */
		 pCurrStack = IoGetCurrentIrpStackLocation(pIrp);

		 ASSERT(pCurrStack);
		 ASSERT(pCurrStack->FileObject);
		 
		 /* going to set the dispatch routines for major functions coming with IRPs */
		 switch (pCurrStack->MajorFunction) {

		 default:
			 pIrp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
             pIrp->IoStatus.Information = 0;
			 /* no handling (STATUS_INVALID_DEVICE_REQUEST), 
			 so the thread does not have to wait IO_NO_INCREMENT */
             IoCompleteRequest(pIrp, IO_NO_INCREMENT);
             ntstatus = STATUS_INVALID_DEVICE_REQUEST;

		 }

		 return ntstatus;

}

