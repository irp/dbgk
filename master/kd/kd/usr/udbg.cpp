
#define WIN32_NO_STATUS
#include <Windows.h>
#include <ntndk.h>
#include <winioctl.h>
#include <fltUser.h>
#include <stdio.h>
#include <tchar.h>
#include <str.h>
/*
char ar, as;
char command[257];
char *pComm[40];

extern "C" BOOL NTAPI GetCommLine
	( );
extern "C" VOID NTAPI InterComm
	(__in int argc,
	 __in char *argv[]);
VOID NTAPI CommandAbout
	(__in LPVOID lpParameter);

typedef struct _P_CONTEXT {

    HANDLE Port;

}P_CONTEXT, *PP_CONTEXT; P_CONTEXT Context;

extern "C" BOOL NTAPI GetCommLine
	() {

		LONG pCommSize = 0, commandSize;
		BOOL stat;

		while (ar = (char)getchar()) {
			if (ar == '\n') {

				   printf("> ");
				       
				       for (commandSize = 0; 
						    (commandSize < 257) && ((as = (char)getchar()) != '\n'); 
							commandSize++) {

								command[commandSize] = as;

								if (commandSize >= 40) break;

								if (as == ' ') {
									command[commandSize] = 0;
								}

								if (as != ' ') {
									pComm[pCommSize++] = &command[commandSize];
								}

				       }
					   command[commandSize] = '\0';
					   InterComm(commandSize, pComm);

				  
		      }
		 }

		return TRUE;
}

extern "C" VOID NTAPI InterComm
	(__in int argc,
	 __in char *argv[]) {

		 LONG index, i, j;
		 HANDLE hThread;
		 ULONG threadID;

		 for (index = 0; index < argc; index++) {	 
			 if (argv[index][0] == '/') {
				 switch(argv[index][1]) {
				 case 'a':
					 printf("About\n");
					 hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&CommandAbout,
							                (LPVOID)&Context, 0, &threadID);
					 CloseHandle(hThread);
					 break;

				 default:
					 break;
				 }
			 }
		 }

}

VOID NTAPI CommandAbout
	(__in LPVOID lpParameter) {

		PVOID aligned[4096/sizeof(PVOID)];
		PULONG buf = (PULONG) aligned;
		HRESULT hResult;
		COMMAND_MESSAGE commandFilter;
		DWORD bytesReturned;

		commandFilter.Command = about;
		hResult = FilterSendMessage(Context.Port, &commandFilter.Command, sizeof(COMMAND_MESSAGE),
									buf, sizeof(aligned), &bytesReturned);
		printf("Bytes returned: %d\n", bytesReturned);

		if (hResult != S_OK) printf("ERROR: FilterSend failed %08x\n", hResult);

} */

BOOL NTAPI SetPrivilege
	(TCHAR *Privilege) {

		HANDLE hTok;
		LUID luid;
		TOKEN_PRIVILEGES TokenPriv;
		BOOL value;

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hTok)) {
			printf("ERROR: Failed to open the access token\n");
			return FALSE;
		}

		if (!LookupPrivilegeValue(NULL, Privilege, &luid)) {
			printf("ERROR: Failed to retrive LUID\n");
			CloseHandle(hTok);
			return FALSE;
		}

		ZeroMemory (&TokenPriv, sizeof(TokenPriv));
		TokenPriv.PrivilegeCount = 1; //entries
		TokenPriv.Privileges[0].Luid = luid; //LUID
		TokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; //attributes of LUID

		value = AdjustTokenPrivileges(hTok, FALSE, &TokenPriv, 
			                          sizeof(TokenPriv), NULL, NULL);

		if (!value) printf("ERROR: Cannot set privileges for the specified access token\n");

	    CloseHandle(hTok);
		return value;
		
}

BOOL NTAPI InitService
	(LPCTSTR lpService) {
	SC_HANDLE hMgr, hServ;
	BOOL value;
	DWORD er;

	hMgr = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (hMgr == NULL) {
		printf("ERROR: OpenSCMgr failed with code: %d\n", GetLastError());
		return FALSE;
	}
	
	hServ = OpenService(hMgr, lpService, SERVICE_START);
	if (hServ == NULL) {
	 	printf("ERROR: OpenService failed with code: %d\n", GetLastError());
	 	CloseServiceHandle(hMgr);
	 	return FALSE;
	}		
	
	value = StartService(hServ, 0, NULL);
	er = GetLastError();
	if (value == FALSE && er != ERROR_SERVICE_ALREADY_RUNNING) {
		printf("ERROR: StartService failed with code: %d\n", GetLastError());
	 	CloseServiceHandle(hServ);
	 	CloseServiceHandle(hMgr);
	 	return FALSE;
	}
	
	CloseServiceHandle(hServ);
	CloseServiceHandle(hMgr);
	return TRUE;
}

typedef struct _KD {

	SYSDBG_COMMAND DebugCommand;
	//PVOID Command;
	//DWORD CommandLength; 

}KD, *PKD;

BOOL NTAPI ConnectWithSystemDebug
	(__in HANDLE hDevice) {

		KD kd;
		kd.DebugCommand = SysDbgEnableKernelDebugger;
		//kd.Command = ;
		//kd.CommandLength = 0;

		if (!DeviceIoControl(hDevice, 0x22C007, &kd, sizeof(kd), 
			                 NULL, 0, NULL, NULL)) {
								 printf("ERROR: DeviceIoControl failed %d\n", GetLastError());
								 return FALSE;
		}

		printf("Kernel Debugging enabled!\n");
		return TRUE;

}

#define FILTER_NAME       L"\\\\.\\kd"
#define SERVICE_NAME      "kd"
#define PRIVILEGE         _T("SeDebugPrivilege")

int _cdecl main 
	(__in int argc,
     __in char *argv[]) {

		 HRESULT hResult;
		 HANDLE hDevice;
		 BOOL value;
		 
		 printf("Welcome to the communication interface between kdbg.sys and user prompt\n");

		 if (!SetPrivilege(PRIVILEGE)) {
			 printf("ERROR: SetPrivilege failed\n");
		 }

		 if (!InitService(SERVICE_NAME)) {
			 printf("ERROR: InitService failed\n");
		 }

		 hDevice = CreateFileW(FILTER_NAME, GENERIC_READ|GENERIC_WRITE,                
				               FILE_SHARE_READ|FILE_SHARE_WRITE, NULL,             
				               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		 if (hDevice == INVALID_HANDLE_VALUE) {
			 printf("ERROR: CreateFileW failed %d\n", GetLastError());
		 }

		 value = ConnectWithSystemDebug(hDevice);
		 if (value == FALSE) printf("ERROR: ConnectWithSystemDebug failed\n");
	/*	 hResult = FilterConnectCommunicationPort(KD_PORT_NAME, 0, NULL,
									              0, NULL, &Context.Port);
		 if (hResult != S_OK) printf("ERROR: FilterConnect failed\n"); 
		 GetCommLine(); */

		 int c = getchar();
		 return 0;

}