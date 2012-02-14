#define DBGHELP_TRANSLATE_TCHAR

#include <Windows.h>
#include <DbgHelp.h>
#include <Psapi.h>
#include <stdio.h>
#include <tchar.h>
//#include "disasm.h"
#include "disa.h"
#include "comm.h"

CONTEXT Context;
STACKFRAME StackFrame;
DEBUG_EVENT dbgEvent = { 0 };
MEMORY_BASIC_INFORMATION lpBuffer;
DWORD nameLen, moduleBase;
PPONTE pPonte;

LPVOID ImgBase;
PBYTE firstB;
PBYTE excOp;

int modCount = 0;
BOOL iBp = FALSE;

BYTE inst, original;

struct mod {
	HANDLE hFile;
	HMODULE hModule;
	LPVOID LoadAddress;
	TCHAR ModuleName[MAX_PATH];
	BOOL SymLoaded;
};

typedef struct procInfo {
	HANDLE hFile;
};

procInfo process[1];
mod modules[1000];
BOOL IsSymLoaded = FALSE;


/*            BP                      */


extern "C" VOID NTAPI SetBpOnTar
	(__in PBYTE pTar,
	 __in HANDLE hProcess) {

		DWORD oldPro, readB;

		//printf("BP: Setting WRITE access on the first byte target.\n");
		if (!VirtualProtectEx(hProcess, pTar, 0x1000, PAGE_EXECUTE_READWRITE, &oldPro)) printf("BP ERROR: VPEx failed: %d\n", GetLastError());
		ReadProcessMemory(hProcess, pTar, &inst, 1, &readB); 
		original = inst;
		inst = 0xcc;
		WriteProcessMemory(hProcess, pTar, &inst, 1, &readB); 
		if (!FlushInstructionCache(hProcess, pTar, 1)) printf("BP ERROR: FlushInstructionCache failed: %d\n", GetLastError());
		//printf("BP: 0xcc copied!\n");	
		//printf("pTar %x\n", *pTar);
}

extern "C" void NTAPI ClearBpOnTar
	(__in PBYTE pTar,
	 __in HANDLE hProcess) {

		 DWORD readB, oldPro;
		 VirtualProtectEx(hProcess, pTar, 0x1000, PAGE_EXECUTE_READWRITE, &oldPro);	 
		 WriteProcessMemory(hProcess, pTar, &original, 1, &readB); 	
		 if (!FlushInstructionCache(hProcess, pTar, 1)) printf("BP ERROR: FlushInstructionCache failed: %d\n", GetLastError());
		// printf("BP: original byte restored!\n");	
}

/*                       STEP                                 */


VOID Step
	(__in PBYTE pByte,
	 __in LPDEBUG_EVENT DbgEvent,
	 __in HANDLE hProcess,
	 __in HANDLE hThread) {
		 
		 SetBpOnTar(pByte, hProcess);
		 Context.Eip--;
		 SetThreadContext(hThread, &Context);
}

BOOL NTAPI SetStackFrame
	(__in      HANDLE hProcess,
     __in      HANDLE hThread,
     __inout   STACKFRAME stackFrame,
     __inout   PCONTEXT context,
     __in_opt  PFUNCTION_TABLE_ACCESS_ROUTINE FunctionTableAccessRoutine,
     __in_opt  PGET_MODULE_BASE_ROUTINE GetModuleBaseRoutine) {

	     ZeroMemory(&stackFrame, sizeof(stackFrame));
		 if (context != NULL) {
	         stackFrame.AddrPC.Offset = context->Eip;
	         stackFrame.AddrPC.Mode = AddrModeFlat;
	         stackFrame.AddrStack.Offset = context->Esp;
	         stackFrame.AddrStack.Mode = AddrModeFlat;
	         stackFrame.AddrFrame.Offset = context->Ebp;
			 stackFrame.AddrFrame.Mode = AddrModeFlat; }

		 //Note: MachineType IMAGE_FILE_MACHINE_I386
		 //so if I've no context I've to initialize the 
		 //stack frame in another way, reading from asm code
		 else {

			 ULONG programCoun, pStack, pBase;
			 __asm {
				 pop [programCoun]
				 mov [pStack], esp
				 mov [pBase], ebp }

			 stackFrame.AddrPC.Offset = programCoun;
	         stackFrame.AddrPC.Mode = AddrModeFlat;
	         stackFrame.AddrStack.Offset = pStack;
	         stackFrame.AddrStack.Mode = AddrModeFlat;
	         stackFrame.AddrFrame.Offset = pBase;
			 stackFrame.AddrFrame.Mode = AddrModeFlat; }

		 if (hProcess != INVALID_HANDLE_VALUE) {
			if (StackWalk(IMAGE_FILE_MACHINE_I386, hProcess, hThread, 
				          &StackFrame, context, 0, FunctionTableAccessRoutine, 
						  GetModuleBaseRoutine, 0)) {
							  return TRUE; }
			else return FALSE; 
		 }

		 else return FALSE;
}

PBYTE NTAPI OnBpException
	(__in HANDLE hThread,
	 __in HANDLE hProcess,
	 __in LPDEBUG_EVENT DbgEvent) {

        PBYTE next;
		LONG i;	
        PSYMBOL_INFOW ppSymbol;
		CHAR bufs[sizeof(PSYMBOL_INFOW) + MAX_SYM_NAME * sizeof(TCHAR)];
		ZeroMemory(bufs, sizeof(buf));
        ppSymbol = (PSYMBOL_INFOW)bufs;
        ppSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        ppSymbol->MaxNameLen = MAX_SYM_NAME;

		printf("Exception Address %08x\n", DbgEvent->u.Exception.ExceptionRecord.ExceptionAddress);
		for (i = 0; i < modCount; i++) {
			if (modules[modCount].SymLoaded == FALSE) {
				moduleBase = SymLoadModuleExW(hProcess, modules[i].hFile, modules[i].ModuleName, 
							                  NULL, (DWORD)modules[i].LoadAddress, 0, NULL, 0);
				if (moduleBase != 0) {
					modules[i].SymLoaded = TRUE;
					/* Test */
					if (SymFromAddrW(hProcess, (DWORD)DbgEvent->u.Exception.ExceptionRecord.ExceptionAddress, 0, ppSymbol)) {
						_tprintf(_T("Symbol name for the exception: %s\n"), ppSymbol->Name);
					    printf("Symbol Address: %08x\n", ppSymbol->Address); }
					
					else printf("SymFromAddrW failed with code: %d\n", GetLastError());				
				}
				else printf("moduleBase == 0\n");
			}
			else printf("SymLoaded == TRUE\n");
		}
		//modules[i].SymLoaded = FALSE;
		Context.ContextFlags = CONTEXT_INTEGER;
		if (GetThreadContext(hThread, &Context)) {
			printf("Edi %08x Esi %08x Ebx %08x ", Context.Edi, Context.Esi, Context.Ebx);
			printf("Edx %08x Ecx %08x Eax %08x\n", Context.Edx, Context.Ecx, Context.Eax); }
		Context.ContextFlags = CONTEXT_CONTROL;
		if (GetThreadContext(hThread, &Context)) {
			printf("Ebp %08x Eip %08x Esp %08x\n", Context.Ebp, Context.Eip, Context.Esp);
			if (MemoryMapping(process[0].hFile)) {                                                 
		    PBYTE excOpcode = (BYTE *)Context.Eip;
			next = disasm(excOpcode, FALSE);
			//printf("Next Byte %x\n", *next);
			}
			else printf("ERROR: MemoryMapping failed\n");
	  
	   }
		if (SymCleanup(hProcess)) printf("SymCleanup success\n");
		return next;
}

PBYTE NTAPI OnAccessViolationException
	(__in HANDLE hThread,
	 __in HANDLE hProcess,
	 __in LPDEBUG_EVENT DbgEvent) {
        
		PBYTE next, excOpcode;
        PSYMBOL_INFOW pSymbol;
		CHAR buf[sizeof(PSYMBOL_INFOW) + MAX_SYM_NAME * sizeof(TCHAR)];
		ZeroMemory(buf, sizeof(buf));
        pSymbol = (PSYMBOL_INFOW)buf;
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = MAX_SYM_NAME;

        printf("Exception Address %08x\n", (DWORD)DbgEvent->u.Exception.ExceptionRecord.ExceptionAddress);
		printf("Exception Address %08x\n", DbgEvent->u.Exception.ExceptionRecord.ExceptionAddress);
		for (int i = 0; i < modCount; i++) {
			if (modules[modCount].SymLoaded == FALSE) {
				moduleBase = SymLoadModuleExW(hProcess, modules[i].hFile, modules[i].ModuleName, 
							                  NULL, (DWORD64)modules[i].LoadAddress, 0, NULL, 0);
				if (moduleBase != 0) {
					modules[i].SymLoaded = TRUE;
					/* Test */
					if (SymFromAddrW(hProcess, (DWORD)DbgEvent->u.Exception.ExceptionRecord.ExceptionAddress, 0, pSymbol)) {
						_tprintf(_T("Symbol name for the exception: %s\n"), pSymbol->Name);
					    //printf("Symbol Address: %08x\n", pSymbol->Address); 
					}		
					else printf("SymFromAddrW failed with code: %d\n", GetLastError());				
				}
				else printf("module base  %d\n", GetLastError());
			}
		}

		Context.ContextFlags = CONTEXT_INTEGER;
		if (GetThreadContext(hThread, &Context)) {
			printf("Edi %08x Esi %08x Ebx %08x ", Context.Edi, Context.Esi, Context.Ebx);
			printf("Edx %08x Ecx %08x Eax %08x\n", Context.Edx, Context.Ecx, Context.Eax); }
		Context.ContextFlags = CONTEXT_CONTROL;
		if (GetThreadContext(hThread, &Context)) {
			printf("Ebp %08x Eip %08x Esp %08x\n", Context.Ebp, Context.Eip, Context.Esp);
			if (MemoryMapping(process[0].hFile)) {                                                 
		    excOpcode = (BYTE *)Context.Eip;
			printf("excOpcode %x\n", *excOpcode);
			next = disasm(excOpcode, FALSE);
			//printf("Next Byte %x\n", *next);
			}
			else printf("ERROR: MemoryMapping failed\n");
	  
	   }
		if (SymCleanup(hProcess)) printf("SymCleanup success\n");
		return next;
}

BOOL NTAPI SetDbgEvents
	(__in LPDEBUG_EVENT DbgEvent) {

		HANDLE hProcess, hThread;
		PBYTE nextB;
		DWORD dwContinueStatus = DBG_CONTINUE, oldProtection;

		for (;;) {
			if (WaitForDebugEvent(DbgEvent, INFINITE)) {
				hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT,
								     FALSE, DbgEvent->dwThreadId);
				hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_ALL_ACCESS | PROCESS_VM_OPERATION,
								       FALSE, DbgEvent->dwProcessId);				
		        //SetThreadContext(hThread, &Context);
				SymInitializeW(DbgEvent->u.CreateProcessInfo.hProcess, NULL, FALSE);
				switch (DbgEvent->dwDebugEventCode) {

				case CREATE_PROCESS_DEBUG_EVENT:
					
					process[0].hFile = DbgEvent->u.CreateProcessInfo.hFile;
					printf("Image base: %08x\n", DbgEvent->u.CreateProcessInfo.lpBaseOfImage);
					modules[modCount].hFile = DbgEvent->u.CreateProcessInfo.hFile;
					modules[modCount].LoadAddress = DbgEvent->u.CreateProcessInfo.lpBaseOfImage;
					nameLen = GetProcessImageFileName(hProcess, modules[modCount].ModuleName, 
						                            sizeof(modules[modCount].ModuleName)/sizeof(TCHAR));
					if (nameLen == 0) { printf("GetProcessImageFileName failed with code: %d\n", GetLastError()); }
					modCount++;
					
					ImgBase = MemoryMapping(process[0].hFile);
					if (ImgBase == NULL) printf("ERROR: MemoryMapping failed!\n");
					else {
						firstB = GetPEInfo(process[0].hFile, ImgBase);
					} 
					//firstB = (PBYTE)DbgEvent->u.CreateProcessInfo.lpStartAddress;
					CloseHandle(process[0].hFile);
					break;

				case LOAD_DLL_DEBUG_EVENT:
					if (IsSymLoaded = FALSE) {
						SymSetOptions(SYMOPT_DEFERRED_LOADS);
						if (SymInitialize(hProcess, NULL, TRUE)) {
							IsSymLoaded = TRUE; }
						else printf("SymInitialize failed with code: %d\n", GetLastError());
					}
					modules[modCount].hFile = DbgEvent->u.LoadDll.hFile;
					modules[modCount].LoadAddress = DbgEvent->u.LoadDll.lpBaseOfDll;
					nameLen = GetMappedFileName(hProcess, modules[modCount].LoadAddress, modules[modCount].ModuleName,
						                        sizeof(modules[modCount].ModuleName)/sizeof(TCHAR));
					if (nameLen == 0)  printf("GetMappedFileName failed with code: %d\n", GetLastError());
					else {
						moduleBase = SymLoadModuleExW(hProcess, modules[modCount].hFile, modules[modCount].ModuleName, 
							                          NULL, (DWORD64)modules[modCount].LoadAddress, 0, NULL, 0);
						moduleBase = SymLoadModuleExW(hProcess, modules[modCount].hFile, modules[modCount].ModuleName, 
							                          NULL, (DWORD64)modules[modCount].LoadAddress, 0, NULL, 0);
						if (moduleBase != 0) {
							modules[modCount].SymLoaded = TRUE; }
						_tprintf(_T("Loaded DLL %s\n"), modules[modCount].ModuleName);
					}
					modCount++;
	              	if (SymCleanup(hProcess)) printf("SymCleanup success\n");
					break;
					
				case EXCEPTION_DEBUG_EVENT:
					switch (DbgEvent->u.Exception.ExceptionRecord.ExceptionCode) {
						/*
					case EXCEPTION_ACCESS_VIOLATION:
						printf("EXCEPTION_ACCESS_VIOLATION\n");			
				        SuspendThread(hThread);
						if (DbgEvent->u.Exception.dwFirstChance == 1) printf("!!First chance!!\n");
						nextB = OnAccessViolationException(hThread, DbgEvent->u.CreateProcessInfo.hProcess, DbgEvent);
						GetCommLine(DbgEvent, nextB, Context, hProcess, hThread);
						dwContinueStatus = DBG_CONTINUE; 

						CloseHandle(process[0].hFile);
						ResumeThread(hThread);
						
					    break;
						 */
					case EXCEPTION_BREAKPOINT:

						printf("EXCEPTION_BREAKPOINT\n");			
                        dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
						Context.ContextFlags = CONTEXT_CONTROL;
						if (!iBp) {	
							GetThreadContext(hThread, &Context);
							nextB = OnBpException(hThread, hProcess, DbgEvent);
							//SetBpOnTar((PBYTE)DbgEvent->u.Exception.ExceptionRecord.ExceptionAddress, hProcess);
                            //SetBpOnTar(firstB, hProcess);
							Context.Eip--;
                            SetThreadContext(hThread, &Context);
							iBp = TRUE;
							ClearBpOnTar(firstB, hProcess);
							GetCommLine(DbgEvent, nextB, Context, hProcess, hThread);
							dwContinueStatus = DBG_CONTINUE;	
						}
						else {    
							GetThreadContext(hThread, &Context);
							if (Context.Eip - 1 == (DWORD)firstB) {
								 printf("BP: $exentry breakpoint\n");
								 Context.Eip--;
                                 SetThreadContext(hThread, &Context);
			
								 nextB = OnBpException(hThread, hProcess, DbgEvent);
								 
								 //ClearBpOnTar(firstB, hProcess);
								 
		 						 GetCommLine(DbgEvent, nextB, Context, hProcess, hThread);
								 //dwContinueStatus = GetCommLine();
                                 dwContinueStatus = DBG_CONTINUE;
							}
							else printf("BP: Unkown breakpoint at add: %08x\n", DbgEvent->u.Exception.ExceptionRecord.ExceptionAddress);
						}
						
						/*   */
						
						//dwContinueStatus = GetCommLine();


						/*   */
					//	break;
						
					default:
					    break;
						}
				    break;

				default:
					break;
				}
				CloseHandle(hThread);

			}
			
			if (dwContinueStatus == DBG_EXCEPTION_NOT_HANDLED) {
				printf("(if not first chance) ERROR: Exception not handled!\n");
				//DebugBreakProcess(hProcess);
				
			}
			else ContinueDebugEvent(DbgEvent->dwProcessId, DbgEvent->dwThreadId, dwContinueStatus); 
            CloseHandle(hProcess);  
		}
}

int __cdecl main
	() {

		PROCESS_INFORMATION procInfo;
		STARTUPINFO startupInfo; 
 
        ZeroMemory(&startupInfo, sizeof(startupInfo)); 
        startupInfo.cb = sizeof(startupInfo); 
        ZeroMemory(&procInfo, sizeof(procInfo));

		printf("Welocome to dbg\n");
		if (CreateProcessW(L"C:\\try.exe", NULL, NULL, NULL, 
			               FALSE, DEBUG_ONLY_THIS_PROCESS, NULL,
						   NULL, &startupInfo, &procInfo)) {
							   
							  if (SetDbgEvents(&dbgEvent)) { }
		}

		//int c = getchar();
		return 0;
}

			              


