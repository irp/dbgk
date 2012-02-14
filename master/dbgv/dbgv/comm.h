#ifndef __COMM_H__
#define __COMM_H__

#include <DbgHelp.h>
#include <Windows.h>
#include "dec.h"

char ar, as;
char command[257];
char *pComm[40];
PBYTE pNext;
BOOL first = TRUE;

DWORD NTAPI WaitForInput 
	() {

		//HANDLE hConsole = GetStdHandle(STD_INPUT_HANDLE);
		HANDLE hConsole = CreateFile(L"CON", GENERIC_READ, FILE_SHARE_READ, 
			                         FALSE, OPEN_EXISTING, 0, 0);
		DWORD state = WaitForSingleObject(hConsole, INFINITE);
		return state;
}

extern "C" BOOL NTAPI InterComm
	(__in int argc,
	 __in char *argv[],
	 __in LPDEBUG_EVENT DbgEvent,
	 __in CONTEXT Context,
	 __in PBYTE pByte,
	 __in HANDLE hProcess,
	 __in HANDLE hThread) {

		 ULONG addr[256];
		 LONG index, i, j;

		 char typed[256];
		 for (i = 4, j = 0; i < 12, j < 8; i++, j++)
		 {
			     typed[j] = argv[0][i];
			// printf("typed %c\n", typed[i]);
		 }
		  
		 for (index = 0; index < argc; index++) {
			 
			 if (argv[index][0] == '/') {

				 //Command mode
				 switch(argv[index][1]) {
				 case 'h':
				 case 'H':
					 printf("Dbg help\n [/c]- ContinueDbgEvent\n [/o]- StepOver\n [/i]- StepIn\n ");
					 return TRUE;
					 break;
				 case 'c':
				 case 'C':
					 ContinueDebugEvent(DbgEvent->dwProcessId, DbgEvent->dwThreadId, DBG_CONTINUE);
					 return TRUE;
					 break;

				 case 'o':
				 case 'O':
					 if (first == TRUE) {
					 //StepIn(pByte, DbgEvent, hProcess, hThread);
					// pNext = disasm(pByte);
					 pNext = disasm(pByte, FALSE);  
					 Step(pNext, DbgEvent, hProcess, hThread);
					 //printf("pNeXt %x\n", pNext);
					 ClearBpOnTar(pByte, hProcess);
					 ContinueDebugEvent(DbgEvent->dwProcessId, DbgEvent->dwThreadId, DBG_CONTINUE); 
					 first = FALSE;
					 }
					 else {
						 Context.Eip--;
                         SetThreadContext(hThread, &Context);
						 ClearBpOnTar(pByte, hProcess);
						 Step(pNext, DbgEvent, hProcess, hThread);
						 pNext = disasm(pNext, FALSE); 
						 //printf("pNeXt %x\n", pNext);
						 ContinueDebugEvent(DbgEvent->dwProcessId, DbgEvent->dwThreadId, DBG_CONTINUE); 
						 first = FALSE;
					 }
					 return TRUE;
					 break;

				 case 'i':
				 case 'I':
					 if (first == TRUE) {
					 //StepIn(pByte, DbgEvent, hProcess, hThread);
					// pNext = disasm(pByte);
					 pNext = disasm(pByte, TRUE);  
					 Step(pNext, DbgEvent, hProcess, hThread);
					 //printf("pNeXt %x\n", pNext);
					 ClearBpOnTar(pByte, hProcess);
					 ContinueDebugEvent(DbgEvent->dwProcessId, DbgEvent->dwThreadId, DBG_CONTINUE); 
					 first = FALSE;
					 }
					 else {
						 Context.Eip--;
                         SetThreadContext(hThread, &Context);
						 ClearBpOnTar(pByte, hProcess);
						 Step(pNext, DbgEvent, hProcess, hThread);
						 pNext = disasm(pNext, TRUE); 
						 //printf("pNeXt %x\n", pNext);
						 ContinueDebugEvent(DbgEvent->dwProcessId, DbgEvent->dwThreadId, DBG_CONTINUE); 
						 first = FALSE;
					 }
					 return TRUE;
					 break;

				 case 'u':
				 case 'U':
					addr[0] = *(ULONG *&)*(typed);		
					printf("addr %d\n", addr[0]);
					printf("addr %d\n", *addr);
					break;
					 
				 default:
					 return TRUE;
					 break;
				 }
			 }
			 else return FALSE;

		 }
}

extern "C" BOOL NTAPI GetCommLine
	(__in LPDEBUG_EVENT DbgEvent,
	 __in PBYTE pByte,
	 __in CONTEXT Context,
	 __in HANDLE hProcess,
	 __in HANDLE hThread) {

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
					   stat = InterComm(commandSize, pComm, DbgEvent, Context, pByte, hProcess, hThread);

				  
		      }
		 }

		return stat;

}

#endif