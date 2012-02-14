#ifndef __DISASM_H__
#define __DISASM_H__

#include <Windows.h>
#include <stdio.h>
#include "dec.h"

LPVOID NTAPI MemoryMapping
	(__in HANDLE hFile) {

		HANDLE hFileMapp = CreateFileMapping(hFile, NULL,  PAGE_READONLY | SEC_IMAGE,
								             0, 0, NULL);
        if (hFileMapp == NULL) {
            printf("ERROR: CreateFileMapping failed  with code: %d\n", GetLastError());
            return FALSE; }

       LPVOID ImageBase = MapViewOfFile(hFileMapp, FILE_MAP_READ,
							            0, 0, NULL);
	   return ImageBase;
}

PBYTE NTAPI GetPEInfo
	(__in HANDLE hFile,
	 __in LPVOID ImageBase) {

		 mz = (IMAGE_DOS_HEADER *) ImageBase;
	     if (mz->e_magic != IMAGE_DOS_SIGNATURE) {   
		   VirtualFree(mz, 0, MEM_FREE);
		   printf("DISASM ERROR: The file is not an exe for windows.\n");
           return NULL; }

         pe = (IMAGE_NT_HEADERS *)(mz->e_lfanew + (long) mz);
         if (pe->Signature != IMAGE_NT_SIGNATURE) {
           VirtualFree(mz, 0, MEM_FREE);
           printf("DISASM ERROR: The file is not an exe for windows.\n");
           return NULL; }

	     DWORD ep = pe->OptionalHeader.AddressOfEntryPoint; 
	     buf = (unsigned char*) ImageBase;
	     PBYTE first = (BYTE*)((long)ImageBase + ep); 
		 return first;
}
 
/* PRINT */

VOID printInstr
	(__in BOOL isModOn,
     __in BOOL isImm,
	 __in LONG disp,
	 __in PINSTRUCTION_TABLE pInsTab,
	 __in char *reg,
	 __in char *sreg,
	 __in BYTE imm,
	 __in BYTE dispB,
	 __in BYTE opcode) {

		 printf("%s ", pInsTab->Name);
		 if ((isModOn == TRUE) && (isImm == TRUE))  {
			 printf("byte ptr %s, ", reg);
			 printf("%02xh\n", imm);
		 }
		 if ((isModOn == TRUE) && (isImm == FALSE)) {
			 switch (opcode) {
				 case 0x8b:

			         if (disp == 0) {
			             printf("%s, ", sreg);
				         printf("byte ptr %s\n", reg);
			         }
			         if (disp == 1) {
						 printf("%s, ", sreg);	
				         printf("dword ptr %s + %x\n ", reg, dispB);			         	 
		             }
				 break;

				 case 0x89:

			         if (disp == 0) {
				         printf("byte ptr %s, ", reg);
			             printf("%s\n", sreg);
			         }
			         if (disp == 1) {
						 printf("dword ptr %s + %x, ", reg, dispB);
						 printf("%s\n", sreg);				         	 
		             }
				break;

				 default:
						 break;
			 }
		 }
		 
}

/*   */

PBYTE  prefixR 
	(__in struct _INSTRUCTION_TABLE* pInsTab,                 
	 __in PBYTE pb_from,
	 __in BOOL stepIn) {  
              
				  if (pInsTab->opcode == 0x66) { //operand size override prefix
                      opsize_override = TRUE;
				      PBYTE pNext = modrm_SIB(pInsTab, pb_from, stepIn);
				      return pNext; }

				  else if(pInsTab->opcode == 0x67) { //address size override prefix
					  addsize_override = TRUE;
				      PBYTE pNext = modrm_SIB(pInsTab, pb_from, stepIn);
				      return pNext; }

				  else if(seg_fs == TRUE) { //seg override prefix (fs)
				      PBYTE pNext = modrm_SIB(pInsTab, pb_from + 1, stepIn);
				      return pNext; }

				  else { PBYTE pNext = modrm_SIB(pInsTab, pb_from, stepIn); 

				  return pNext; }

}

PBYTE  modrm_SIB
	(__in struct _INSTRUCTION_TABLE* pInsTab,                 
	 __in PBYTE pb_from,
	 __in BOOL stepIn) {  

		           BOOL flagImm = FALSE, flagModRm = FALSE, flagSIB = FALSE;
                   BYTE rmValue, regValue, b_modrm, b_imm, b_disp;
				   DWORD dw_disp;
                   char *regMod, *firstOp, *secondOp;
				   	 
				   printf("Opcode %x\n", pInsTab->opcode);
		           printf("Address: %08x    ", pb_from);
                   opsize_override = FALSE;
				   addsize_override = FALSE;
				  //se indirizza in memoria, controllo l'addsize override prefix, se è attivo allora userò la
				  //lunghezza dell'opcode in 16bit mode, altrimenti quella con 32
				  LONG target_length = (pInsTab->flag & FUNC_ADD)
					  ?(addsize_override ? pInsTab->opcode_size16 : pInsTab->opcode_size32) 
					  :(opsize_override ? pInsTab->opcode_size16 : pInsTab->opcode_size32);
				  //prendo modrm e sib byte e decodifico la lunghezza dell'istruzione da copiare
				  //se il SIB fa parte della colonna [*] (ovvero disp32 senza base se mod == 0x00, [ebp] altrimenti)	
					if (pInsTab->modrm != 0) { 	
						flagModRm = TRUE;
						modrm_on = TRUE;
						b_modrm = pb_from[pInsTab->modrm];
						BYTE b_flag = modrm_table[b_modrm]; 
						printf("%02x", pInsTab->opcode);
						printf("%02x  ", pb_from[pInsTab->modrm]);
						if (pInsTab->imm != 0) {
						    flagImm = TRUE; }
						target_length += b_flag & NO_SIB; // aggiungo il sib se presente
						if (b_flag & SIB_PRESENT) {
                            BOOL flagSIB = TRUE;
							BYTE b_sib = pb_from[pInsTab->modrm + 1];
							//printf("%x", pb_from[pInsTab->modrm + 1]);
					        if ((b_sib & 0x07) == 0x05) { 
								if ((b_modrm & 0xc0) == 0x00) {   //primo quadrante tabella intel 
									target_length += 4; }
								else if ((b_modrm & 0xc0) == 0x40) { //secondo quadrante tabella intel
									target_length += 1; }
								else if ((b_modrm & 0xc0) == 0x80) { //terzo quadrante tabella intel
									target_length += 4; }
							}
						} 
					}

					/* WITH IMMEDIATE (only rm field) */

					if (flagModRm == TRUE && flagImm == TRUE) {
					    rmValue = b_modrm & 0x07;
					    regMod = dwReg[rmValue];
					    if ((b_modrm & 0xc0) == 0x00) { 
						    b_imm = pb_from[pInsTab->modrm + 1];
						   // target_length += 1;
						   // printf("immediate %x\n", b_imm); 
							printInstr(TRUE, TRUE, 0, pInsTab, regMod, NULL, b_imm, 0, pb_from[0]);
						}

					    // 8 bit disp

					    else if ((b_modrm & 0xc0) == 0x40) { 
						    b_disp = pb_from[pInsTab->modrm + 1];
						    b_imm = pb_from[pInsTab->modrm + 2];	
						   // target_length += 2;
						    //printf("immediate %x\n", b_imm); 	
							printInstr(TRUE, TRUE, 1, pInsTab, regMod, NULL, b_imm, b_disp, pb_from[0]);
					    }

					    //4 byte disp

					    else if ((b_modrm & 0xc0) == 0x80) { 
						    dw_disp = pb_from[pInsTab->modrm + 1];
						    b_imm = pb_from[pInsTab->modrm + 5];
						 //   target_length += 5;
						   // printf("immediate %x\n", b_imm);
							printInstr(TRUE, TRUE, 4, pInsTab, regMod, NULL, b_imm, dw_disp, pb_from[0]);
					    }

					    else printf ("DISASM ENGINE ERROR UNKOWN\n");

					}

					/*  MOV NO IMM (mod-reg-rm)*/

					if ((flagModRm == TRUE) && (flagImm == FALSE)) {
						if ((b_modrm & 0xc0) == 0x00) { 
							if (seg_fs == TRUE) {
							    firstOp = "fs:";
								regValue = b_modrm & 0x38;
							    secondOp = dwRegNoInd[regValue/8];
								printInstr(TRUE, FALSE, 0, pInsTab, firstOp, secondOp, 0, 0, pb_from[0]);
							}
							else {
						        rmValue = b_modrm & 0x07;
							    firstOp = dwReg[rmValue];
							    regValue = b_modrm & 0x38;
							    secondOp = dwRegNoInd[regValue/8];
								printInstr(TRUE, FALSE, 0, pInsTab, firstOp, secondOp, 0, 0, pb_from[0]);
							}
					    }

					    // 8 bit disp

					    else if ((b_modrm & 0xc0) == 0x40) { 
							if (seg_fs == TRUE) {
							    firstOp = "fs:";
								regValue = b_modrm & 0x38;
								secondOp = dwRegNoInd[regValue/8];
								b_disp = pb_from[pInsTab->modrm + 1];							        
								printInstr(TRUE, FALSE, 1, pInsTab, firstOp, secondOp, 0, b_disp, pb_from[0]);
							}
							else {
						        rmValue = b_modrm & 0x07;
							    firstOp = dwReg[rmValue];
							    regValue = b_modrm & 0x38;
							    secondOp = dwRegNoInd[regValue/8];
								b_disp = pb_from[pInsTab->modrm + 1];							       				
								printInstr(TRUE, FALSE, 1, pInsTab, firstOp, secondOp, 0, b_disp, pb_from[0]);
							}
						    
					    }

					    //4 byte disp

					    else if ((b_modrm & 0xc0) == 0x80) { 
						    if (seg_fs == TRUE) {
							    firstOp = "fs:";
								regValue = b_modrm & 0x38;
								secondOp = dwRegNoInd[regValue/8];
								dw_disp = pb_from[pInsTab->modrm + 1];							      
								printInstr(TRUE, FALSE, 4, pInsTab, firstOp, secondOp, 0, dw_disp, pb_from[0]);
							}
							else {
						        rmValue = b_modrm & 0x07;
							    firstOp = dwReg[rmValue];
							    regValue = b_modrm & 0x38;
							    secondOp = dwRegNoInd[regValue/8];
								dw_disp = pb_from[pInsTab->modrm + 1];	
								printInstr(TRUE, FALSE, 4, pInsTab, firstOp, secondOp, 0, dw_disp, pb_from[0]);
							}
					    }

						else  printf("DISASM ERROR\n");
									
						
					}

					if ((flagModRm == FALSE) && (flagImm == FALSE)) {
							if (pInsTab->opcode == 0xc3) {
								printf("ret\n");
							}
					}

					printf("target length: %d\n", target_length); 
				    PBYTE pNext = pb_from + target_length;
					return pNext;
}  

PBYTE  jumpR
	(__in struct _INSTRUCTION_TABLE* pInsTab,               
     __in PBYTE pb_from,
	 __in BOOL stepIn) {

		 PBYTE addr;
		
		 printf("Address: %08x    ", pb_from);
		 if (pInsTab->relOff == 1) {
			 addr = pb_from + (2 + pb_from[1]);
			 printf("jmp %08x\n", addr);
		 }
		 
		 return (addr);

		 return addr;
}

PBYTE  callR 
	(__in struct _INSTRUCTION_TABLE* pInsTab,
	 __in PBYTE pb_from,
	 __in BOOL stepIn) {
		 
		 PBYTE addr;
		 LONG target_length = (pInsTab->flag & FUNC_ADD)
					  ?(addsize_override ? pInsTab->opcode_size16 : pInsTab->opcode_size32) 
					  :(opsize_override ? pInsTab->opcode_size16 : pInsTab->opcode_size32);

		 addr = pb_from + (5 + (DWORD)(PBYTE&)(*(pb_from + 1)));	 
		 printf("Address: %08x    ", pb_from);
		 if (*pb_from == 0xe8) {
			 printf("call %08x\n", addr);
			 if (stepIn == FALSE) return addr;
			 else return (pb_from + target_length);
		 }
         if (*pb_from == 0xe9) {
			 printf("jmp %08x\n", addr);
			 return (addr + target_length);
		 }

		 else return pb_from; 
		// target_length += 5;  

		 
}

PBYTE disasm 
	(__in PBYTE pb_from, 
	 __in BOOL stepIn) {
	
		 if (pb_from[0] == 0x64) {
			 pInsTab = &deco[pb_from[1]];
			 seg_fs = TRUE;
	         return (pInsTab->disasmFunc)((struct _INSTRUCTION_TABLE*)pInsTab, pb_from, stepIn);
		 }
		 else {
	         pInsTab = &deco[pb_from[0]];
	         return (pInsTab->disasmFunc)((struct _INSTRUCTION_TABLE*)pInsTab, pb_from, stepIn);
		 }
									
}

VOID NTAPI _iprint
	(__in PBYTE pb_from,
	 __in LONG target_length,
	 __in BOOL modRM,
	 __in BOOL imm) {

		 if (modRM == TRUE && imm == FALSE) {

			 if (target_length == 




}

#endif __DISASM_H__