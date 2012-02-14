#ifndef __DISASM_H__
#define __DISASM_H__

#include <Windows.h>
#include <stdio.h>

/* Ponte */

typedef struct _PONTE {

	BYTE copied[30];   //istruzioni copiate
	BYTE f_codeSize;   //grandezza di ^
	PBYTE pstay;       //puntatore alla prima istruzione non copiata
	PVOID phook;       //puntatore alla prima istruzione dell'hook

}PONTE, *PPONTE;

/*  */


/* PE */

IMAGE_DOS_HEADER * mz;
IMAGE_NT_HEADERS * pe;
BYTE * buf;

/* */

char dwReg[8][8] = { "[eax]", "[ecx]", "[edx]", "[edx]", "[esp]",  "[ebp]", "[esi]", "[edi]" };
char dwRegNoInd[8][8] = { "eax", "ecx", "edx", "edx", "esp",  "ebp", "esi", "edi" };

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

typedef PBYTE (NTAPI *DISASM_FUNC) (struct _INSTRUCTION_TABLE* pInsTab,                
			                        PBYTE pb_from,
	                                BOOL stepIn); 
             
/* Flag */
#define FUNC_ADD        0x02   //istruzione che indirizza in memoria
#define NO_SIB          0x0f   //istruzione senza sib
#define SIB_PRESENT     0x10


/* strutture */
typedef const struct _INSTRUCTION_TABLE {

	ULONG opcode;
	ULONG modrm;
	ULONG sib;
	ULONG flag;           //flag per i prefissi
	//PPREFIX_TABLE pprefixTab;
	DISASM_FUNC disasmFunc;

	LONG opcode_size32;  //offset dell'ultimo byte se a 32bit mode
	LONG opcode_size16;  //offset dell'ultimo byte se a 16bit mode
	ULONG imm;
	ULONG relOff;
	char Name[8];

}INSTRUCTION_TABLE, *PINSTRUCTION_TABLE;

PINSTRUCTION_TABLE pInsTab;

//typedef PBYTE ( *DISASM_FUNC)(PINSTRUCTION_TABLE pInsTab, PBYTE p_where, PBYTE pb_from);
BOOL opsize_override = FALSE;
BOOL addsize_override = FALSE;
BOOL seg_fs = FALSE;
BOOL modrm_on = FALSE;

/*              */

const BYTE modrm_table[256] = {

    0,0,0,0,1,4,0,0,0,0,0,0,1,4,0,0,0,0,0,0,
	1,4,0,0,0,0,0,0,1,4,0,0,0,0,0,0,1,4,0,0, 
	0,0,0,0,1,4,0,0,0,0,0,0,1,4,0,0,0,0,0,0, 
	1,4,0,0,1,1,1,1,2,1,1,1,1,1,1,1,2,1,1,1,                  
    1,1,1,1,2,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,
	2,1,1,1,1,1,1,1,2,1,1,1,1,1,1,1,2,1,1,1,
	1,1,1,1,2,1,1,1,4,4,4,4,5,4,4,4,4,4,4,4,
	5,4,4,4,4,4,4,4,5,4,4,4,4,4,4,4,5,4,4,4,                  
    4,4,4,4,5,4,4,4,4,4,4,4,5,4,4,4,4,4,4,4,
	5,4,4,4,4,4,4,4,5,4,4,4,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,                  
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0   

}; 
 
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

//PPREFIX_TABLE pprefixTab;

/* funzioni */
//DISASM_FUNC modrm_SIB;

PBYTE  modrm_SIB 
	(__in struct _INSTRUCTION_TABLE* pInsTab,
	 __in PBYTE pb_from,
	 __in BOOL stepIn);

PBYTE  prefixR
	(__in struct _INSTRUCTION_TABLE* pInsTab,               
     __in PBYTE pb_from,
	 __in BOOL stepIn);

PBYTE  jumpR
	(__in struct _INSTRUCTION_TABLE* pInsTab,               
     __in PBYTE pb_from,
	 __in BOOL stepIn);

PBYTE  callR 
	(__in struct _INSTRUCTION_TABLE* pInsTab,
	 __in PBYTE pb_from,
	 __in BOOL stepIn);

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
				   	 
				   //printf("Opcode %x\n", pInsTab->opcode);
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


/*                  */

/* macro */                      /*mod,sib,flag,func,size32,size16,imm,relOff*/

#define oneByte_MACRO                0, 0, 0, &prefixR, 1, 1, 0, 0
#define twoByte_MACRO                0, 0, 0, &prefixR, 2, 2, 0, 0
#define trefiveByte_MACRO            0, 0, 0, &prefixR, 5, 3, 0, 0
#define trefiveByteRel_MACRO         0, 0, 0, &callR, 5, 3, 0, 1
#define twoByteModrm_MACRO           1, 0, 0, &prefixR, 2, 2, 0, 0
#define threeByteModrm_MACRO         1, 0, 0, &prefixR, 3, 3, 1, 0
#define JmpRelByte_MACRO             0, 0, 0, &jumpR, 2, 2, 0, 1
#define prefix_MACRO                 0, 0, 0, &prefixR, 1, 1, 0, 0
/* instruction set */  
/* /r il modrm byte contiene un registro 
   cd 4 byte seguono l'opcode */

const INSTRUCTION_TABLE deco[256] = {
	  
	{ 0x00, twoByteModrm_MACRO, "add" }, { 0x01, twoByteModrm_MACRO, "add" }, { 0x02, twoByteModrm_MACRO, "add" }, { 0x03, twoByteModrm_MACRO, "add" },
	{ 0x04, twoByte_MACRO, "add" }, { 0x05, trefiveByte_MACRO, "add" }, //ADD no imm8/16/32

	{ 0x06, oneByte_MACRO, "push es"}, { 0x07, oneByte_MACRO, "pop es"},  //PUSH ES, POP ES

	{ 0x08, twoByteModrm_MACRO, "or" }, { 0x09, twoByteModrm_MACRO, "or" }, { 0x0A, twoByteModrm_MACRO, "or" }, { 0x0B, twoByteModrm_MACRO, "or" },
	{ 0x0C, oneByte_MACRO, "or"}, { 0x0D, oneByte_MACRO, "or"},  //OR

	{ 0x0E, oneByte_MACRO, "push cs"}, { 0x0F, oneByte_MACRO, "pop"}, //PUSH CS, POP FS, GS

    { 0x10, twoByteModrm_MACRO, "adc" }, { 0x11, twoByteModrm_MACRO, "adc" }, { 0x12, twoByteModrm_MACRO, "adc" }, { 0x13, twoByteModrm_MACRO, "adc" },
	{ 0x14, twoByte_MACRO, "adc" },  { 0x15, trefiveByte_MACRO, "adc" }, //ADC no imm8/16

	{ 0x16, oneByte_MACRO, "mov"}, { 0x17, oneByte_MACRO, "mov"}, //PUSH SS, POP SS

	{ 0x18, twoByteModrm_MACRO, "mov" }, { 0x19, twoByteModrm_MACRO, "mov" }, { 0x1A, twoByteModrm_MACRO, "add" }, { 0x1B, twoByteModrm_MACRO, "add" },
    { 0x1C, twoByte_MACRO, "add" }, { 0x1D, trefiveByte_MACRO, "add" }, //SBB no imm8/16

	{ 0x1E, oneByte_MACRO, "add"}, { 0x1F, oneByte_MACRO, "add"}, //PUSH DS, POP DS

	{ 0x20, twoByteModrm_MACRO, "add" }, { 0x21, twoByteModrm_MACRO, "add" }, { 0x22, twoByteModrm_MACRO, "add" }, { 0x23, twoByteModrm_MACRO, "add" }, 
	{ 0x24, twoByte_MACRO, "add" }, { 0x25, trefiveByte_MACRO, "add" }, //AND no imm8/16/32

	{ 0x26, prefix_MACRO, "add" }, //prefix

	{ 0x27, oneByte_MACRO, "add"}, //DAA (decimal adjust AL after addiction)

    { 0x28, twoByteModrm_MACRO, "add" }, { 0x29, twoByteModrm_MACRO, "add" }, { 0x2A, twoByteModrm_MACRO, "add" }, { 0x2B, twoByteModrm_MACRO, "add" },
	{ 0x2C, twoByte_MACRO, "add" }, { 0x2D, trefiveByte_MACRO, "add" }, //SUB no imm8/16/32

    { 0x2E, prefix_MACRO, "add" }, //prefix

    { 0x2F, oneByte_MACRO, "add"}, //DAS (DAA for subtractions)

	{ 0x30, twoByteModrm_MACRO, "add" }, { 0x31, twoByteModrm_MACRO, "add" }, { 0x32, twoByteModrm_MACRO, "add" }, { 0x33, twoByteModrm_MACRO, "add" },
	{ 0x34, twoByte_MACRO, "add" }, { 0x35, trefiveByte_MACRO, "add" }, //XOR no imm8/16/32

	{ 0x36, prefix_MACRO, "add" }, //prefix

	{ 0x37, oneByte_MACRO, "add"}, //AAA (ascii adjust AL for addictions)

    { 0x38, oneByte_MACRO, "add"}, { 0x39, oneByte_MACRO, "add"}, { 0x3A, oneByte_MACRO, "add"}, { 0x3B, oneByte_MACRO, "add"},
	{ 0x3C, oneByte_MACRO, "add"}, { 0x3D, oneByte_MACRO, "add"}, //CMP

	{ 0x3E, prefix_MACRO, "add" }, //prefix

	{ 0x3F, oneByte_MACRO, "add"}, //AAS (AAA for subtractions)

	{ 0x40, oneByte_MACRO, "add"}, { 0x41, oneByte_MACRO, "add"}, { 0x42, oneByte_MACRO, "add"}, { 0x43, oneByte_MACRO, "add"},
	{ 0x44, oneByte_MACRO, "add" }, { 0x45, oneByte_MACRO, "add" }, { 0x46, oneByte_MACRO, "add" }, { 0x47, oneByte_MACRO, "add" }, //INC

	{ 0x48, oneByte_MACRO, "add" }, { 0x49, oneByte_MACRO, "add" }, { 0x4A, oneByte_MACRO, "add" }, { 0x4B, oneByte_MACRO, "add" },
    { 0x4C, oneByte_MACRO, "add" }, { 0x4D, oneByte_MACRO, "add" }, { 0x4E, oneByte_MACRO, "add" }, { 0x4F, oneByte_MACRO, "add" }, //DEC

	{ 0x50, oneByte_MACRO, "add" }, { 0x51, oneByte_MACRO, "add" }, { 0x52, oneByte_MACRO, "add" }, { 0x53, oneByte_MACRO, "add" }, 
	{ 0x54, oneByte_MACRO, "add" }, { 0x55, oneByte_MACRO, "add" }, { 0x56, oneByte_MACRO, "add" }, { 0x57, oneByte_MACRO, "add" }, //PUSH r

	{ 0x58, oneByte_MACRO, "add" }, { 0x59, oneByte_MACRO, "add" }, { 0x5A, oneByte_MACRO, "add" }, { 0x5B, oneByte_MACRO, "add" },
	{ 0x5C, oneByte_MACRO, "add" }, { 0x5D, oneByte_MACRO, "add" }, { 0x5E, oneByte_MACRO, "add" }, { 0x5F, oneByte_MACRO, "add" }, //POP r

    { 0x60, oneByte_MACRO, "add" }, { 0x61, oneByte_MACRO, "add" }, //PUSHAD, POPAD (pushano e poppano i general registers nello e dallo stack)

	{ 0x62, oneByte_MACRO, "add" }, //??
	{ 0x63, oneByte_MACRO, "add" }, //??
	
	{ 0x64, prefix_MACRO, "add" }, { 0x65, prefix_MACRO, "add" }, 
	{ 0x66, prefix_MACRO, "add" }, { 0x67, prefix_MACRO, "add" }, //OperandOverride and AddressOverride prefix

	{ 0x68, trefiveByte_MACRO, "add" }, //PUSH imm16/32

	{ 0x69, oneByte_MACRO, "add" }, //??

    { 0x6A, twoByte_MACRO, "add" }, //PUSH imm8

    { 0x6B, oneByte_MACRO, "add" }, //??

	{ 0x6C, oneByte_MACRO, "add" }, { 0x6D, oneByte_MACRO, "add" }, { 0x6E, oneByte_MACRO, "add" }, { 0x6F, oneByte_MACRO, "add" }, //INS, OUTS

	{ 0x70, oneByte_MACRO, "add" },
	{ 0x71, oneByte_MACRO, "add" },
	{ 0x72, oneByte_MACRO, "add" },
	{ 0x73, oneByte_MACRO, "add" },
    { 0x74, oneByte_MACRO, "add" },
    { 0x75, oneByte_MACRO, "add" },
	{ 0x76, oneByte_MACRO, "add" },
	{ 0x77, oneByte_MACRO, "add" },
	{ 0x78, twoByteModrm_MACRO, "add" },     
	{ 0x79, oneByte_MACRO, "add" },
	{ 0x7A, oneByte_MACRO, "add" },
	{ 0x7B, oneByte_MACRO, "add" },
	{ 0x7C, oneByte_MACRO, "add" },
	{ 0x7D, oneByte_MACRO, "add" },
    { 0x7E, oneByte_MACRO, "add" },
    { 0x7F, oneByte_MACRO, "add" },

	{ 0x80, oneByte_MACRO, "add" },  //??
	{ 0x81, oneByte_MACRO, "add" },  //??

	{ 0x82, twoByte_MACRO, "add" },  //MOV AL, src

	{ 0x83, oneByte_MACRO, "add" },  //??

	{ 0x84, twoByteModrm_MACRO, "add" }, { 0x85, twoByteModrm_MACRO, "add" }, //TEST

	{ 0x86, twoByteModrm_MACRO, "add" }, { 0x87, twoByteModrm_MACRO, "add" }, //XCHG r, r/m

    { 0x88, twoByteModrm_MACRO, "mov" }, { 0x89, twoByteModrm_MACRO, "mov" }, { 0x8A, twoByteModrm_MACRO, "mov" }, { 0x8B, twoByteModrm_MACRO, "mov" },
	{ 0x8C, twoByteModrm_MACRO, "mov" },    // MOV r, r/m etc.., 

	{ 0x8D, twoByteModrm_MACRO, "add" }, { 0x8E, twoByteModrm_MACRO, "add" }, { 0x8F, twoByteModrm_MACRO, "add" }, //LEA, MOV sRegister, r/m, POP

	{ 0x90, oneByte_MACRO, "add" },  //NOP (XCHG EAX, EAX)

	{ 0x91, oneByte_MACRO, "add" }, { 0x92, oneByte_MACRO, "add" }, { 0x93, oneByte_MACRO, "add" }, { 0x94, oneByte_MACRO, "add" },
	{ 0x95, oneByte_MACRO, "add" }, { 0x96, oneByte_MACRO, "add" }, { 0x97, oneByte_MACRO, "add" }, //XCHG ax, ..., r

	{ 0x98, oneByte_MACRO, "add" }, //??
	{ 0x99, oneByte_MACRO, "add" }, //??
	{ 0x9A, oneByte_MACRO, "add" }, //??

	{ 0x9B, oneByte_MACRO, "wait" }, //WAIT

    { 0x9C, oneByte_MACRO, "push fs" }, { 0x9D, oneByte_MACRO, "pop fd" }, { 0x9E, oneByte_MACRO, "sahf" }, { 0x9F, oneByte_MACRO, "lahf" }, //PUSHFS, POPFD, SAHF, LAHF
	//SAHF, LAHF settano da AH alcuni flag dell'EFLAGS, PUSHFD, POPFD pushano nello stack l'EFLAG

	{ 0xA0, oneByte_MACRO, "add" },
	{ 0xA1, oneByte_MACRO, "add" }, 
	{ 0xA2, oneByte_MACRO, "add" },
	{ 0xA3, oneByte_MACRO, "add" },

	{ 0xA4, oneByte_MACRO, "add" }, { 0xA5, oneByte_MACRO, "add" }, //MOVS, MOVSD  mov ES:(E)DI, DS:(E)SI

    { 0xA6, oneByte_MACRO, "add" }, { 0xA7, oneByte_MACRO, "add" }, //CMP
	
	{ 0xA8, twoByte_MACRO, "add" }, { 0xA9, trefiveByte_MACRO, "add" }, //TEST

	{ 0xAA, oneByte_MACRO, "stos" }, { 0xAB, oneByte_MACRO, "stos" }, { 0xAC, oneByte_MACRO, "stos" }, { 0xAD, oneByte_MACRO, "stos" },
	{ 0xAE, oneByte_MACRO, "stos" }, { 0xAF, oneByte_MACRO, "stos" }, //STOS, LODS, SCAS salvano in ES:(E)DI da AX, etc..

    { 0xB0, twoByte_MACRO, "mov" }, { 0xB1, twoByte_MACRO, "mov" }, { 0xB2, twoByte_MACRO, "mov" }, { 0xB3, twoByte_MACRO, "mov" },
	{ 0xB4, twoByte_MACRO, "mov" }, { 0xB5, twoByte_MACRO, "mov" }, { 0xB6, twoByte_MACRO, "mov" }, { 0xB7, twoByte_MACRO, "mov" }, //MOV r, r/m etc...

	{ 0xB8, trefiveByte_MACRO, "add" }, { 0xB9, trefiveByte_MACRO, "add" }, { 0xBA, trefiveByte_MACRO, "add" }, { 0xBB, trefiveByte_MACRO, "add" },
	{ 0xBC, trefiveByte_MACRO, "add" }, { 0xBD, trefiveByte_MACRO, "add" }, { 0xBE, trefiveByte_MACRO, "add" }, { 0xBF, trefiveByte_MACRO, "add" }, //MOB r, imm...

    { 0xC0, oneByte_MACRO, "add" },
    { 0xC1, oneByte_MACRO, "add" },
    { 0xC2, oneByte_MACRO, "add" },

    { 0xC3, oneByte_MACRO, "ret" },

    { 0xC4, oneByte_MACRO, "add" },
    { 0xC5, oneByte_MACRO, "add" },

    { 0xC6, threeByteModrm_MACRO , "mov" }, //mov r/m8, imm8

    { 0xC7, oneByte_MACRO, "add" },
    { 0xC8, oneByte_MACRO, "add" },
    { 0xC9, oneByte_MACRO, "add" },
    { 0xCA, oneByte_MACRO, "add" },
    { 0xCB, oneByte_MACRO, "add" },
    { 0xCC, oneByte_MACRO, "add" },
    { 0xCD, oneByte_MACRO, "add" },
    { 0xCE, oneByte_MACRO, "add" },
    { 0xCF, oneByte_MACRO, "add" },

	{ 0xD0, oneByte_MACRO, "add" },
	{ 0xD1, oneByte_MACRO, "add" },  
	{ 0xD2, trefiveByte_MACRO, "add" },        
	{ 0xD3, trefiveByte_MACRO, "add" }, 
    { 0xD4, trefiveByte_MACRO, "add" },
	{ 0xD5, trefiveByte_MACRO, "add" }, 
	{ 0xD6, trefiveByte_MACRO, "add" },        
	{ 0xD7, trefiveByte_MACRO, "add" }, 
    { 0xD8, trefiveByte_MACRO, "add" },
	{ 0xD9, trefiveByte_MACRO, "add" },
	{ 0xDA, trefiveByte_MACRO, "add" },        
	{ 0xDB, trefiveByte_MACRO, "add" }, 
    { 0xDC, trefiveByte_MACRO, "add" },
	{ 0xDD, trefiveByte_MACRO, "add" },
	{ 0xDE, trefiveByte_MACRO, "add" },
	{ 0xDF, trefiveByte_MACRO, "add" },

	{ 0xE0, trefiveByte_MACRO, "mov" },
	{ 0xE1, trefiveByte_MACRO, "mov" },
	{ 0xE2, trefiveByte_MACRO, "mov" },
	{ 0xE3, trefiveByte_MACRO, "mov" },
	{ 0xE4, trefiveByte_MACRO, "mov" },
	{ 0xE5, trefiveByte_MACRO, "mov" },
	{ 0xE6, trefiveByte_MACRO, "mov" },       
	{ 0xE7, trefiveByte_MACRO, "mov" }, 

    { 0xE8, trefiveByteRel_MACRO, "call" },  //call cd

	{ 0xE9, trefiveByte_MACRO, "jmp" }, 
	{ 0xEA, trefiveByte_MACRO, "mxx" },

	{ 0xEB, JmpRelByte_MACRO, "jmp" },  //jmp cb

	{ 0xEC, trefiveByte_MACRO, "xxx" },
	{ 0xED, trefiveByte_MACRO, "xxs" },
	{ 0xEE, trefiveByte_MACRO, "add" },
	{ 0xEF, trefiveByte_MACRO, "add" },

	{ 0xF0, prefix_MACRO, "add" }, //prefix LOCK 

	{ 0xF1, trefiveByte_MACRO, "add" }, 

    { 0xF2, prefix_MACRO, "add" }, { 0xF3, prefix_MACRO, "add" }, //prefix REPNE, REPE

	{ 0xF4, trefiveByte_MACRO, "add" },        
	{ 0xF5, trefiveByte_MACRO, "add" }, 
    { 0xF6, trefiveByte_MACRO, "add" },
	{ 0xF7, trefiveByte_MACRO, "add" },
	{ 0xF8, trefiveByte_MACRO, "add" },
	{ 0xF9, trefiveByte_MACRO, "add" },
	{ 0xFA, trefiveByte_MACRO, "add" },
	{ 0xFB, trefiveByte_MACRO, "add" },
	{ 0xFC, trefiveByte_MACRO, "add" },
	{ 0xFD, trefiveByte_MACRO, "add" },
	{ 0xFE, trefiveByte_MACRO, "add" },
	{ 0xFF, trefiveByte_MACRO, "add" },


};

/*                                    */






/*                                    */

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

#endif __DISASM_H__