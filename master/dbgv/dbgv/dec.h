#ifndef __DEC_H__
#define __DEC_H__

#include <Windows.h>

VOID Step
	(__in PBYTE pByte,
	 __in LPDEBUG_EVENT DbgEvent,
	 __in HANDLE hProcess,
	 __in HANDLE hThread);

extern "C" void NTAPI ClearBpOnTar
	(__in PBYTE pTar,
	 __in HANDLE hProcess);

/* PE */

IMAGE_DOS_HEADER * mz;
IMAGE_NT_HEADERS * pe;
BYTE * buf;

/* */

/* Flag */
#define FUNC_ADD        0x02   //istruzione che indirizza in memoria
#define NO_SIB          0x0f   //istruzione senza sib
#define SIB_PRESENT     0x10

BOOL ds_flag = FALSE;
BOOL cs_flag = FALSE;
BOOL es_flag = FALSE;
BOOL gs_flag = FALSE;
BOOL fs_flag = FALSE;
BOOL ss_flag = FALSE;

typedef PBYTE (NTAPI *DISASM_FUNC) (struct _INSTRUCTION_TABLE* pInsTab,                
			            PBYTE pb_from,
				    BOOL stepIn); 
             


typedef struct _PONTE {

	BYTE copied[30];   //istruzioni copiate
	BYTE f_codeSize;   //grandezza di ^
	PBYTE pstay;       //puntatore alla prima istruzione non copiata
	PVOID phook;       //puntatore alla prima istruzione dell'hook

}PONTE, *PPONTE;

char dwReg[8][8] = { "eax", "ecx", "edx", "edx", "esp",  "ebp", "esi", "edi" };

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
	BOOL inMem; //for the difference between mov r, rm and mov rm, r
	ULONG relOff;
	char Name[8];

}INSTRUCTION_TABLE, *PINSTRUCTION_TABLE;

PINSTRUCTION_TABLE pInsTab;

//typedef PBYTE ( *DISASM_FUNC)(PINSTRUCTION_TABLE pInsTab, PBYTE p_where, PBYTE pb_from);
BOOL opsize_override = FALSE;
BOOL addsize_override = FALSE;
BOOL seg_fs = FALSE;
BOOL modrm_on = FALSE;

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


#endif __DEC_H__