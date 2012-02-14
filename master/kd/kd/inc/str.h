#ifndef __STR_H__
#define __STR_H__


#define KD_PORT_NAME   L"\\KDbgPort"

typedef enum _STRUCT_COMMAND {

	about

}STRUCT_COMMAND;

typedef struct _COMMAND_MESSAGE {

    STRUCT_COMMAND Command;
 
} COMMAND_MESSAGE, *PCOMMAND_MESSAGE;

#endif