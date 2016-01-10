#pragma once

#include "stdafx.h"
#include "ExceptionUnwind.h"

//
// Define AMD64 exception handling structures and function prototypes.
//
// Define unwind operation codes.
//

typedef enum _UNWIND_OP_CODES {
	UWOP_PUSH_NONVOL = 0,
	UWOP_ALLOC_LARGE,
	UWOP_ALLOC_SMALL,
	UWOP_SET_FPREG,
	UWOP_SAVE_NONVOL,
	UWOP_SAVE_NONVOL_FAR,
	UWOP_SAVE_XMM,
	UWOP_SAVE_XMM_FAR,
	UWOP_SAVE_XMM128,
	UWOP_SAVE_XMM128_FAR,
	UWOP_PUSH_MACHFRAME
} UNWIND_OP_CODES, *PUNWIND_OP_CODES;

typedef enum _UnwindRegisters
{
	RAX = 0,
	XMM0 = 0,
	RCX = 1,
	XMM1 = 1,
	RDX = 2,
	XMM2 = 2,
	RBX = 3,
	XMM3 = 3,
	RSP = 4,
	XMM4 = 4,
	RBP = 5,
	XMM5 = 5,
	RSI = 6,
	XMM6 = 6,
	RDI = 7,
	R8 = 8,
	R9 = 9,
	R10 = 10,
	R11 = 11,
	R12 = 12,
	R13 = 13,
	R14 = 14,
	R15 = 15
} UnwindRegisters;

//
// Define unwind code structure.
//
#pragma warning (disable:4214)
typedef union _UNWIND_CODE {
	struct {
		UCHAR CodeOffset;
		UCHAR UnwindOp : 4;
		UCHAR OpInfo : 4;
	};

	USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO {
	UCHAR Version : 3;
	UCHAR Flags : 5;
	UCHAR SizeOfProlog;
	UCHAR CountOfUnwindCodes;
	UCHAR FrameRegister : 4;
	UCHAR FrameOffset : 4;
	UNWIND_CODE UnwindCode[1];

	//
	// The unwind codes are followed by an optional DWORD aligned field that
	// contains the exception handler address or the address of chained unwind
	// information. If an exception handler address is specified, then it is
	// followed by the language specified exception handler data.
	//
	//  union {
	//      ULONG ExceptionHandler;
	//      ULONG FunctionEntry;
	//  };
	//
	//  ULONG ExceptionData[];
	//

} UNWIND_INFO, *PUNWIND_INFO;


