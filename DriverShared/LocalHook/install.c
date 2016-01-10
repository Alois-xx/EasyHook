// EasyHook (File: EasyHookDll\install.c)
//
// Copyright (c) 2009 Christoph Husse & Copyright (c) 2015 Justin Stenning
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// Please visit https://easyhook.github.io for more information
// about the project and latest updates.

#include "stdafx.h"
#include "ExceptionUnwind.h"

// Disable warning C4276: no prototype provided; assumed no parameters
// For ASM functions
#pragma warning(disable: 4276)


LOCAL_HOOK_INFO             GlobalHookListHead;
LOCAL_HOOK_INFO             GlobalRemovalListHead;
RTL_SPIN_LOCK               GlobalHookLock;
ULONG                       GlobalSlotList[MAX_HOOK_COUNT];
UINT_PTR                    GlobalHookReturnAddresses[MAX_HOOK_COUNT];

static LONG                 UniqueIDCounter = 0x10000000;

void LhCriticalInitialize()
{
/*
Description:
    
    Fail safe initialization of global hooking structures...
*/
    RtlZeroMemory(&GlobalHookListHead, sizeof(GlobalHookListHead));
    RtlZeroMemory(&GlobalRemovalListHead, sizeof(GlobalRemovalListHead));
	RtlZeroMemory(&GlobalHookReturnAddresses[0], sizeof(GlobalHookReturnAddresses));
    RtlInitializeLock(&GlobalHookLock);
}





EASYHOOK_BOOL_INTERNAL LhIsValidHandle(
            TRACED_HOOK_HANDLE InTracedHandle,
            PLOCAL_HOOK_INFO* OutHandle)
{
/*
Description:

    A handle is considered to be valid, if the whole structure
    points to valid memory AND the signature is valid AND the
    hook is installed!

*/
    if(!IsValidPointer(InTracedHandle, sizeof(HOOK_TRACE_INFO)))
        return FALSE;

    if(!IsValidPointer(InTracedHandle->Link, sizeof(LOCAL_HOOK_INFO)))
        return FALSE;

    if(InTracedHandle->Link->Signature != LOCAL_HOOK_SIGNATURE)
        return FALSE;

    if(!IsValidPointer(InTracedHandle->Link, InTracedHandle->Link->NativeSize))
        return FALSE;

    if(InTracedHandle->Link->HookProc == NULL)
        return FALSE;

    if(OutHandle != NULL)
        *OutHandle = InTracedHandle->Link;

    return TRUE;
}

void RegisterReturnAddres(LOCAL_HOOK_INFO *pHook)
{
	// Save NetOutro code address for later backpatching to make stackwalks possible after the intercepted method as been called
	RtlAcquireLock(&GlobalHookLock);
	{
		int i = 0;
		for (i = 0; i < MAX_HOOK_COUNT; i++)
		{
			if (GlobalHookReturnAddresses[i] == 0)
			{
				GlobalHookReturnAddresses[i] = (UINT_PTR)(pHook + 1) + (GetNetOutroPtr() - GetTrampolinePtr());
				break;
			}
		}
		ASSERT(i != MAX_HOOK_COUNT, L"Could not insert .NET outro pointer!");
	}
	RtlReleaseLock(&GlobalHookLock);
}

#ifdef _M_X64
// AddUnwindInfos makes debugging with full call stack possible when entering the dynamically generate assembly code up to a certain point
// when the stack return address is overwritten. Because the backpatch handler will call a method to patch the stack return address back we
// get under x64 by definition unwalkable stacks. 
// That problem could be circumvented by creating synthetic stack frames while copying the local data but that would be very complex and I am not even
// sure if this can ever work reliable. Instead we backpatch the original return address in LhBarrierBeginStackTrace even when we are not inside
// the hook handler which was a limitation of the original EasyHook implementation. 
// That prevented us from getting the callstack after we have called the original method to inspect the return code, or returned handle, ... to tracie
// it via ETW events which need a walkable stack.
void AddUnwindInfos(LOCAL_HOOK_INFO *pHook, int trampolineSize)
{
	// Everything defined here is tightly coupled to the function prolog of Trampoline_ASM_x64
	// If you change the code of the trampoline you need to adjust the offsets and codes here as well or x64 stackwalks will break!
	// Usually I look at the disassembled code in Windbg and then calculate the offsets by OffsetOf(NextInstructionAfterStackAllocation) - MethodStart
	//
	//	00007ff8`883c0298 488bc4          mov     rax,rsp  .CodeOffset 0
	//	00007ff8`883c029b 51              push    rcx      29c-298 = .CodeOffset = 4  (  = Offset next instruction - method entry )
	//	00007ff8`883c029c 52              push    rdx    ...
	//	00007ff8`883c029d 4150            push    r8
	//	00007ff8`883c029f 4151            push    r9
	//	00007ff8`883c02a1 55              push    rbp
	
	#define TrampolineUnwindCodesCount  15

	// this initializer only works in C. C++ has no good initializer syntax for structs/unions!
	const UNWIND_CODE TrampolineUnwindCodes[TrampolineUnwindCodesCount] = {
		{ .CodeOffset = 38,  .UnwindOp = UWOP_SAVE_XMM128, .OpInfo = XMM3    },  // movups  xmmword ptr [rsp+50h],xmm3
	    { .FrameOffset = 5                                                   },
		{ .CodeOffset = 33,  .UnwindOp = UWOP_SAVE_XMM128, .OpInfo = XMM2,   },  // movups  xmmword ptr[rsp + 40h], xmm2
		{ .FrameOffset = 4                                                   },
		{ .CodeOffset = 28,  .UnwindOp = UWOP_SAVE_XMM128, .OpInfo = XMM1,   },  //  movups  xmmword ptr[rsp + 30h], xmm1
		{ .FrameOffset = 3                                                   },
		{ .CodeOffset = 23,  .UnwindOp = UWOP_SAVE_XMM128, .OpInfo = XMM0,   },  //  movups  xmmword ptr[rsp + 20h], xmm0
		{ .FrameOffset = 2                                                   },
		{ .CodeOffset = 18,  .UnwindOp = UWOP_SET_FPREG,   .OpInfo = 0       },  // lea     rbp,[rsp]
		{ .CodeOffset = 14,  .UnwindOp = UWOP_ALLOC_SMALL, .OpInfo = 12      },  // sub     rsp,68h => OpInfo=12 = 12*8+8  alloc size is stored in OpInfo 
																		         //  https://msdn.microsoft.com/en-us/library/ck9asaa9.aspx - Allocate a small - sized area on the stack.The size of the allocation is the operation info field * 8 + 8, allowing allocations from 8 to 128 bytes.		                                                                
		{ .CodeOffset = 10,  .UnwindOp = UWOP_PUSH_NONVOL, .OpInfo = RBP     },  // push rbp
		{ .CodeOffset = 9,   .UnwindOp = UWOP_PUSH_NONVOL, .OpInfo = R9      },  // push r9
		{ .CodeOffset = 7,   .UnwindOp = UWOP_PUSH_NONVOL, .OpInfo = R8      },  // push r8
		{ .CodeOffset = 5,   .UnwindOp = UWOP_PUSH_NONVOL, .OpInfo = RDX     },  // push rdx 
		{ .CodeOffset = 4,   .UnwindOp = UWOP_PUSH_NONVOL, .OpInfo = RCX     },  // push rcx 
	};

	memcpy(&pHook->Trampoline_UnwindInfo.UnwindCode[0], TrampolineUnwindCodes, sizeof(TrampolineUnwindCodes));

	PUNWIND_INFO pUnwindInfo = &pHook->Trampoline_UnwindInfo;

	pUnwindInfo->FrameOffset = 0;
	pUnwindInfo->FrameRegister = RBP;
	pUnwindInfo->Version = 1;
	pUnwindInfo->SizeOfProlog = 45;
	pUnwindInfo->CountOfUnwindCodes = TrampolineUnwindCodesCount;
	pUnwindInfo->Flags = UNW_FLAG_NHANDLER;

	// _IMAGE_RUNTIME_FUNCTION_ENTRY addresses are relative addresses to the base address we choose in RtlAddFunctionTable
	// pHook points to the start of the newly allocated page for our trampoline code
	// After pHook comes the trampoline code for which we need to register unwind information
	pHook->Trampoline_RuntimeFunction.BeginAddress = (DWORD) (pHook->Trampoline - (byte *)pHook);
	pHook->Trampoline_RuntimeFunction.EndAddress = pHook->Trampoline_RuntimeFunction.BeginAddress + 177; // 177 is correct offset pointing to the next instruction after the final ret/jmp statement
	pHook->Trampoline_RuntimeFunction.UnwindInfoAddress = (DWORD) ((byte*)&pHook->Trampoline_UnwindInfo - (byte *)pHook);

	BOOLEAN lret = RtlAddFunctionTable(&pHook->Trampoline_RuntimeFunction, 1, (DWORD64) pHook);
	ASSERT(lret, L"RTLAddFunctionTable failed");

	#define NetOutroUnwindCodeCount  5

	// Register unwind codes for .NET Outro function
	pUnwindInfo = &pHook->Trampoline_Net_Outro_UnwindInfo;
	pUnwindInfo->FrameOffset = 0;
	pUnwindInfo->FrameRegister = 0;
	pUnwindInfo->Version = 1;
	pUnwindInfo->SizeOfProlog = 12;
	pUnwindInfo->CountOfUnwindCodes = NetOutroUnwindCodeCount;
	pUnwindInfo->Flags = UNW_FLAG_NHANDLER;

	const UNWIND_CODE NetOutroUwindCodes[NetOutroUnwindCodeCount] = {
		{ .CodeOffset = 12, .UnwindOp = UWOP_SAVE_XMM128, .OpInfo = XMM0,  },  // movups  xmmword ptr[rsp + 20h], xmm0
		{ .FrameOffset = 1                                                 },
	    { .CodeOffset = 7,  .UnwindOp = UWOP_ALLOC_SMALL, .OpInfo = 5      },  // sub     rsp,30h   alloc size is stored in OpInfo and is 8*11+8 per definition of 
	    { .CodeOffset = 3,  .UnwindOp = UWOP_PUSH_NONVOL, .OpInfo = RAX    },  // push rax
		{ .CodeOffset = 2,  .UnwindOp = UWOP_ALLOC_SMALL, .OpInfo = 0      }  // push 0
	};

	memcpy(&pHook->Trampoline_Net_Outro_UnwindInfo.UnwindCode[0], NetOutroUwindCodes, sizeof(NetOutroUwindCodes));
	pHook->Trampoline_Net_Outro_RuntimeFunction.BeginAddress = pHook->Trampoline_RuntimeFunction.BeginAddress + (DWORD) (GetNetOutroPtr()  - GetTrampolinePtr());
	pHook->Trampoline_Net_Outro_RuntimeFunction.EndAddress = pHook->Trampoline_Net_Outro_RuntimeFunction.BeginAddress + 55;
	pHook->Trampoline_Net_Outro_RuntimeFunction.UnwindInfoAddress = (DWORD)  ((byte*)pUnwindInfo - (byte *)pHook);
	lret = RtlAddFunctionTable(&pHook->Trampoline_Net_Outro_RuntimeFunction, 1, (DWORD64)pHook);

	ASSERT(lret, L"RTLAddFunctionTable failed");
}
#endif

EASYHOOK_NT_INTERNAL LhAllocateHook(
            void* InEntryPoint,
            void* InHookProc,
            void* InCallback,
            LOCAL_HOOK_INFO** OutHook,
            ULONG* RelocSize)
{
/*
Description:

    For internal use only, this method allocates a hook for the given 
    entry point, preparing the redirection of all calls to the given 
    hooking method. Upon completion the original entry point remains
    unchanged.
    
    Originally located within LhInstallHook, this code has been split 
    out to improve testing.

Parameters:

    - InEntryPoint

        An entry point to hook. Not all entry points are hookable. In such
        a case STATUS_NOT_SUPPORTED will be returned.

    - InHookProc

        The method that should be called instead of the given entry point.
        Please note that calling convention, parameter count and return value
        must EXACTLY match the original entry point!

    - InCallback

        An uninterpreted callback later available through
        LhBarrierGetCallback().

    - OutHook

        OutHook will point to a newly allocated Hook, with completed trampoline
        code including relocated entry point. The original entry point is still 
        unchanged at this point.

    - RelocSize

        Will contain the size of the entry point relocation instructions.

Returns:

    STATUS_NO_MEMORY
    
        Unable to allocate memory around the target entry point.
    
    STATUS_NOT_SUPPORTED
    
        The target entry point contains unsupported instructions.
    
    STATUS_INSUFFICIENT_RESOURCES
    
        The limit of MAX_HOOK_COUNT simultaneous hooks was reached.
    
*/

    ULONG           			EntrySize;
    LOCAL_HOOK_INFO*            Hook = NULL;
    LONGLONG          			RelAddr;
    UCHAR*                      MemoryPtr;
    LONG                        NtStatus = STATUS_INTERNAL_ERROR;

#if X64_DRIVER
	// 48 b8 00 00 00 00 00 00 00 00  mov rax, 0x0
	// ff e0                          jmp rax
	UCHAR			            Jumper_x64[12] = {0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0};
#endif

#ifndef _M_X64
    ULONG                       Index;
    UCHAR*			            Ptr;
#endif

    // validate parameters
    if(!IsValidPointer(InEntryPoint, 1))
        THROW(STATUS_INVALID_PARAMETER_1, L"Invalid entry point.");

    if(!IsValidPointer(InHookProc, 1))
        THROW(STATUS_INVALID_PARAMETER_2, L"Invalid hook procedure.");

    // allocate memory for hook, for 64-bit this will be located within a 32-bit relative jump of entry point
	if((*OutHook = (LOCAL_HOOK_INFO*)LhAllocateMemory(InEntryPoint)) == NULL)
        THROW(STATUS_NO_MEMORY, L"Failed to allocate memory.");
    Hook = *OutHook;

    FORCE(RtlProtectMemory(Hook, 4096, PAGE_EXECUTE_READWRITE));

    MemoryPtr = (UCHAR*)(Hook + 1);

    // determine entry point size
#ifdef X64_DRIVER
	FORCE(EntrySize = LhRoundToNextInstruction(InEntryPoint, 12));
#else
    FORCE(EntrySize = LhRoundToNextInstruction(InEntryPoint, 5));
#endif

    // create and initialize hook handle
    Hook->NativeSize = sizeof(LOCAL_HOOK_INFO);
#if !_M_X64
    __pragma(warning(push))
    __pragma(warning(disable:4305))
#endif
    Hook->RandomValue = (void*)0x69FAB738962376EF;
#if !_M_X64
    __pragma(warning(pop))
#endif
    Hook->HookProc = (UCHAR*)InHookProc;
    Hook->TargetProc = (UCHAR*)InEntryPoint;
    Hook->EntrySize = EntrySize;	
    Hook->IsExecutedPtr = (int*)((UCHAR*)Hook + 2048);
    Hook->Callback = InCallback;
    *Hook->IsExecutedPtr = 0;

    /*
	    The following will be called by the trampoline before the user defined handler is invoked.
	    It will setup a proper environment for the hook handler which includes the "fiber deadlock barrier"
	    and user specific callback.
    */
    Hook->HookIntro = (PVOID)LhBarrierIntro;
    Hook->HookOutro = (PVOID)LhBarrierOutro;

    // copy trampoline
    Hook->Trampoline = MemoryPtr; 
    MemoryPtr += GetTrampolineSize();

    Hook->NativeSize += GetTrampolineSize();

    RtlCopyMemory(Hook->Trampoline, GetTrampolinePtr(), GetTrampolineSize());

#if _M_X64
	AddUnwindInfos(Hook, GetTrampolineSize());
#endif

	RegisterReturnAddres(Hook);  // needed for stackwalks outside hook handler

    /*
	    Relocate entry point (the same for both archs)
	    Has to be written directly into the target buffer, because to
	    relocate RIP-relative addressing we need to know where the
	    instruction will go to...
    */
    *RelocSize = 0;
    Hook->OldProc = MemoryPtr; 

    FORCE(LhRelocateEntryPoint(Hook->TargetProc, EntrySize, Hook->OldProc, RelocSize));

    MemoryPtr += *RelocSize + 12;
    Hook->NativeSize += *RelocSize + 12;

    // add jumper to relocated entry point that will proceed execution in original method
#ifdef X64_DRIVER

	// absolute jumper
	RelAddr = (LONGLONG)(Hook->TargetProc + Hook->EntrySize);

	RtlCopyMemory(Hook->OldProc + *RelocSize, Jumper_x64, 12);
	// Set address to be copied into RAX
	RtlCopyMemory(Hook->OldProc + *RelocSize + 2, &RelAddr, 8);

#else

	// relative jumper
    RelAddr = (LONGLONG)(Hook->TargetProc + Hook->EntrySize) - ((LONGLONG)Hook->OldProc + *RelocSize + 5);

	if(RelAddr != (LONG)RelAddr)
		THROW(STATUS_NOT_SUPPORTED, L"The given entry point is out of reach.");

    Hook->OldProc[*RelocSize] = 0xE9;

    RtlCopyMemory(Hook->OldProc + *RelocSize + 1, &RelAddr, 4);

#endif

    // backup original entry point
    Hook->TargetBackup = *((ULONGLONG*)Hook->TargetProc); 

#ifdef X64_DRIVER
	Hook->TargetBackup_x64 = *((ULONGLONG*)(Hook->TargetProc + 8)); 
#endif

#ifndef _M_X64

    /*
	    Replace absolute placeholders with proper addresses...
    */
    Ptr = Hook->Trampoline;

    for(Index = 0; Index < GetTrampolineSize(); Index++)
    {
    #pragma warning (disable:4311) // pointer truncation
	    switch(*((ULONG*)(Ptr)))
	    {
	    /*Handle*/			case 0x1A2B3C05: *((ULONG*)Ptr) = (ULONG)Hook; break;
	    /*UnmanagedIntro*/	case 0x1A2B3C03: *((ULONG*)Ptr) = (ULONG)Hook->HookIntro; break;
	    /*OldProc*/			case 0x1A2B3C01: *((ULONG*)Ptr) = (ULONG)Hook->OldProc; break;
	    /*Ptr:NewProc*/		case 0x1A2B3C07: *((ULONG*)Ptr) = (ULONG)&Hook->HookProc; break;
	    /*NewProc*/			case 0x1A2B3C00: *((ULONG*)Ptr) = (ULONG)Hook->HookProc; break;
	    /*UnmanagedOutro*/	case 0x1A2B3C06: *((ULONG*)Ptr) = (ULONG)Hook->HookOutro; break;
	    /*IsExecuted*/		case 0x1A2B3C02: *((ULONG*)Ptr) = (ULONG)Hook->IsExecutedPtr; break;
	    /*RetAddr*/			case 0x1A2B3C04: *((ULONG*)Ptr) = (ULONG)(Hook->Trampoline + 94); break;
	    }

	    Ptr++;
    }
#endif

    RETURN(STATUS_SUCCESS);

THROW_OUTRO:
FINALLY_OUTRO:
    {
        if(!RTL_SUCCESS(NtStatus))
        {
	        if(Hook != NULL)
	            LhFreeMemory(&Hook);
        }

        return NtStatus;
    }
}






EASYHOOK_NT_EXPORT LhInstallHook(
            void* InEntryPoint,
            void* InHookProc,
            void* InCallback,
            TRACED_HOOK_HANDLE OutHandle)
{
/*
Description:

    Installs a hook at the given entry point, redirecting all
    calls to the given hooking method. The returned handle will
    either be released on library unloading or explicitly through
    LhUninstallHook() or LhUninstallAllHooks().

Parameters:

    - InEntryPoint

        An entry point to hook. Not all entry points are hookable. In such
        a case STATUS_NOT_SUPPORTED will be returned.

    - InHookProc

        The method that should be called instead of the given entry point.
        Please note that calling convention, parameter count and return value
        shall match EXACTLY!

    - InCallback

        An uninterpreted callback later available through
        LhBarrierGetCallback().

    - OutPHandle

        The memory portion supplied by *OutHandle is expected to be preallocated
        by the caller. This structure is then filled by the method on success and
        must stay valid for hook-life time. Only if you explicitly call one of
        the hook uninstallation APIs, you can safely release the handle memory.

Returns:

    STATUS_NO_MEMORY
    
        Unable to allocate memory around the target entry point.
    
    STATUS_NOT_SUPPORTED
    
        The target entry point contains unsupported instructions.
    
    STATUS_INSUFFICIENT_RESOURCES
    
        The limit of MAX_HOOK_COUNT simultaneous hooks was reached.
    
*/
    LOCAL_HOOK_INFO*			Hook = NULL;
    ULONG                       Index;
    LONGLONG          			RelAddr;
    ULONG           			RelocSize;
    UCHAR			            Jumper[12] = {0xE9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ULONGLONG                   AtomicCache;
    BOOL                        Exists;
    LONG                        NtStatus = STATUS_INTERNAL_ERROR;

#if X64_DRIVER
	// 48 b8 00 00 00 00 00 00 00 00  mov rax, 0x0
	// ff e0                          jmp rax
	UCHAR			            Jumper_x64[12] = {0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0};
	ULONGLONG					AtomicCache_x64;
	KIRQL						CurrentIRQL = PASSIVE_LEVEL;
#endif

    // validate parameters
    if(!IsValidPointer(InEntryPoint, 1))
        THROW(STATUS_INVALID_PARAMETER_1, L"Invalid entry point.");

    if(!IsValidPointer(InHookProc, 1))
        THROW(STATUS_INVALID_PARAMETER_2, L"Invalid hook procedure.");

    if(!IsValidPointer(OutHandle, sizeof(HOOK_TRACE_INFO)))
        THROW(STATUS_INVALID_PARAMETER_4, L"The hook handle storage is expected to be allocated by the caller.");

    if(OutHandle->Link != NULL)
        THROW(STATUS_INVALID_PARAMETER_4, L"The given trace handle seems to already be associated with a hook.");

    // allocate hook and prepare trampoline / hook stub
    FORCE(LhAllocateHook(InEntryPoint, InHookProc, InCallback, &Hook, &RelocSize));
    
	// Prepare jumper from entry point to hook stub...
#if X64_DRIVER

	// absolute jumper
	RelAddr = (ULONGLONG)Hook->Trampoline;

	RtlCopyMemory(Jumper, Jumper_x64, 12);
	// Set address to be copied into RAX
	RtlCopyMemory(Jumper + 2, &RelAddr, 8);

#else

	// relative jumper
    RelAddr = (LONGLONG)Hook->Trampoline - ((LONGLONG)Hook->TargetProc + 5);

	if(RelAddr != (LONG)RelAddr)
		THROW(STATUS_NOT_SUPPORTED, L"The given entry point is out of reach.");

    RtlCopyMemory(Jumper + 1, &RelAddr, 4);

    FORCE(RtlProtectMemory(Hook->TargetProc, Hook->EntrySize, PAGE_EXECUTE_READWRITE));
#endif

    // register in global HLS list
    RtlAcquireLock(&GlobalHookLock);
    {
		Hook->HLSIdent = UniqueIDCounter++;

		Exists = FALSE;

        for(Index = 0; Index < MAX_HOOK_COUNT; Index++)
        {
	        if(GlobalSlotList[Index] == 0)
	        {
		        GlobalSlotList[Index] = Hook->HLSIdent;

		        Hook->HLSIndex = Index;

		        Exists = TRUE;

		        break;
	        }
        }
    }
    RtlReleaseLock(&GlobalHookLock);

	// ATTENTION: This must be the last THROW!!!!
    if(!Exists)
	    THROW(STATUS_INSUFFICIENT_RESOURCES, L"Not more than MAX_HOOK_COUNT hooks are supported simultaneously.");

    // from now on the unrecoverable code section starts...
#ifdef X64_DRIVER

	AtomicCache = *((ULONGLONG*)(Hook->TargetProc + 8));
    {
		RtlCopyMemory(&AtomicCache_x64, Jumper, 8);
	    RtlCopyMemory(&AtomicCache, Jumper + 8, 4);

		// backup entry point for later comparison
	    Hook->HookCopy = AtomicCache_x64;
    }
	CurrentIRQL = KeGetCurrentIrql();
	RtlWPOff();
	*((ULONGLONG*)(Hook->TargetProc + 0)) = AtomicCache_x64;
    *((ULONGLONG*)(Hook->TargetProc + 8)) = AtomicCache;
	RtlWPOn(CurrentIRQL);

#else

    AtomicCache = *((ULONGLONG*)Hook->TargetProc);
    {
	    RtlCopyMemory(&AtomicCache, Jumper, 5);

	    // backup entry point for later comparison
	    Hook->HookCopy = AtomicCache;
    }
    *((ULONGLONG*)Hook->TargetProc) = AtomicCache;

#endif

    /*
        Add hook to global list and return handle...
    */
    RtlAcquireLock(&GlobalHookLock);
    {
        Hook->Next = GlobalHookListHead.Next;
        GlobalHookListHead.Next = Hook;
    }
    RtlReleaseLock(&GlobalHookLock);

    Hook->Signature = LOCAL_HOOK_SIGNATURE;
    Hook->Tracking = OutHandle;
    OutHandle->Link = Hook;

    RETURN(STATUS_SUCCESS);

THROW_OUTRO:
FINALLY_OUTRO:
    {
        if(!RTL_SUCCESS(NtStatus))
        {
	        if(Hook != NULL)
	            LhFreeMemory(&Hook);
        }

        return NtStatus;
    }
}

/*////////////////////// GetTrampolineSize

DESCRIPTION:

	Will dynamically detect the size in bytes of the assembler code stored
	in "HookSpecifix_x##.asm".
*/
static ULONG ___TrampolineSize = 0;

#ifdef _M_X64
	EXTERN_C void __stdcall Trampoline_ASM_x64();
#else
	EXTERN_C void __stdcall Trampoline_ASM_x86();
#endif


#ifdef _M_X64
	EXTERN_C void __stdcall Trampoline_ASM_x64_Net_Outro();
#else 
	EXTERN_C void __stdcall Trampoline_ASM_x86_Net_Outro();
#endif

UCHAR* GetNetOutroPtr()
{
#ifdef _M_X64
	UCHAR* Ptr = (UCHAR*)Trampoline_ASM_x64_Net_Outro;
#else
	UCHAR* Ptr = (UCHAR*)Trampoline_ASM_x86_Net_Outro;
#endif

	if (*Ptr == 0xE9)
		Ptr += *((int*)(Ptr + 1)) + 5;
	return Ptr;
}


UCHAR* GetTrampolinePtr()
{
// bypass possible Visual Studio debug jump table
#ifdef _M_X64
	UCHAR* Ptr = (UCHAR*)Trampoline_ASM_x64;
#else
	UCHAR* Ptr = (UCHAR*)Trampoline_ASM_x86;
#endif

	if(*Ptr == 0xE9)
		Ptr += *((int*)(Ptr + 1)) + 5;

	return Ptr;
}

ULONG GetTrampolineSize()
{
    UCHAR*		Ptr = GetTrampolinePtr();
	UCHAR*		BasePtr = Ptr;
    ULONG       Signature;
    ULONG       Index;

	if(___TrampolineSize != 0)
		return ___TrampolineSize;
	
	// search for signature
	for(Index = 0; Index < 2000 /* some always large enough value*/; Index++)
	{
		Signature = *((ULONG*)Ptr);

		if(Signature == 0x12345678)	
		{
			___TrampolineSize = (ULONG)(Ptr - BasePtr);

			return ___TrampolineSize;
		}

		Ptr++;
	}

    ASSERT(FALSE,L"install.c - ULONG GetTrampolineSize()");

    return 0;
}