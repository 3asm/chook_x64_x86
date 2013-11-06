#include <windows.h>

#if !defined( _AFXDLL )
#define DllExport

#else

#define DllExport __declspec( dllexport)

#endif // !defined( _AFXDLL ) || defined( _XT_STATICLINK )
#ifndef _CHOOK_H_
#define _CHOOK_H_

//Debug option
//#define DEBUG

//Max instruction to disasm in the prolog of the API to hook.
#define MAX_INSTR 5

#ifdef _M_IX86
#pragma comment(lib, "distorm3.lib")
#else ifdef _M_AMD64
#pragma comment(lib, "distorm3.64.lib")
#endif
/*
	Function that will choose one of the hooking methods avaliable and rewrite the orgFuncAddr with it.
	It will also redirect the execution flow of the orgFunc to the callbackFunc.
*/
//extern __declspec(dllexport) bool HookAttach(ULONG_PTR orgFunc,ULONG_PTR trampolineAddr,ULONG_PTR callbackFunc);
bool HookAttach(ULONG_PTR orgFunc,ULONG_PTR trampolineAddr,ULONG_PTR callbackFunc);
//bool HookAttach(DWORD orgFunc,DWORD trampolineAddr,DWORD callbackFunc);
/*
	Function that restore the function in realAddr removing a custom hooking previously implemented.
	trampolineAddr must inform the address of the trampoline function obtained from a previously call to
	HookAttach.
*/
//extern __declspec(dllexport) bool HookDetach(ULONG_PTR realAddr,ULONG_PTR trampolineAddr);
bool HookDetach(ULONG_PTR realAddr,ULONG_PTR trampolineAddr);
//bool HookDetach(DWORD realAddr,DWORD trampolineAddr);

#endif //
