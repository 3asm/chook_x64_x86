#pragma comment(lib, "customHook.lib")
/*
	Function that will choose one of the hooking methods avaliable and rewrite the orgFuncAddr with it.
	It will also redirect the execution flow of the orgFunc to the callbackFunc.
*/
bool HookAttach(DWORD orgFunc,DWORD trampolineAddr,DWORD callbackFunc);
/*
	Function that restore the function in realAddr removing a custom hooking previously implemented.
	trampolineAddr must inform the address of the trampoline function obtained from a previously call to
	HookAttach.
*/
bool HookDetach(DWORD realAddr,DWORD trampolineAddr);



