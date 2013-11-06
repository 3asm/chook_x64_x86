/*
	This file contains the possible hook methods used to overwrite the beginning of the API to redirect 
	the execution flow to other function. The hook methods must be passed as a byte vector that describe
	a sequence of assembly instructions which will redirect the execution flow to some other function. 
	The address of the other function should be passed as 0xAABBCCDD in the custom hooking, so it can be 
	possible to the hooking engine identify the point that must be substituted by the function address 
	that is dynamically generated. Also, the vector  that contains the instructions must end with 0xFFFF 
	in order to be possible to count the number of bytes presented in the vector.
*/
#ifdef _M_IX86
static BYTE HookMethod1[] = {0x68,0xAA,0xBB,0xCC,0xDD,0xC3,0xFF,0xFF};
static BYTE postHook1[] = {0x00,0xFF,0xFF};
#else ifdef _M_AMD64
static BYTE HookMethod1[] = {0x48,0xB8,0xAA,0xBB,0xCC,0xDD,0xAA,0xBB,0xCC,0xDD,0xFF,0xE0};
static BYTE postHook1[] = {0x00,0xFF,0xFF};
#endif
/*
	This hooking method correspond to the following assembly instructions:
			PUSH <Address of the function>
			RET
*/
//static BYTE HookMethod2[]= {0xB8,0xAA,0xBB,0xCC,0xDD,0xFF,0xE0,0xFF,0xFF}; 
static BYTE HookMethod2[] = {0x89,0xC3,0xB8,0xAA,0xBB,0xCC,0xDD,0xFF,0xE0,0xFF,0xFF};
static BYTE postHook2[] = {0x89,0xD8,0xFF,0xFF}; 
/*
	This hooking method correspond to the following assembly instructions:
			MOV EBX, EAX
			MOV EAX, <Address of the function>
			JMP EAX
*/
//static BYTE HookMethod3[]= {0x31,0xC0,0xB8,0xAA,0xBB,0xCC,0xDD,0xFF,0xE0,0xFF,0xFF}; 


//static BYTE *Hooks[] = {HookMethod1,HookMethod2};
static BYTE *Hooks[] = {HookMethod1};
/*
	This vector will contain all avaliable hook methods that can be used by the custom hooking engine.
	It is necessary so the custom hooking engine can be found the avaliable hook methods.
*/

//static BYTE *postHooks[] = {postHook1,postHook2};
static BYTE *postHooks[] = {postHook1};