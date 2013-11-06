#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <strsafe.h>
#include "distorm.h"
#include "mnemonics.h"
#include "customHook.h"
#include "hookTemplate.h"

//Max number of assembly instruction supported to substitute by hook method.
#define MAX_INSTRUCTIONS 128

//Some assembly definitions.
#define mov_ebx 0xBB

#define push 0x68
#define ret 0xC3

#define rel_jmp 0xE9



#define jmp_ebx1 0xFF
#define jmp_ebx2 0xE3

void printDebug(ULONG_PTR Addr){
	//Print assembly code from Addr. 
	int length  = 0, i = 0;
	_DecodeResult res;
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
	char * debugString = (char *)calloc(1024,sizeof(char));
	char * line = (char *)calloc(128,sizeof(char));
	unsigned int decodedInstructionsCount = 0;
	// Decode the buffer at given offset (virtual address).

#ifdef _M_IX86
	_DecodeType decodeType = Decode32Bits;
#else ifdef _M_AMD64
	_DecodeType decodeType = Decode64Bits;
#endif

	res = distorm_decode(0,(const unsigned char *)Addr, 32, decodeType, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount); 
	if (res == DECRES_INPUTERR) { 
		return;
	}  
	for(i = 0; i < (int)decodedInstructionsCount; i++){
		sprintf_s(line,128,"%0*I32x (%02d) %-24s %s%s%s\n", Decode32Bits != Decode64Bits ? 8 : 16, decodedInstructions[i].offset, decodedInstructions[i].size, (char*)decodedInstructions[i].instructionHex.p, (char*)decodedInstructions[i].mnemonic.p, decodedInstructions[i].operands.length != 0 ? " " : "", (char*)decodedInstructions[i].operands.p);
		StringCbCatN(debugString,1024,line,128);
	}
	OutputDebugString(debugString);
	free(debugString);
	free(line);
	return;
}
int findRet(ULONG_PTR baseAddress, int maxInstrRead){
	/*
	This function will check if exist a instruction RET in the piece of code that must be oweritten.
	The parameters are:
		vector with the informations provided by the disasm of the prolog of the API, indicated in decodedInstructions.
		the max number o instructions that can be oweritten.
	*/

	int  i = 0;
	DWORD readedInstr = 0;
	_CodeInfo ci;
	unsigned int     decodedInstructionsCount = 0;
	_DInst           decodedInstructions[MAX_INSTRUCTIONS];

	//Fill the structure used by distorm.
	ci.code = (unsigned char *)baseAddress;
	ci.codeLen = 32;
	ci.codeOffset = 0;
#ifdef _M_IX86
	ci.dt = Decode32Bits;
#else ifdef _M_AMD64
	ci.dt = Decode64Bits;
#endif
	ci.dt = Decode32Bits;
	ci.features = DF_NONE;

	//Disasm the beginning of the Api to hook.
	distorm_decompose(&ci,decodedInstructions,MAX_INSTRUCTIONS,&decodedInstructionsCount);
	for(i = 0; i < maxInstrRead; i++){
		if(decodedInstructions[i].flags == FLAG_NOT_DECODABLE){
#ifdef _DEBUG
			OutputDebugString("[*] Can`t disasm the trampoline!!\n");
#endif
			return 0;
		}
		//Check on the instructions present in the trampoline
		if(decodedInstructions[i].opcode == I_RET){
			//If exist a RET instruction, get the total of instructions readed so far
			//and return the value.
			readedInstr = i;
			break;
		}
	}
	return readedInstr;
}

void findCallJmp(DWORD baseAddress,BYTE * newInstr,_DInst decodedInstructions[], int instrRead,int pushRetAddress){
	/*
	This function will check if exist a relative call in the trampoline. If yes, the function will obtain the absolute address
	and will append a push ret on the end of the trampoline to that address.
	The parameters are:
		baseAddress of the API being Hooked.
		pointer to the trampoline, indicated by newInstr.
		vector with the informations provided by the disasm of the prolog of the API, indicated in decodedInstructions.
		number of instructions readed by the disasm, indicated in instrRead.
		address of the trampoline end, indicated in pushRetAddress.
	*/
	int  i = 0;
	DWORD nextAddress = 0, instrPoint = 0, retAddr = 0;
	DWORD *dwPtr = NULL;
		DWORD            dwOldProtect = 0;
	for(i = 0; i < instrRead; i++){
		if(decodedInstructions[i].flags == FLAG_NOT_DECODABLE){
#ifdef _DEBUG
			OutputDebugString("[*] Can`t disasm the trampoline!!\n");
#endif
			return;
		}
		//Check on the instructions present in the trampoline
		if(decodedInstructions[i].opcode == I_RET){
			//If exist a relative CALL
			//Address of the next instruction.
			instrPoint =  baseAddress + (DWORD)decodedInstructions[i].addr;
			//Absolute address used by the call.
			nextAddress = baseAddress + (DWORD)INSTRUCTION_GET_TARGET(&decodedInstructions[i]) ;
			//Relative address of the push ret at the end of the trampoline. Will be used in the original CALL instruction.
			retAddr = (baseAddress + pushRetAddress) - (instrPoint + decodedInstructions[i].size);
			//Address of the push ret instruction which will use the absolute address of the call.
			dwPtr = (DWORD *)&(newInstr[(DWORD)decodedInstructions[i].addr + 1]);
			*dwPtr = (DWORD)retAddr;
			/*
			newInstr[pushRetAddress] = rel_jmp;             
			dwPtr = (DWORD *)&(newInstr[pushRetAddress+1]);

			//Must calculate the relative address
			*dwPtr = nextAddress;
			*dwPtr = ((nextAddress)-(retAddr)-5);
			*/
			/*Fill the end of the trampoline with
			MOV EBX, <ABSOLUTE ADDRESS>
			JMP EBX
			*/
			newInstr[pushRetAddress] = mov_ebx;
			dwPtr = (DWORD *)&(newInstr[pushRetAddress+1]);
			*dwPtr = nextAddress;
			newInstr[pushRetAddress+5] = jmp_ebx1;
			newInstr[pushRetAddress+6] = jmp_ebx2;
		}
		
	}
	return;
}

int bytesNumber(BYTE *arrayBytes){
	//TODO: this should be replaced with a hook structure which indicates size and end caracter
	//Count the number of bytes present in the hook vector which ends in 0xFFFF. 
	int i = 0;
	//While is not the end of the byte vector.

#ifdef _M_IX86
	while(arrayBytes[i] != 0xFF || arrayBytes[i+1] != 0xFF){
#else ifdef _M_AMD64
	while(arrayBytes[i] != 0xE0){
#endif
		i++;
	}

#ifdef _M_AMD64
	i++;
#endif

	return i;
}

BYTE * inlineHookMethod(ULONG_PTR callbackFunc, int *sizeHook, ULONG_PTR apiFunc, BYTE *postTrampoline, int *sizePostTrampoline){
	/*
	This function will chose amoung a set of inline hooking method avaliable. 
	It will return a buffer to subscribe in the beginning of the function.
	The apiFunc parameter indicates the address of the function that must be hooked. It will
	be necessary to check if the prolog of the function have an RET instruction.
	*/
	int    length = 0, i = 0, sizeInstr = 0, hookNumber = 0, hookNumbers = 0, maxSizeHook = 0;
	BYTE  *newInstr = NULL;
	BYTE  *hookMethod = NULL;
	BYTE  *postHookMethod = NULL;
	ULONG_PTR *dwPtr = NULL;


	//Seed the random number generator.
	srand((unsigned int) GetTickCount()*callbackFunc);
	//Get the max number of instructions to disasm
	maxSizeHook = findRet(callbackFunc,MAX_INSTR);

	hookNumbers = (sizeof(Hooks)/sizeof(BYTE*));
	//Check which hooks can be used because of the size.
	if(maxSizeHook == 0){//If there`s no restriction about the size of the hook.
		//Randonly chose one of the hook methods avaliable.
		hookNumber = (rand())%(hookNumbers);
	}
	else{
		//If there`s a RET instruction that limit`s the
		//hook method size, use the smallest hook method.
		hookNumber = 0;
	}
	//Choose one of the hooking methods available.
	hookMethod = Hooks[hookNumber];
	postHookMethod = postHooks[hookNumber];
	if(postHookMethod[0] != 0x00){
		//Must put some instructions in the beggining of the hook and also
		//inform that the trampoline must have some instructions.
		*sizePostTrampoline = bytesNumber(postHookMethod);
		CopyMemory(postTrampoline,postHookMethod,*sizePostTrampoline);
	}
	else{
		sizePostTrampoline = 0;
	}
	//Get the size in bytes of the hook method chosed.
	sizeInstr = bytesNumber(hookMethod);
	newInstr = (BYTE *)calloc(sizeInstr,sizeof(BYTE));
	if (newInstr == NULL) {
#ifdef _DEBUG
		OutputDebugString("[*] Problem alocating Hook Method!\n");
#endif
		return NULL;
	}

	//Copy the content of the hook instruction.
	CopyMemory(newInstr,hookMethod,sizeInstr);

	//Search on the instructions for the address template.
	while(i < sizeInstr){
		//We have found the address template to substitute.
		if(newInstr[i] == 0xAA){
			dwPtr = (ULONG_PTR *)&(newInstr[i]);
			break;
		}
		i++;
	}
	
	//Fill the address of the Prolog Hook Function. 
	*dwPtr = (ULONG_PTR)callbackFunc;
	*sizeHook = sizeInstr;
	return newInstr;
}



bool HookAttach(ULONG_PTR orgFunc,ULONG_PTR trampolineAddr,ULONG_PTR callbackFunc){
	/*
	Function that make the hook and redirect the execution of the orgFunc to a callbackFunc.
	This callbackFunc must call the real function to complete the normal operation of the system.
	orgFunc must be the address of the original API.
	backupFuncAddr must be the address of the trampoline. He must be prealocated and if the size is not enough, HookAttach will reallocate it.
	callbackFunc must be the address of the function that will intercepet the execution flow.
	*/
    
	int				length  = 0, i = 0, sizeHook = 0, instrRead = 0, postHookSize = 0;
	//unsigned int	decodedInstructionsCount = 0;
	//_DInst			decodedInstructions[MAX_INSTRUCTIONS];
	BYTE            *newInstr = NULL;
	BYTE			*newInstrTemp = NULL;
	_CodeInfo		ci;
	BYTE			*backupFunc;
	BYTE			postHook[64];
	ULONG_PTR			*dwPtr = NULL;
	DWORD			dwOldProtect = 0;
	ULONG_PTR		trampoline = trampolineAddr;
	char			dbgString[128];

	ZeroMemory(postHook,64);
#ifdef _DEBUG	
		OutputDebugString("[*] Starting Hook process\n");
#endif
	//Get one of the inline hooking methods avaliable.
	if(orgFunc == 0){
#ifdef _DEBUG
		OutputDebugString("[*] Function with invalid value!!\n");
#endif
		return false;
	}
	if(callbackFunc == 0){
#ifdef _DEBUG
		OutputDebugString("[*] Callback with invalid value!!\n");
#endif
		return false;
	}
	if(trampolineAddr == NULL){
#ifdef _DEBUG
		OutputDebugString("[*] trampoline with invalid value!!\n");
#endif
		return false;
	}
	newInstr = inlineHookMethod(callbackFunc,&sizeHook,orgFunc,postHook,&postHookSize);
	if (newInstr == NULL) {
#ifdef _DEBUG
		OutputDebugString("[*] Problem creating Hook Method!\n");
#endif
		return false;
	}
	/*
	//Fill the structure used by distorm.
	ci.code = (unsigned char *)orgFunc;
	ci.codeLen = 32;
	ci.codeOffset = 0;
#ifdef _M_IX86
	ci.dt = Decode32Bits;
#else ifdef _M_AMD64
	ci.dt = Decode64Bits;
#endif
	ci.features = DF_NONE;

	//Disasm the beginning of the Api to hook.
	distorm_decompose(&ci,decodedInstructions,MAX_INSTRUCTIONS,&decodedInstructionsCount);
	*/
	_DecodeResult res;
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
	unsigned int decodedInstructionsCount = 0;
	// Decode the buffer at given offset (virtual address).

#ifdef _M_IX86
	_DecodeType decodeType = Decode32Bits;
#else ifdef _M_AMD64
	_DecodeType decodeType = Decode64Bits;
#endif

	res = distorm_decode(0,(const unsigned char *)orgFunc, 128, decodeType, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount); 



	/*
#ifdef _DEBUG
	OutputDebugString("[*] decompose 1\n");
	_DecodedInst decodedInst[MAX_INSTRUCTIONS];
	distorm_format(&ci,decodedInstructions,decodedInst);


	char * debugString = (char *)calloc(1024,sizeof(char));
	char * line = (char *)calloc(128,sizeof(char));

	for(i = 0; i < (int)decodedInstructionsCount; i++){
		sprintf_s(line,128,"%0*I32x (%02d) %-24s %s%s%s\n", Decode32Bits != Decode64Bits ? 8 : 16, decodedInst[i].offset, decodedInst[i].size, (char*)decodedInst[i].instructionHex.p, (char*)decodedInst[i].mnemonic.p, decodedInst[i].operands.length != 0 ? " " : "", (char*)decodedInst[i].operands.p);
		StringCbCatN(debugString,1024,line,128);
	}
	OutputDebugString(debugString);
	free(debugString);
	free(line);

	printDebug(orgFunc);
#endif
	*/

	for(i = 0; i < (int)decodedInstructionsCount; i++){
		/*
		if(decodedInstructions[i].flags == FLAG_NOT_DECODABLE){
			//If the disasm goes wrong.
#ifdef _DEBUG
			OutputDebugString("[*] Can`t disasm the function!!");
#endif
			return false;
		}
		*/
		if(length < sizeHook) {
			//Check while the instructions readed are less then what is need to overwrite.
			length += (int)decodedInstructions[i].size;
			instrRead++;
		}
		else{
			break;
		}
	}
	//We must pad with NOP (0x90) if the size is greater than 6 bytes
	if(length > sizeHook){
	//Increase the size of the hooking mechanism buffer.

		newInstrTemp = (BYTE *)calloc(length,sizeof(BYTE));
		if(newInstrTemp == NULL){
#ifdef _DEBUG
			OutputDebugString("[*] Problem  realocatoing space for Hook Method!!\n");
#endif
			return false;
		}
		CopyMemory(newInstrTemp,(BYTE *)newInstr,sizeHook);
		newInstr = (BYTE *)realloc(newInstr,length);
		if(newInstr == NULL){
#ifdef _DEBUG
			OutputDebugString("[*] Problem realocatoing space for Hook Method!!\n");
#endif
			return false;
		}
		ZeroMemory(newInstr, length);
		CopyMemory(newInstr,newInstrTemp,length);
		free(newInstrTemp);
		//We must NOP the rest of the buffer.
		for(i = sizeHook; i < length; i++){
			newInstr[i] = 0x90;
		}
	}
	//Check if the size of the trampoline function is enough. If not, realocate a new one with the correct size.
	//backupFunc = malloc(sizeof(BYTE)*(length+6));
	if(postHookSize != 0){
		//Copy the post hook procedures
		sprintf_s(dbgString,128,"PostTrampSize %d",postHookSize);
		OutputDebugString(dbgString);
		CopyMemory((void *)trampoline,postHook,postHookSize);
		trampoline = (trampoline+(DWORD)postHookSize);
	}
	backupFunc = (BYTE *)calloc((length+7+7),sizeof(BYTE));
	
	if(backupFunc == NULL){
#ifdef _DEBUG
		OutputDebugString("[*] Problem alocating space for API trampoline!!\n");
#endif
		return false;
	}
    //Save the original syscall prolog. The size used is the original prolog + size to JMP original function addr.
	backupFunc[length] = rel_jmp;             
	dwPtr = (ULONG_PTR *)&(backupFunc[length + 1]);
	CopyMemory(backupFunc,(void *)orgFunc,length);
	//Fill with the address of the real API.

	//Must calculate the relative address
	*dwPtr = ((orgFunc+length)-(trampoline+length)-5);
	//Check the trampoline if it have a relative call.
	//findCallJmp(orgFunc,backupFunc,decodedInstructions,instrRead,length+5);

	CopyMemory((void *)trampoline,backupFunc,length+7+7);
	free(backupFunc);

	//Overwrite the beginning of the API with the selected hook method.
	if(!VirtualProtect((void *)orgFunc,length,PAGE_EXECUTE_READWRITE,&dwOldProtect)){
#ifdef _DEBUG
		OutputDebugString("[*] Problem setting READ/WRITE permission on API memory!!\n");
#endif
		return false;
	}
#ifdef _DEBUG
		OutputDebugString("[*] Before Hook\n");
		printDebug(orgFunc);
#endif
	//Overwrite the API prolog.
	CopyMemory((void *)orgFunc,newInstr,length);

#ifdef _DEBUG
		OutputDebugString("[*] After Hook\n");
		printDebug(orgFunc);
#endif
#ifdef _DEBUG
		OutputDebugString("[*] Trampoline\n");
		printDebug((ULONG_PTR)trampolineAddr);
#endif
	if(!VirtualProtect((void *)orgFunc,length,dwOldProtect,&dwOldProtect)){
#ifdef _DEBUG
		OutputDebugString("[*] Problem reseting permission on API memory!!\n");
#endif
		return false;
	}
#ifdef _DEBUG
		OutputDebugString("[*] Hook Attached Sucefully!!\n");
#endif
	free(newInstr);  
	return true;
}

bool HookDetach(ULONG_PTR realAddr,ULONG_PTR trampolineAddr){
	/*
	Function that restore the API function, removing the hook.
	realAddr is the address of the API.
	trampolineAddr is the address of the trampoline function.
	*/
	int             length  = 0, i = 0, sizeHook = 0;
	unsigned int    decodedInstructionsCount = 0; 
	_DecodeResult   res;
	_DecodedInst    decodedInstructions[MAX_INSTRUCTIONS];
	DWORD           dwOldProtect = 0;

#ifdef _M_IX86
	_DecodeType decodeType = Decode32Bits;
#else ifdef _M_AMD64
	_DecodeType decodeType = Decode64Bits;
#endif

	//Disasm the trampoline code. 
	res = distorm_decode(0,(unsigned char *)trampolineAddr, 128, decodeType, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount); 
	
	if (res == DECRES_INPUTERR) {
#ifdef _DEBUG
		OutputDebugString("[*] Problem calculating Inline Hooking instructions size!\n");
#endif
		return false;
	}

	for(i = 0; i < (int)decodedInstructionsCount; i++){
		//Count until find the end of the trampoline.
		if((strcmp((char*)decodedInstructions[i].instructionHex.p,"0000") != 0)){
			sizeHook += decodedInstructions[i].size;
		}
		else{
			break;
		}
	}
	
	//Remove the size of the JMP ADDR from the hook.
	sizeHook -= 5;
	
	//Restore the beginning of the API with the original content.
	if(!VirtualProtect((void *)realAddr,sizeHook,PAGE_EXECUTE_READWRITE,&dwOldProtect)){
#ifdef _DEBUG
		OutputDebugString("[*] Problem setting READ/WRITE permission on API memory!!\n");
#endif
		return false;
	}
#ifdef _DEBUG
	OutputDebugString("[*] Function Before Restore\n");
	printDebug((ULONG_PTR)realAddr);
#endif
	CopyMemory((void *)realAddr,(void *)trampolineAddr,sizeHook);
	if(!VirtualProtect((void *)realAddr,sizeHook,dwOldProtect,&dwOldProtect)){
#ifdef _DEBUG
		OutputDebugString("[*] Problem reseting permission on API memory!!\n");
#endif
		return false;
	}
	#ifdef _DEBUG
		OutputDebugString("[*] Trampoline\n");
		printDebug(trampolineAddr);
		OutputDebugString("[*] Function After Restore\n");
		printDebug((ULONG_PTR)realAddr);
	#endif

	return true;
}





