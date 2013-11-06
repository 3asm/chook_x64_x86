#include "customHook.h"
#include "hookTemplate.h"


void printDebug(DWORD Addr){
	//Print assembly code from Addr. 
	int length  = 0, i = 0;
	_DecodeResult res = NULL;
	_DecodedInst decodedInstructions[MAX_INSTRUCTIONS];
	unsigned int decodedInstructionsCount = 0;
	// Decode the buffer at given offset (virtual address).
	res = distorm_decode(0,(const unsigned char *)Addr, 16, Decode32Bits, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount); 
	if (res == DECRES_INPUTERR) { 
		puts("Problem doing disasm");
		return;
	}  
	puts("DEBUG");
	for(i = 0; i < (int)decodedInstructionsCount; i++){
		printf("%0*I64x (%02d) %-24s %s%s%s\n", dt != Decode64Bits ? 8 : 16, decodedInstructions[i].offset, decodedInstructions[i].size, (char*)decodedInstructions[i].instructionHex.p, (char*)decodedInstructions[i].mnemonic.p, decodedInstructions[i].operands.length != 0 ? " " : "", (char*)decodedInstructions[i].operands.p);
	}
	return;
}

HANDLE WINAPI hookCreateFileW(
							LPCWSTR lpFileName,
							DWORD dwDesiredAccess,
							DWORD dwShareMode,
							LPSECURITY_ATTRIBUTES lpSecurityAttributes,
							DWORD dwCreationDisposition,
							DWORD dwFlagsAndAttributes,
							HANDLE hTemplateFile){
	//Function that will intercept the API parameters.
	HANDLE returnValue = NULL;
	printf("File Name %ws DesiredAccess %X\n",lpFileName,dwDesiredAccess);
	//Call the real API
	returnValue = Real_CreateFileW(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,
									 dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);
	return returnValue;
}


int bytesNumber(BYTE *arrayBytes){
	//Count the number of bytes of the hook shellcode which ends in 0xFFFF. 
	int size = 1, i = 0;
	//While is not the end of the shellcode
	while(arrayBytes[i] != 0xFF || arrayBytes[i+1] != 0xFF){
		size++;
		i++;
	}
	return size;
}

BYTE * inlineHookMethod(DWORD callbackFunc, int *sizeHook){
	/*
	This function will chose amoung a set of inline hooking method avaliable. 
	It will return a buffer to subscribe in the beginning of the functino.
	*/
	int    length = 0, i = 0, sizeInstr = 0, hookNumber = 0;
	BYTE  *newInstr = NULL;
	BYTE  *hookMethod = NULL;
	DWORD *dwPtr = NULL;
    
	//Seed the random number generator.
	srand(time(0));

	//Randonly chose one of the hook methods avaliable.
	hookNumber = rand() % (sizeof(Hooks)/sizeof(BYTE*));
	hookMethod = Hooks[hookNumber];
	
	//Get the size in bytes of the hook method chosed.
	sizeInstr = bytesNumber(hookMethod);
	newInstr = calloc(sizeInstr,sizeof(BYTE));
	if (newInstr == NULL) {
		puts("[ERROR] Problem alocating Hook Method!");
		return NULL;
	}

	//Copy the content of the hook instruction.
	memcpy(newInstr,hookMethod,sizeInstr);

	//Search on the instructions for the address template.
	while(i < sizeInstr){
		//We have found the address template to substitute.
		if(newInstr[i] == 0xAA){
			dwPtr = (DWORD *)&(newInstr[i]);
			break;
		}
		i++;
	}
	
	//Fill the address of the Prolog Hook Function. 
	*dwPtr = (DWORD)callbackFunc;
	*sizeHook = sizeInstr;
	return newInstr;
}



bool HookAttach(DWORD *orgFunc,DWORD callbackFunc){
	/*
	Function that make the hook and redirect the execution of the orgFunc to a callbackFunc.
	This callbackFunc must call the real function to complete the normal operation of the system.
	orgFunc must be a pointer to an API.
	callbackFunc must be the address of the function that will intercepet the execution flow.
	*/
    
	int              length  = 0, i = 0, sizeHook = 0;
	unsigned int     decodedInstructionsCount = 0;
	_DecodeResult    res = NULL;
	_DecodedInst     decodedInstructions[MAX_INSTRUCTIONS];
	BYTE            *newInstr = NULL;
	BYTE            *newInstrTemp = NULL;
	DWORD            orgFuncAddr = *orgFunc;
	BYTE            *backupFunc = NULL;
	DWORD           *dwPtr = NULL;
	DWORD            dwOldProtect = 0;
	
	//Get one of the inline hooking methods avaliable.
	newInstr = inlineHookMethod(callbackFunc,&sizeHook);
	if (newInstr == NULL) {
		puts("[ERROR] Problem creating Hook Method!");
		return false;
	}
	//Disasm the beginning of the Api to hook.
	res = distorm_decode(0,(unsigned char *)orgFuncAddr, 16, Decode32Bits, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount); 
	if (res == DECRES_INPUTERR) {
		puts("[ERROR] Problem calculating Inline Hooking instructions size!");
		return false;
	}
	for(i = 0; i < (int)decodedInstructionsCount; i++){
	//Check while the instructions readed are less then what is need to overwrite.
		if(length < sizeHook) {
			length += decodedInstructions[i].size;
		}
	}

	//We must pad with NOP (0x90) if the size is greater than 6 bytes
	if(length > sizeHook){
	//Increase the size of the hooking mechanism buffer.
		newInstrTemp = calloc(length,sizeof(BYTE));
		memcpy(newInstrTemp,(BYTE *)newInstr,sizeHook);
		newInstr = realloc(newInstr,length);
		if(newInstr == NULL){
			puts("[ERROR] Problem realocatoing space for Hook Method!!");
			return false;
		}
		ZeroMemory(newInstr, length);
		memcpy(newInstr,newInstrTemp,length);
		free(newInstrTemp);
		//We must NOP the rest of the buffer.
		for(i = sizeHook; i < length; i++){
			newInstr[i] = 0x90;
		}
	}
	//Save the original syscall prolog. The size used is the original prolog + size to JMP original function addr.
	backupFunc = calloc(length+6,sizeof(BYTE));
	if(backupFunc == NULL){
		puts("[ERROR] Problem alocating space for API trampoline!!");
		return false;
	}
	memcpy(backupFunc,(void *)orgFuncAddr,length);
	backupFunc[length] = push;         
	dwPtr = (DWORD *)&(backupFunc[length + 1]);

	//Fill with the address of the real API.
	*dwPtr = (DWORD)(orgFuncAddr + length);
	backupFunc[length+5] = ret;   
	
	//Save the address of the trampoline function.
	*orgFunc = (DWORD)backupFunc;
	
	//Overwrite the beginning of the API with the selected hook method.
	if(!VirtualProtect((void *)orgFuncAddr,length,PAGE_EXECUTE_READWRITE,&dwOldProtect)){
		puts("[ERROR] Problem setting READ/WRITE permission on API memory!!");
		return false;
	}
	memcpy((void *)orgFuncAddr,newInstr,length);
	if(!VirtualProtect((void *)orgFuncAddr,length,dwOldProtect,&dwOldProtect)){
		puts("[ERROR] Problem reseting permission on API memory!!");
		return false;
	}
	free(newInstr);  
	return true;
}

bool HookDetach(DWORD realAddr,DWORD trampolineAddr){
	/*
	Function that restore the API function, removing the hook.
	realAddr is the address of the API.
	trampolineAddr is the address of the trampoline function.
	*/
	int             length  = 0, i = 0, sizeHook = 0;
	unsigned int    decodedInstructionsCount = 0; 
	_DecodeResult   res = NULL;
	_DecodedInst    decodedInstructions[MAX_INSTRUCTIONS];
	DWORD           dwOldProtect = 0;
	
	//Disasm the trampoline code. 
	res = distorm_decode(0,(unsigned char *)trampolineAddr, 16, Decode32Bits, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount); 
	if (res == DECRES_INPUTERR) {
		puts("[ERROR] Problem calculating Inline Hooking instructions size!");
		return false;
	}

	for(i = 0; i < (int)decodedInstructionsCount; i++){
		//Count until find the RET instruction, which tells where the trampoline ends.
		if(strcmp((char*)decodedInstructions[i].instructionHex.p,"c3") != 0){
			sizeHook += decodedInstructions[i].size;
		}
		else{
			break;
		}
	}
	
	//Remove the size of the PUSH ADDR from the hook.
	sizeHook -= 5;
	
	//Restore the beginning of the API with the original content.
	if(!VirtualProtect((void *)realAddr,sizeHook,PAGE_EXECUTE_READWRITE,&dwOldProtect)){
		puts("[ERROR] Problem setting READ/WRITE permission on API memory!!");
		return false;
	}
	memcpy((void *)realAddr,(void *)trampolineAddr,sizeHook);
	if(!VirtualProtect((void *)realAddr,sizeHook,dwOldProtect,&dwOldProtect)){
		puts("[ERROR] Problem reseting permission on API memory!!");
		return false;
	}

	return true;
}
int main(int argc, CHAR* argv[])
{
	Real_CreateFileW = CreateFileW;
	if(HookAttach((DWORD *)&Real_CreateFileW,(DWORD)hookCreateFileW) == true){
		puts("Succefully done Inline Hooking!!");
	}
	else{
		puts("Problem doing Inline Hooking!!");
		exit(0);
	}
	CreateFileW(L"C:\\a.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	HookDetach((DWORD)CreateFileW,(DWORD)Real_CreateFileW);
	puts("Hook Detached!");
	CreateFileW(L"C:\\b.txt", GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	return 0;
}


