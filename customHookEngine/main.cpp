#include "customHook.h"
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <windows.h>

//=====================================================================
// Hook CreateFileW
//=====================================================================

#define TRAMPSIZE 30
#define BUFSIZE 2048

typedef HANDLE (WINAPI * CREATEFILEW)(LPCWSTR lpFileName,
                                      DWORD dwDesiredAccess,
                                      DWORD dwShareMode,
                                      LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                                      DWORD dwCreationDisposition,
                                      DWORD dwFlagsAndAttributes,
                                      HANDLE hTemplateFile);



CREATEFILEW Real_CreateFileW = (CREATEFILEW)VirtualAllocEx(GetCurrentProcess(),
                                                           NULL,
                                                           sizeof(BYTE) * TRAMPSIZE,
                                                           MEM_COMMIT | MEM_RESERVE,
                                                           PAGE_EXECUTE_READWRITE);

HANDLE WINAPI My_CreateFileW(LPCWSTR lpFileName,
                             DWORD dwDesiredAccess,
                             DWORD dwShareMode,
                             LPSECURITY_ATTRIBUTES lpSecurityAttributes,
                             DWORD dwCreationDisposition,
                             DWORD dwFlagsAndAttributes,
                             HANDLE hTemplateFile)
{
    char *buffer = (char *)calloc(BUFSIZE, sizeof(char));
    char *access = (char *)calloc(255, sizeof(char));
    HANDLE hFile;

#ifdef _DEBUG
    OutputDebugString("[cuckoo] Hook CreateFileW IN\n");
#endif

    hFile = Real_CreateFileW(lpFileName,
                             dwDesiredAccess,
                             dwShareMode,
                             lpSecurityAttributes,
                             dwCreationDisposition,
                             dwFlagsAndAttributes,
                             hTemplateFile);


    if(hFile == INVALID_HANDLE_VALUE)
        sprintf_s(buffer,
                  BUFSIZE,
                  "\"filesystem\",\"CreateFileW\",\"FAILURE\",\"\",\"lpFileName->%ws\",\"dwDesiredAccess->%s\"\r\n",
                  lpFileName,
                  access);
    else
        sprintf_s(buffer,
                  BUFSIZE,
                  "\"filesystem\",\"CreateFileW\",\"SUCCESS\",\"0x%08x\",\"lpFileName->%ws\",\"dwDesiredAccess->%s\"\r\n",
                  hFile,
                  lpFileName,
                  access);
    
#ifdef _DEBUG
    OutputDebugString(buffer);
    OutputDebugString("[cuckoo] Hook CreateFileW OUT\n");
#endif

    // Send path of files being created on the file system to cuckoo
    // process, in order to be later dumped and stored.
    if(dwDesiredAccess == GENERIC_WRITE || dwDesiredAccess == GENERIC_ALL || dwDesiredAccess == 0xc0000000)
    {
        memset(buffer, 0, BUFSIZE);
        sprintf_s(buffer,
                  BUFSIZE,
                  "FILE:%ws",
                  lpFileName);

    }

#ifdef _DEBUG
    OutputDebugString(buffer);
    OutputDebugString("[cuckoo] Hook CreateFileW OUT\n");
#endif

    free(access);
    free(buffer);

    return hFile;
}


int _tmain(int argc, _TCHAR* argv[])
{

	HINSTANCE hKernel32;
	HANDLE hFile; 

	hKernel32 = LoadLibraryA("kernel32.dll");

	hFile = CreateFileW(L"a0.txt",                // name of the write
                       GENERIC_WRITE,          // open for writing
                       0,                      // do not share
                       NULL,                   // default security
                       CREATE_NEW,             // create new file only
                       FILE_ATTRIBUTE_NORMAL,  // normal file
                       NULL); 
	CloseHandle(hFile);


	   // Hook Filesystem Functions.
    if(HookAttach((ULONG_PTR)GetProcAddress(hKernel32, "CreateFileW"), (ULONG_PTR)Real_CreateFileW, (ULONG_PTR)My_CreateFileW) == TRUE) {
#ifdef _DEBUG
        OutputDebugString("[cuckoo] CreateFileW Hooked\n");
#endif


    hFile = CreateFileW(L"a1.txt",                // name of the write
                       GENERIC_WRITE,          // open for writing
                       0,                      // do not share
                       NULL,                   // default security
                       CREATE_NEW,             // create new file only
                       FILE_ATTRIBUTE_NORMAL,  // normal file
                       NULL); 
	CloseHandle(hFile);


    }

	if(HookDetach((ULONG_PTR)CreateFileW, (ULONG_PTR)Real_CreateFileW) == FALSE) {
#ifdef _DEBUG
        OutputDebugString("[cuckoo] Failed Unhooking CreateFile\n");
#endif
	}

	hFile = CreateFileW(L"a2.txt",                // name of the write
                       GENERIC_WRITE,          // open for writing
                       0,                      // do not share
                       NULL,                   // default security
                       CREATE_NEW,             // create new file only
                       FILE_ATTRIBUTE_NORMAL,  // normal file
                       NULL); 
	CloseHandle(hFile);

	return 0;
}
