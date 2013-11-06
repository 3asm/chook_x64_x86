/**
 * Cuckoo - A sandbox for malware analysis
 * Copyright (C) 2010-2011 Claudio Guarnieri (claudio@shadowserver.org)
 *
 * This file is part of Cuckoo.
 *
 * Cuckoo is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Cuckoo is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see http://www.gnu.org/licenses/.
 **/

#include <windows.h>
#include <detours.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include "headers.h"
#include "hooks.h"

#pragma comment(lib, "Ws2_32.lib")
//#pragma comment(lib, "detours.lib")
//#pragma comment(lib, "detoured.lib")

//=====================================================================
// Current Process Informations
//=====================================================================
PROCESSENTRY32 cuckooedProcess = GetProcessEntry(GetCurrentProcessId());

//=====================================================================
// Log File Handle
//=====================================================================
HANDLE hLogFile = 0;

//=====================================================================
// Install Hooks
//=====================================================================
void HooksAttach()
{
#ifdef DEBUG
	OutputDebugString("[cuckoo] Installing Hooks...");
#endif

	// Hook Filesystem Functions.
	Real_CreateFileW = CreateFileW;
	HookAttach((DWORD)&Real_CreateFileW,(DWORD)My_CreateFileW);
	Real_DeleteFileW = DeleteFileW;
	HookAttach((DWORD)&Real_DeleteFileW,(DWORD)My_DeleteFileW);
	Real_MoveFileExW = MoveFileExW;
	HookAttach((DWORD)&Real_MoveFileExW,(DWORD)My_MoveFileExW);
	Real_ReadFile = ReadFile;
	HookAttach((DWORD)&Real_ReadFile,(DWORD)My_ReadFile);
	Real_WriteFile = WriteFile;
	HookAttach((DWORD)&Real_WriteFile,(DWORD)My_WriteFile);
	// Hook Registry Functions.
	Real_RegOpenKeyW = RegOpenKeyW;
	HookAttach((DWORD)&Real_RegOpenKeyW, My_RegOpenKeyW);
	Real_RegCreateKeyW = RegCreateKeyW;
	HookAttach((DWORD)&Real_RegCreateKeyW, My_RegCreateKeyW);
	Real_RegDeleteKeyW = RegDeleteKeyW;
	HookAttach((DWORD)&Real_RegDeleteKeyW, My_RegDeleteKeyW);
	Real_RegEnumKeyExW = RegEnumKeyExW;
	HookAttach((DWORD)&Real_RegEnumKeyExW, My_RegEnumKeyExW);
	Real_RegEnumValueW = RegEnumValueW;
	HookAttach((DWORD)&Real_RegEnumValueW, My_RegEnumValueW);
	Real_RegSetValueExW = RegSetValueExW;
	HookAttach((DWORD)&Real_RegSetValueExW, My_RegSetValueExW);
	// Hook Processes Functions.
	Real_CreateProcessA = CreateProcessA;
	HookAttach((DWORD)&Real_CreateProcessA, My_CreateProcessA);
	Real_CreateProcessW = CreateProcessW;
	HookAttach((DWORD)&Real_CreateProcessW, My_CreateProcessW);
	Real_TerminateProcess = TerminateProcess;
	HookAttach((DWORD)&Real_TerminateProcess, My_TerminateProcess);
	Real_ShellExecuteExW = ShellExecuteExW;
	HookAttach((DWORD)&Real_ShellExecuteExW, My_ShellExecuteExW);
	Real_CreateRemoteThread = CreateRemoteThread,;
	HookAttach((DWORD)&Real_CreateRemoteThread, My_CreateRemoteThread);
	Real_WriteProcessMemory = WriteProcessMemory;
	HookAttach((DWORD)&Real_WriteProcessMemory, My_WriteProcessMemory);
	Real_ReadProcessMemory = ReadProcessMemory;
	HookAttach((DWORD)&Real_ReadProcessMemory, My_ReadProcessMemory);
	// Hook Syncronization Functions.
	Real_CreateMutexW = CreateMutexW;
	HookAttach((DWORD)&Real_CreateMutexW, My_CreateMutexW);
	Real_OpenMutexW = OpenMutexW;
	HookAttach((DWORD)&Real_OpenMutexW, My_OpenMutexW);
	//HookAttach(Real_ReleaseMutex, My_ReleaseMutex);
	// Hook Windows Functions.
	HookAttach((DWORD)&Real_FindWindowW, My_FindWindowW);
	// Hook Services Functions.
	Real_OpenSCManagerW = OpenSCManagerW;
	HookAttach((DWORD)&Real_OpenSCManagerW, My_OpenSCManagerW);
	Real_CreateServiceA = CreateServiceA;
	HookAttach((DWORD)&Real_CreateServiceA, My_CreateServiceA);
	Real_CreateServiceW = CreateServiceW;
	HookAttach((DWORD)&Real_CreateServiceW, My_CreateServiceW);
	Real_OpenServiceW = OpenServiceW;
	HookAttach((DWORD)&Real_OpenServiceW, My_OpenServiceW);
	Real_StartServiceW = StartServiceW;
	HookAttach((DWORD)&Real_StartServiceW, My_StartServiceW);
	Real_ControlService = ControlService;
	HookAttach((DWORD)&Real_ControlService, My_ControlService);
	Real_DeleteService = DeleteService;
	HookAttach((DWORD)&Real_DeleteService, My_DeleteService);
	// Hook Network Functions.
	Real_URLDownloadToFileW = URLDownloadToFileW;
	HookAttach((DWORD)&Real_URLDownloadToFileW, My_URLDownloadToFileW);
	Real_InternetOpenUrlW = InternetOpenUrlW;
	HookAttach((DWORD)&Real_InternetOpenUrlW, My_InternetOpenUrlW);

#ifdef DEBUG
	OutputDebugString("[cuckoo] Hooks Installed!");
#endif
}

//=====================================================================
// Uninstall Hooks
//=====================================================================
void HooksDetach()
{
#ifdef DEBUG
	OutputDebugString("[cuckoo] Uninstalling Hooks...");
#endif

	// Un-Hook Filesystem Functions
	HookDetach(CreateFileW,Real_CreateFileW);
	HookDetach(DeleteFileW,Real_DeleteFileW);
	HookDetach(MoveFileExW,Real_MoveFileExW);
	HookDetach(ReadFile,Real_ReadFile);
	HookDetach(WriteFile,Real_WriteFile);
	// Un-Hook Registry Functions.
	HookDetach(RegOpenKeyW,Real_RegOpenKeyW);
	HookDetach(RegCreateKeyW,Real_RegCreateKeyW);
	HookDetach(RegDeleteKeyW,Real_RegDeleteKeyW);
	HookDetach(RegEnumKeyExW,Real_RegEnumKeyExW);
	HookDetach(RegEnumValueW,Real_RegEnumValueW);
	HookDetach(RegSetValueExW,Real_RegSetValueExW);
	// Un-Hook Processes Functions.
	HookDetach(CreateProcessA,Real_CreateProcessA);
	HookDetach(CreateProcessW,Real_CreateProcessW);
	HookDetach(TerminateProcess,Real_TerminateProcess);
	HookDetach(ShellExecuteExW,Real_ShellExecuteExW);
	HookDetach(CreateRemoteThread,Real_CreateRemoteThread);
	HookDetach(WriteProcessMemory,Real_WriteProcessMemory);
	HookDetach(ReadProcessMemory,Real_ReadProcessMemory);
	// Un-Hook Syncronization Functions.
	HookDetach(CreateMutexW,Real_CreateMutexW);
	HookDetach(OpenMutexW,Real_OpenMutexW);
	//HookDetach(Real_ReleaseMutex, My_ReleaseMutex);
	// Un-Hook Windows Functions.
	HookDetach(FindWindowW,Real_FindWindowW);
	// Un-Hook Services Functions.
	HookDetach(OpenSCManagerW,Real_OpenSCManagerW);
	HookDetach(CreateServiceA,Real_CreateServiceA);
	HookDetach(CreateServiceW,Real_CreateServiceW);
	HookDetach(OpenServiceW,Real_OpenServiceW);
	HookDetach(StartServiceW,Real_StartServiceW);
	HookDetach(ControlService,Real_ControlService);
	HookDetach(DeleteService,Real_DeleteService);
	// Un-Hook Network Functions.
	HookDetach(URLDownloadToFileW,Real_URLDownloadToFileW);
	HookDetach(InternetOpenUrlW,Real_InternetOpenUrlW);

#ifdef DEBUG
	OutputDebugString("[cuckoo] Hooks Uninstalled!");
#endif
}

//=====================================================================
// DLL Entry Point
//=====================================================================
BOOL APIENTRY DllMain(HINSTANCE hInst, DWORD dwReason, LPVOID iReserved)
{
	switch (dwReason)
	{
		case DLL_PROCESS_ATTACH:
			char logFilePath[MAX_PATH];
			
#ifdef DEBUG
			OutputDebugString("[cuckoo] DLL Injected. Loading...");
#endif

			// Generate the absolute path of the log file in which I'll store
			// all API calls invoked by the monitored process.
			sprintf_s(
				logFilePath,
				sizeof(logFilePath),
				"%slogs\\%d.csv",
				CUCKOO_PATH,
				cuckooedProcess.th32ProcessID);

			// Create the file and retrieve an handle.
			hLogFile = OpenLog(logFilePath);

			// Install hooks and start monitoring the process.
			HooksAttach();
			break;

		case DLL_PROCESS_DETACH:
#ifdef DEBUG
			OutputDebugString("[cuckoo] Unloading DLL...");
#endif

			// Uninstall hooks and stop monitoring the process.
			HooksDetach();
			// Close handle to the opened log file.
			CloseLog(hLogFile);

#ifdef DEBUG
			OutputDebugString("[cuckoo] End :-(");
#endif

			break;
	}

	return TRUE;
}