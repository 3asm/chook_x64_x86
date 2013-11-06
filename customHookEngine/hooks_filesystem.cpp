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

//=====================================================================
// Hook CreateFileW
//=====================================================================
HANDLE (WINAPI * Real_CreateFileW)(
	LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile) = CreateFileW;

HANDLE WINAPI My_CreateFileW(
	LPCWSTR lpFileName,
	DWORD dwDesiredAccess,
	DWORD dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD dwCreationDisposition,
	DWORD dwFlagsAndAttributes,
	HANDLE hTemplateFile)
{
	char *buffer = (char *)malloc(BUFSIZE * sizeof(char));
	char *timestamp = (char *)malloc(20 * sizeof(char));
	char *access = (char *)malloc(255 * sizeof(char));
	HANDLE hFile;

	memset(buffer, 0, sizeof(buffer));
	memset(timestamp, 0, sizeof(timestamp));
	memset(access, 0, sizeof(access));

#ifdef DEBUG
	OutputDebugString("[cuckoo] Hook CreateFileW IN");
#endif

	GetSystemTimestamp(timestamp, 20);

	hFile = Real_CreateFileW(
		lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile);

	GetFileDesiredAccess(dwDesiredAccess, access, 255);

	sprintf_s(
		buffer,
		BUFSIZE,
		"\"%s\",\"%d\",\"%s\",\"CreateFileW\",\"dwDesiredAccess->%s\",\"lpFileName->%ws\",\"hFile->0x%08x\"\r\n",
		timestamp,
		cuckooedProcess.th32ProcessID,
		cuckooedProcess.szExeFile,
		access,
		lpFileName,
		hFile);
	
	Append(buffer);
	
#ifdef DEBUG
	OutputDebugString(buffer);
	OutputDebugString("[cuckoo] Hook CreateFileW OUT");
#endif

	free(access);
	free(timestamp);
	free(buffer);

	return hFile;
}

//=====================================================================
// Hook ReadFile
//=====================================================================
BOOL (WINAPI * Real_ReadFile)(
	HANDLE hFile,
	LPVOID lpBuffer,
	DWORD nNumberOfBytesToRead,
	LPDWORD lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped) = ReadFile;
	
BOOL WINAPI My_ReadFile(
	HANDLE hFile,
	LPVOID lpBuffer,
	DWORD nNumberOfBytesToRead,
	LPDWORD lpNumberOfBytesRead,
	LPOVERLAPPED lpOverlapped)
{
	char *buffer = (char *)malloc(BUFSIZE * sizeof(char));
	char *timestamp = (char *)malloc(20 * sizeof(char));

	memset(buffer, 0, sizeof(buffer));
	memset(timestamp, 0, sizeof(timestamp));

#ifdef DEBUG
	OutputDebugString("[cuckoo] Hook ReadFile IN");
#endif

	GetSystemTimestamp(timestamp, 20);

	sprintf_s(
		buffer,
		BUFSIZE,
		"\"%s\",\"%d\",\"%s\",\"ReadFile\",\"hFile->0x%08x\",\"nNumberOfBytesToRead->%d\"\r\n",
		timestamp,
		cuckooedProcess.th32ProcessID,
		cuckooedProcess.szExeFile,
		hFile,
		nNumberOfBytesToRead);
		
	Append(buffer);

#ifdef DEBUG
	OutputDebugString(buffer);
	OutputDebugString("[cuckoo] Hook ReadFile OUT");
#endif

	free(timestamp);
	free(buffer);

	return Real_ReadFile(
		hFile,
		lpBuffer,
		nNumberOfBytesToRead,
		lpNumberOfBytesRead,
		lpOverlapped);
}

//=====================================================================
// Hook DeleteFileW
//=====================================================================
BOOL (WINAPI * Real_DeleteFileW)(LPCWSTR lpFileName) = DeleteFileW;

BOOL WINAPI My_DeleteFileW(LPCWSTR lpFileName)
{
	char *buffer = (char *)malloc(BUFSIZE * sizeof(char));
	char *timestamp = (char *)malloc(20 * sizeof(char));
	char *fileDumpPath = (char *)malloc(MAX_PATH * sizeof(char));
	wchar_t *fileDumpPathW = (wchar_t *)malloc(MAX_PATH * sizeof(wchar_t));
	char *fileName = (char *)malloc(MAX_PATH * sizeof(char));
	
	memset(buffer, 0, sizeof(buffer));
	memset(timestamp, 0, sizeof(timestamp));
	memset(fileDumpPath, 0, sizeof(fileDumpPath));
	memset(fileDumpPathW, 0, sizeof(fileDumpPathW));
	memset(fileName, 0, sizeof(fileName));
	
#ifdef DEBUG
	OutputDebugString("[cuckoo] Hook DeleteFileW IN");
#endif

	GetSystemTimestamp(timestamp, 20);

	sprintf_s(
		buffer,
		BUFSIZE,
		"\"%s\",\"%d\",\"%s\",\"DeleteFileW\",\"lpFileName->%ws\"\r\n",
		timestamp,
		cuckooedProcess.th32ProcessID,
		cuckooedProcess.szExeFile,
		lpFileName);

	Append(buffer);

	// Create a backup of the file to be deleted.
	GetFilenameFromPath(lpFileName, fileName, MAX_PATH);

	sprintf_s(
		fileDumpPath,
		MAX_PATH,
		"%sfiles\\%s",
		CUCKOO_PATH,
		fileName);

	MultiByteToWideChar(
		CP_ACP,
		0,
		fileDumpPath,
		-1,
		fileDumpPathW,
		MAX_PATH);

	// Copy file to Cuckoo dump directory.
	CopyFileW(lpFileName, fileDumpPathW, TRUE);

#ifdef DEBUG
	OutputDebugString(buffer);
	OutputDebugString("[cuckoo] Hook DeleteFileW OUT");
#endif

	free(fileName);
	free(fileDumpPathW);
	free(fileDumpPath);
	free(timestamp);
	free(buffer);

	return Real_DeleteFileW(lpFileName);
}

//=====================================================================
// Hook MoveFileExW
//=====================================================================
BOOL (WINAPI * Real_MoveFileExW)(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName,
	DWORD dwFlags) = MoveFileExW;

BOOL WINAPI My_MoveFileExW(
	LPCWSTR lpExistingFileName,
	LPCWSTR lpNewFileName,
	DWORD dwFlags)
{
	char *buffer = (char *)malloc(BUFSIZE * sizeof(char));
	char *timestamp = (char *)malloc(20 * sizeof(char));

	memset(buffer, 0, sizeof(buffer));
	memset(timestamp, 0, sizeof(timestamp));
	
#ifdef DEBUG
	OutputDebugString("[cuckoo] Hook MoveFileExW IN");
#endif

	GetSystemTimestamp(timestamp, 20);

	sprintf_s(
		buffer,
		BUFSIZE,
		"\"%s\",\"%d\",\"%s\",\"MoveFileExW\",\"lpExistingFileName->%ws\",\"lpNewFileName->%ws\"\r\n",
		timestamp,
		cuckooedProcess.th32ProcessID,
		cuckooedProcess.szExeFile,
		lpExistingFileName,
		lpNewFileName);
	
	Append(buffer);
	
#ifdef DEBUG
	OutputDebugString(buffer);
	OutputDebugString("[cuckoo] Hook MoveFileExW OUT");
#endif

	free(timestamp);
	free(buffer);

	return Real_MoveFileExW(
		lpExistingFileName,
		lpNewFileName,
		dwFlags);
}

//=====================================================================
// Hook WriteFile
//=====================================================================
BOOL (WINAPI * Real_WriteFile)(
   HANDLE hFile,
   LPCVOID lpBuffer,
   DWORD nNumberOfBytesToWrite,
   LPDWORD lpNumberOfBytesWritten,
   LPOVERLAPPED lpOverlapped) = WriteFile;

BOOL WINAPI My_WriteFile(
   HANDLE hFile,
   LPCVOID lpBuffer,
   DWORD nNumberOfBytesToWrite,
   LPDWORD lpNumberOfBytesWritten,
   LPOVERLAPPED lpOverlapped)
{
	char *buffer = (char *)malloc(BUFSIZE * sizeof(char));
	char *timestamp = (char *)malloc(20 * sizeof(char));

	memset(buffer, 0, sizeof(buffer));
	memset(timestamp, 0, sizeof(timestamp));

#ifdef DEBUG
	OutputDebugString("[cuckoo] Hook WriteFile IN");
#endif

	GetSystemTimestamp(timestamp, 20);

	sprintf_s(
		buffer,
		BUFSIZE,
		"\"%s\",\"%d\",\"%s\",\"WriteFile\",\"hFile->0x%08x\",\"nNumberOfBytesToWrite->%d\"\r\n",
		timestamp,
		cuckooedProcess.th32ProcessID,
		cuckooedProcess.szExeFile,
		hFile,
		nNumberOfBytesToWrite);

	Append(buffer);

#ifdef DEBUG
	OutputDebugString(buffer);
	OutputDebugString("[cuckoo] Hook WriteFile OUT");
#endif

	free(timestamp);
	free(buffer);

	return Real_WriteFile(
		hFile,
		lpBuffer,
		nNumberOfBytesToWrite,
		lpNumberOfBytesWritten,
		lpOverlapped);
}