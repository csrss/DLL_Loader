
#pragma warning(disable: 4996)
#include "LoadSys.h"

HANDLE KeGetPID(WCHAR *pstrProcessName){
        NTSTATUS Status;
        SIZE_T cbBuffer = 0x8000;
        PVOID pBuffer = NULL;
        HANDLE hResult = NULL;
		HANDLE dwId;
		PSYSTEM_PROCESSES pProcesses;
		RTL_HEAP_DEFINITION  heapParams;
		heapParams.Length = sizeof( RTL_HEAP_PARAMETERS );

        do{
		pBuffer = (void *)RtlAllocateHeap(NtGetProcessHeap(), 0, cbBuffer); if (pBuffer == NULL){return 0;}
            Status = NtQuerySystemInformation(SystemProcessInformation,pBuffer, cbBuffer, NULL);
            if (Status == STATUS_INFO_LENGTH_MISMATCH){ 
			RtlFreeHeap(NtGetProcessHeap(), 0, pBuffer); cbBuffer *= 2;
            }else if (!NT_SUCCESS(Status)){ 
				RtlFreeHeap(NtGetProcessHeap(), 0, pBuffer); return 0; 
			}
        }
        while (Status == STATUS_INFO_LENGTH_MISMATCH);
        pProcesses = (PSYSTEM_PROCESSES)pBuffer;

        for (;;){
            WCHAR *pszProcessName = pProcesses->ProcessName.Buffer;
            if (pszProcessName == NULL)pszProcessName = L"Idle";
            if(wcscmp(pszProcessName, pstrProcessName) == 0){
				dwId = (HANDLE)pProcesses->ProcessId;
                break;
            }

            if (pProcesses->NextEntryDelta == 0)break;
            pProcesses = (PSYSTEM_PROCESSES)(((BYTE *)pProcesses)+ pProcesses->NextEntryDelta);
        }
RtlFreeHeap(NtGetProcessHeap(), 0, pBuffer);
return dwId;
}

int __stdcall HostDll(wchar_t *DllPath, 
					  HWND hWnd, 
					  int IfUnload,
					  int IfDelete)
{
	UNICODE_STRING NativeBitch;
	HINSTANCE hTest;
	NTSTATUS Status;
	BOOL St;

	InsertBufferStatus (hWnd, L"[*] %s: %s\r\n", loading_file, PathFindFileNameW(DllPath));

	if(LoaderOptions.nt_api == 1){
		RtlInitUnicodeString(&NativeBitch, DllPath);
		Status = LdrLoadDll(NULL, 0, &NativeBitch, (PHANDLE)&hTest);
		if(Status != STATUS_SUCCESS){
			InsertBufferStatus (hWnd, L"[-] nt!LdrLoadDll Status: 0x%08x\r\n", Status);
			return -1;
		} else {
			InsertBufferStatus (hWnd, dll_loaded);
		}
	} else {
		hTest = LoadLibraryExW(DllPath, NULL, 0);
		if(hTest)
			InsertBufferStatus(hWnd, L"[+] kernel32!LoadLibraryExW: %x\r\n", hTest);
		else 
			InsertBufferStatus(hWnd, L"[-] kernel32!LoadLibraryExW: NULL\r\n");
	}

	if(IfUnload == 1){
		if(LoaderOptions.nt_api == 1){
			Status = LdrUnloadDll(hTest);
			if(Status != STATUS_SUCCESS){
				InsertBufferStatus (hWnd, L"[-] nt!LdrUnloadDll Status: 0x%08x\r\n", Status);
			} else InsertBufferStatus (hWnd, dll_unloaded);
		} else {
			St = FreeLibrary(hTest);
			if(St)
				InsertBufferStatus (hWnd, L"[+] kernel32!FreeLibrary Status: %d\r\n", St);
			else 
				InsertBufferStatus (hWnd, L"[-] kernel32!FreeLibrary Status: %d\r\n", St);
		}
	}

	if(IfDelete == 1){
		if(LoaderOptions.nt_api == 1){
			NtRemoveFile(DllPath, hWnd);
		} else {
			St = DeleteFileW(DllPath);
			if(St)
				InsertBufferStatus (hWnd, L"[+] kernel32!DeleteFileW Status: %d\r\n", St);
			else 
				InsertBufferStatus (hWnd, L"[-] kernel32!DeleteFileW Status: %d\r\n", St);
		}
	}
	return 0;
}

int __stdcall UnloadDll(wchar_t *DllPath, 
						HWND hWnd, 
						int IfDelete)
{
	UNICODE_STRING NativeBitch;
	HANDLE hTest2;
	BOOL St;
	NTSTATUS Status;
	InsertBufferStatus (hWnd, L"[*] %s: %s\r\n", unloading_file, PathFindFileNameW(DllPath));

	if(LoaderOptions.nt_api == 1){	// unload with NTAPI 
		RtlInitUnicodeString(&NativeBitch, DllPath);
		Status = LdrGetDllHandle(0, NULL, &NativeBitch, &hTest2);
		if(Status != STATUS_SUCCESS){
			InsertBufferStatus (hWnd, dll_not_found_mem);
			return -1;
		} else {
			Status = LdrUnloadDll(hTest2);
			if(Status != STATUS_SUCCESS){
				InsertBufferStatus (hWnd, L"[-] LdrUnloadDll failed [Status: 0x%08x]\r\n", Status);
				return -1;
			} else InsertBufferStatus (hWnd, dll_unloaded);
		}
	} else {	// unload with WINAPI
		St = FreeLibrary(GetModuleHandleW(DllPath));
		if(!St){
			InsertBufferStatus(hWnd, L"[-] kernel32!FreeLibrary Status: %d\r\n", St);
		} else {
			InsertBufferStatus (hWnd, L"[+] kernel32!FreeLibrary Status: %d\r\n", St);
		}
	}
	if(IfDelete == 1){
		if(LoaderOptions.nt_api == 1){
			NtRemoveFile(DllPath, hWnd);
		} else {
			St = DeleteFileW(DllPath);
			if(St)
				InsertBufferStatus (hWnd, L"[+] kernel32!DeleteFileW Status: %d\r\n", St);
			else 
				InsertBufferStatus (hWnd, L"[-] kernel32!DeleteFileW Status: %d\r\n", St);
		}
	}
	return 0;
}

int __stdcall Run(int Mode,		// load file or unload ?
				  int InjectionMode, // use injection or not ?
				  int IfUnload,	// unload file right after load ?
				  int IfDelete,	// delete file right after unload ?
				  wchar_t *ModulePath,	// file path
				  wchar_t *TargetProcess,	// target process (for injection)
				  HWND hWnd)	// status window handle, our damn edit control
{
	HANDLE hFile;
	DWORD n = 0;
	wchar_t *lol;
	char buffer[1024] = {0};
	NTSTATUS Status;
	UNICODE_STRING PathNameString;
	LARGE_INTEGER      byteOffset;
	IO_STATUS_BLOCK    ioStatusBlock;
	OBJECT_ATTRIBUTES ObjectAttributes;
	wchar_t lpPathName[1024] = {0x5c, 0x3f, 0x3f, 0x5c, 0x00};

	if(ModulePath == NULL) {	// there is no file selected
		InsertBufferStatus (hWnd, file_not_selected);
		return -1;
	}

	if(InjectionMode == 1 && TargetProcess == NULL){
		InsertBufferStatus (hWnd, no_proc_for_inj);
		return -1;
	}

	wcscat(lpPathName, ModulePath);
	RtlInitUnicodeString(&PathNameString, lpPathName);
	InitializeObjectAttributes( &ObjectAttributes, &PathNameString, OBJ_CASE_INSENSITIVE, NULL, NULL );

	Status = NtCreateFile(
					&hFile,
					GENERIC_READ,
					&ObjectAttributes,
					&ioStatusBlock,
					NULL,
					FILE_ATTRIBUTE_NORMAL,
					FILE_SHARE_READ,
					FILE_OPEN,
					FILE_NON_DIRECTORY_FILE,
					NULL,
					0
    );

	if(Status != STATUS_SUCCESS){
		InsertBufferStatus (hWnd, cannot_open_file);
		return -1;
	} 

	if (hFile == INVALID_HANDLE_VALUE) {
		InsertBufferStatus (hWnd, cannot_open_file);
		return -1;
	} else {
		byteOffset.LowPart = byteOffset.HighPart = 0;
		Status = NtReadFile(hFile, 
							NULL,
							NULL,
							NULL,
							&ioStatusBlock,
							(PVOID)&buffer,
							sizeof(buffer),
							&byteOffset,
							NULL);
		if(Status != STATUS_SUCCESS){
			InsertBufferStatus (hWnd, cannot_check_file);
			NtClose(hFile); 
			return -1;
		}

		if(!strstr((char*)buffer, "MZ")){
			InsertBufferStatus (hWnd, not_win_exe);
			NtClose(hFile); 
			return -1;
		}
	NtClose(hFile);
	}

	lol = PathFindExtension(ModulePath);
	if(wcscmp(lol, L".dll") == 0 || wcscmp(lol, L".DLL") == 0){
		InsertBufferStatus (hWnd, dll_detected);
		if(Mode == 1 && InjectionMode == 0){
			HostDll(ModulePath, hWnd, IfUnload, IfDelete);
		} else if(Mode == 1 && InjectionMode == 1){
			DllInjection(ModulePath, TRUE, TargetProcess, hWnd, IfUnload, IfDelete);
		} else if(Mode == 0 && InjectionMode == 0){
			UnloadDll(ModulePath, hWnd, IfDelete);
		} else if(Mode == 0 && InjectionMode == 1){
			DllInjection(ModulePath, FALSE, TargetProcess, hWnd, IfUnload, IfDelete);
		}
		DeleteModuleList(hWnd);
		BuildDllList(hWnd);
	} else if(wcscmp(lol, L".sys") == 0 || wcscmp(lol, L".SYS") == 0){
		InsertBufferStatus (hWnd, sys_detected);
		if(Mode == 1 && InjectionMode == 0){	// load without injection
			LoadKernelModule(ModulePath, hWnd, IfUnload, IfDelete);
		} else if(Mode == 1 && InjectionMode == 1){	// load with injection
			SysInjection(ModulePath, TRUE, TargetProcess, hWnd, IfUnload, IfDelete);
		} else if(Mode == 0 && InjectionMode == 0){	// unload without injection
			UnloadKernelModule(ModulePath, hWnd, IfDelete);
		} else if(Mode == 0 && InjectionMode == 1){	// unload with injection
			SysInjection(ModulePath, FALSE, TargetProcess, hWnd, IfUnload, IfDelete);
		}
		DeleteDeviceList(hWnd);
		BuildDevicesList(hWnd);
	} else if(wcscmp(lol, L".exe") == 0 || wcscmp(lol, L".EXE") == 0){
		InsertBufferStatus (hWnd, L"[+] Executable Detected. I will not load it.\r\n");
	} else if(wcscmp(lol, L".lib") == 0 || wcscmp(lol, L".LIB") == 0){
		InsertBufferStatus (hWnd, L"[+] Library Detected. I will not load it.\r\n");
	} else if(wcscmp(lol, L".txt") == 0 || wcscmp(lol, L".TXT") == 0){
		InsertBufferStatus (hWnd, L"[+] Text file Detected. I will not load it.\r\n");
	} else if(wcscmp(lol, L".db") == 0 || wcscmp(lol, L".DB") == 0){
		InsertBufferStatus (hWnd, L"[+] Database Detected. I will not load it.\r\n");
	} else if(wcscmp(lol, L".png") == 0 || wcscmp(lol, L".PNG") == 0 ||
		wcscmp(lol, L".jpg") == 0 || wcscmp(lol, L".JPG") == 0 ||
		wcscmp(lol, L".ico") == 0 || wcscmp(lol, L".ICO") == 0 ||
		wcscmp(lol, L".gif") == 0 || wcscmp(lol, L".GIF") == 0 ||
		wcscmp(lol, L".bmp") == 0 || wcscmp(lol, L".BMP") == 0){
		InsertBufferStatus (hWnd, L"[+] Graphic file Detected. I will not load it.\r\n");
	} else if(wcscmp(lol, L".avi") == 0 || wcscmp(lol, L".AVI") == 0 ||
		wcscmp(lol, L".mpeg") == 0 || wcscmp(lol, L".MPEG") == 0){
		InsertBufferStatus (hWnd, L"[+] Movie file Detected. I will not load it.\r\n");
	} else if(wcscmp(lol, L".rar") == 0 || wcscmp(lol, L".RAR") == 0 ||
		wcscmp(lol, L".zip") == 0 || wcscmp(lol, L".ZIP") == 0){
		InsertBufferStatus (hWnd, L"[+] Archive file Detected. I will not load it.\r\n");
	} else {
		InsertBufferStatus (hWnd, unknown_file);
		return -1;
	}
return 0;
}