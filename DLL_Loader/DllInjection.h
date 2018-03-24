
typedef void (WINAPI *Rm_OutputDebugStringW)(LPCTSTR lpOutputString);
typedef NTSTATUS (NTAPI *Rm_DbgPrint)(LPCSTR Format, ...);
typedef NTSTATUS (NTAPI *Rm_LdrUnloadDll)(IN HANDLE ModuleHandle);
typedef NTSTATUS (NTAPI *Rm_LdrGetDllHandle)( IN PWORD pwPath OPTIONAL, IN PVOID Unused OPTIONAL, 
                                   IN PUNICODE_STRING ModuleFileName, OUT PHANDLE pHModule );
typedef NTSTATUS (NTAPI *Rm_LdrLoadDll)( IN PWCHAR PathToFile OPTIONAL, IN ULONG Flags OPTIONAL, 
                              IN PUNICODE_STRING ModuleFileName, OUT PHANDLE ModuleHandle );
typedef VOID (NTAPI *Rm_RtlInitUnicodeString)(PUNICODE_STRING DestinationString,PCWSTR SourceString);
typedef HMODULE (WINAPI *Rm_LoadLibraryExW)(LPCTSTR lpFileName,HANDLE hFile,DWORD dwFlags); // Kernel32.dll
typedef BOOL (WINAPI *Rm_FreeLibrary)(HMODULE hModule); // Kernel32.dll
typedef HMODULE (WINAPI *Rm_GetModuleHandleW)(LPCTSTR lpModuleName); // Kernel32.dll
typedef NTSTATUS (NTAPI *Rm_NtClose)(HANDLE ObjectHandle);
typedef NTSTATUS (NTAPI *Rm_NtTerminateThread)(HANDLE ThreadHandle,NTSTATUS ExitStatus);
typedef int (WINAPI *Rm_MessageBoxW)(HWND hWnd,LPCTSTR lpText,LPCTSTR lpCaption,UINT uType);
typedef BOOL (WINAPI *Rm_DeleteFileW)(LPCTSTR lpFileName);	// kernel32.dll
typedef NTSTATUS (NTAPI *Rm_NtDeleteFile)(POBJECT_ATTRIBUTES   ObjectAttributes);

typedef struct _Structure {
wchar_t ModulePath[1024];

wchar_t LoadError[MAX_PATH];
wchar_t UnloadError[MAX_PATH];
wchar_t ModuleNotInMemory[MAX_PATH];
wchar_t DllNotFoundError[MAX_PATH];
wchar_t DllLoadSuccess[MAX_PATH];
wchar_t DllUnloadSuccess[MAX_PATH];
wchar_t DllDeleteError[MAX_PATH];
wchar_t DllDeleteOk[MAX_PATH];

PVOID RmRtlInitUnicodeString;
PVOID RmLdrGetDllHandle;
PVOID RmLdrLoadDll;
PVOID RmLdrUnloadDll;
PVOID RmCreateFileW;
PVOID RmNtClose;
PVOID RmNtTerminateThread;
PVOID RmMessageBoxW;
PVOID RmDeleteFileW;
PVOID RmDbgPrint;
PVOID RmOutputDebugStringW;
PVOID RmNtDeleteFile;

BOOL mode;
HANDLE hFile;
NTSTATUS Status;
HINSTANCE hTest;
UNICODE_STRING NativeBitch;
UNICODE_STRING PathNameString;
OBJECT_ATTRIBUTES ObjectAttributes;
wchar_t lpPathName[1024];
BOOL shit;
int IfUnload;
int IfDelete;
} Structure;
Structure my_Structure,*pmy_Structure;

DWORD RemoteThread(Structure *Parameter){
//Rm_DeleteFileW myDeleteFileW = (Rm_DeleteFileW)Parameter->RmDeleteFileW;
Rm_NtTerminateThread myNtTerminateThread = (Rm_NtTerminateThread)Parameter->RmNtTerminateThread;
Rm_NtClose myNtClose = (Rm_NtClose)Parameter->RmNtClose;
Rm_NtDeleteFile myNtDeleteFile = (Rm_NtDeleteFile)Parameter->RmNtDeleteFile;
Rm_LdrUnloadDll myLdrUnloadDll = (Rm_LdrUnloadDll)Parameter->RmLdrUnloadDll;
Rm_LdrLoadDll myLdrLoadDll = (Rm_LdrLoadDll)Parameter->RmLdrLoadDll;
Rm_LdrGetDllHandle myLdrGetDllHandle = (Rm_LdrGetDllHandle)Parameter->RmLdrGetDllHandle;
Rm_RtlInitUnicodeString myRtlInitUnicodeString = (Rm_RtlInitUnicodeString)Parameter->RmRtlInitUnicodeString;
//Rm_MessageBoxW myMessageBoxW = (Rm_MessageBoxW)Parameter->RmMessageBoxW;
Rm_DbgPrint myDbgPrint = (Rm_DbgPrint)Parameter->RmDbgPrint;
Rm_OutputDebugStringW myOutputDebugStringW = (Rm_OutputDebugStringW)Parameter->RmOutputDebugStringW;

	if(Parameter->mode == TRUE){	// loading DLL.
			myRtlInitUnicodeString(&Parameter->NativeBitch, Parameter->ModulePath);
			Parameter->Status = myLdrLoadDll(NULL, 0, &Parameter->NativeBitch, (PHANDLE)&Parameter->hTest);
			if(Parameter->Status != STATUS_SUCCESS){
					myOutputDebugStringW(Parameter->LoadError);
					myNtTerminateThread((HANDLE)-2, 0);
			} else {
				myOutputDebugStringW(Parameter->DllLoadSuccess);
			}
		if(Parameter->IfUnload == 1){
			Parameter->Status = myLdrUnloadDll(Parameter->hTest);
			if(Parameter->Status != STATUS_SUCCESS){
					myOutputDebugStringW(Parameter->UnloadError);
					myNtTerminateThread((HANDLE)-2, 0);
			} else {
				myOutputDebugStringW(Parameter->DllUnloadSuccess);
			}
		}
		if(Parameter->IfDelete == 1){
			myRtlInitUnicodeString(&Parameter->PathNameString, Parameter->lpPathName);
			InitializeObjectAttributes( &Parameter->ObjectAttributes, 
				&Parameter->PathNameString, OBJ_CASE_INSENSITIVE, NULL, NULL );
			Parameter->Status = myNtDeleteFile(&Parameter->ObjectAttributes);
			if(Parameter->Status != STATUS_SUCCESS){
				myOutputDebugStringW(Parameter->DllDeleteError);
				myNtTerminateThread((HANDLE)-2, 0);
			} else {
				myOutputDebugStringW(Parameter->DllDeleteOk);
			}
		}
	} else {	// unloading DLL.
			myRtlInitUnicodeString(&Parameter->NativeBitch, Parameter->ModulePath);
			Parameter->Status = myLdrGetDllHandle(0, NULL, &Parameter->NativeBitch, (PHANDLE)&Parameter->hTest);
			if(Parameter->Status != STATUS_SUCCESS){
				myOutputDebugStringW(Parameter->ModuleNotInMemory);
				myNtTerminateThread((HANDLE)-2, 0);
			} else {
				Parameter->Status = myLdrUnloadDll(Parameter->hTest);
				if(Parameter->Status != STATUS_SUCCESS){
					myOutputDebugStringW(Parameter->UnloadError);
					myNtTerminateThread((HANDLE)-2, 0);
				} else {
					myOutputDebugStringW(Parameter->DllUnloadSuccess);
				}
			}
		if(Parameter->IfDelete == 1){
			myRtlInitUnicodeString(&Parameter->PathNameString, Parameter->lpPathName);
			InitializeObjectAttributes( &Parameter->ObjectAttributes, 
				&Parameter->PathNameString, OBJ_CASE_INSENSITIVE, NULL, NULL );
			Parameter->Status = myNtDeleteFile(&Parameter->ObjectAttributes);
			if(Parameter->Status != STATUS_SUCCESS){
				myOutputDebugStringW(Parameter->DllDeleteError);
				myNtTerminateThread((HANDLE)-2, 0);
			} else {
				myOutputDebugStringW(Parameter->DllDeleteOk);
			}
		}
	}	// unloading dll eof
myNtTerminateThread((HANDLE)-2, 0);
return 0;
}

DWORD __stdcall DllInjection(wchar_t *DllPath, 
							 BOOL Mode, 
							 wchar_t *TargetProc,
							 HWND hWnd,
							 int IfUnload,
							 int IfDelete){
CLIENT_ID ClientId;
SIZE_T dwThreadSize = 4000;
void *pThread; BOOL en;
HANDLE hProcess;
NTSTATUS Status;
DWORD dwSize;
OSVERSIONINFO osvi;
OBJECT_ATTRIBUTES ObjectAttributes;

		RtlAdjustPrivilege(20, TRUE, AdjustCurrentProcess, &en);
		InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

ClientId.UniqueProcess = (HANDLE)KeGetPID(TargetProc);
ClientId.UniqueThread = 0;

	if(ClientId.UniqueProcess == NULL){
			InsertBufferStatus (hWnd, pid_failed);
			return -1;
	} else {
		InsertBufferStatus (hWnd, pid_ok);
	}

		Status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS  , &ObjectAttributes, &ClientId);
		if(Status != STATUS_SUCCESS){
			InsertBufferStatus (hWnd, proc_open_failed);
			return -1;
		} else {
			InsertBufferStatus (hWnd, proc_open_ok);
		}

		pThread = NtVirtualAlloc(hProcess, 0, dwThreadSize, MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
		if(pThread == NULL){
			InsertBufferStatus (hWnd, virtmemaloc_failed);
			return -1;
		} else {
			InsertBufferStatus (hWnd, virtmemaloc_ok);
		}

		Status = NtWriteVirtualMemory(hProcess, pThread, (void *)RemoteThread, dwThreadSize,0);
		if(Status != STATUS_SUCCESS){
			InsertBufferStatus (hWnd, virtmemwrite_failed);
			return -1;
		} else {
			InsertBufferStatus (hWnd, virtmemwrite_ok);
		}

NtZeroMemory(&my_Structure,sizeof(Structure));

my_Structure.RmCreateFileW = (void *)GetProcAddress(LoadLibraryW(L"Kernel32.dll"), 
													"CreateFileW");
my_Structure.RmLdrGetDllHandle = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), 
													"LdrGetDllHandle");
my_Structure.RmLdrLoadDll = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), 
													"LdrLoadDll");
my_Structure.RmLdrUnloadDll = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), 
													"LdrUnloadDll");
my_Structure.RmNtClose = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), 
													"NtClose");
my_Structure.RmNtTerminateThread = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), 
													"NtTerminateThread");
my_Structure.RmRtlInitUnicodeString = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), 
													"RtlInitUnicodeString");
my_Structure.RmDbgPrint = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), 
													"DbgPrint");
my_Structure.RmNtDeleteFile = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), 
													"NtDeleteFile");
my_Structure.RmMessageBoxW = (void *)GetProcAddress(LoadLibraryW(L"User32.dll"), 
													"MessageBoxW");
my_Structure.RmDeleteFileW = (void *)GetProcAddress(LoadLibraryW(L"Kernel32.dll"), 
													"DeleteFileW");	// TargetProc
my_Structure.RmOutputDebugStringW = (void *)GetProcAddress(LoadLibraryW(L"Kernel32.dll"), 
													"OutputDebugStringW");

wcscpy(my_Structure.LoadError, L"[ RP ] ");
wcscat(my_Structure.LoadError, L"Dll Loading Failed!\n");

wcscpy(my_Structure.UnloadError, L"[ RP ] ");
wcscat(my_Structure.UnloadError, L"Dll Unloading Failed!\n");

wcscpy(my_Structure.ModuleNotInMemory, L"[ RP ] ");
wcscat(my_Structure.ModuleNotInMemory, L"Dll not found in process memory!\n");

wcscpy(my_Structure.DllDeleteError, L"[ RP ] ");
wcscat(my_Structure.DllDeleteError, L"Dll File could not be deleted!\n");

wcscpy(my_Structure.DllLoadSuccess, L"[ RP ] ");
wcscat(my_Structure.DllLoadSuccess, L"Dll Loaded Successfuly!\n");

wcscpy(my_Structure.DllUnloadSuccess, L"[ RP ] ");
wcscat(my_Structure.DllUnloadSuccess, L"Dll Unloaded Successfuly!\n");

wcscpy(my_Structure.DllDeleteOk, L"[ RP ] ");
wcscat(my_Structure.DllDeleteOk, L"Dll Deleted Successfuly!\n");

wcscpy(my_Structure.ModulePath, DllPath);
my_Structure.mode = Mode;
my_Structure.IfUnload = IfUnload;
my_Structure.IfDelete = IfDelete;
wcscpy(my_Structure.lpPathName, L"\\??\\");
wcscat(my_Structure.lpPathName, DllPath);

dwSize = sizeof(Structure);

		pmy_Structure = (Structure *)NtVirtualAlloc (hProcess ,0,sizeof(Structure),MEM_COMMIT,PAGE_READWRITE);
		NtWriteVirtualMemory(hProcess ,pmy_Structure,&my_Structure,sizeof(my_Structure),0);

		Status = RtlCreateUserThread(hProcess, NULL,FALSE, 0, 0, 0,(LPTHREAD_START_ROUTINE)pThread,(PVOID)pmy_Structure, 0, 0);
		if(Status != STATUS_SUCCESS){
			InsertBufferStatus (hWnd, firstinj_err);
			goto __SecondImpact;
		} else {
			InsertBufferStatus (hWnd, injected_ok);
			NtClose(hProcess);
			return 0;
		}

__SecondImpact:

	NtZeroMemory(&osvi, sizeof(OSVERSIONINFO));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	GetVersionEx(&osvi);
	if(osvi.dwMajorVersion > 5){
		if(NtCreateThreadEx){
			HANDLE hRemoteThread = NULL;
			UNKNOWN Buffer;
			DWORD dw0 = 0;
			DWORD dw1 = 0; 
			NtZeroMemory(&Buffer, sizeof(UNKNOWN));
			Buffer.Length = sizeof (UNKNOWN);
			Buffer.Unknown1 = 0x10003;
			Buffer.Unknown2 = 0x8;
			Buffer.Unknown3 = &dw1;
			Buffer.Unknown4 = 0;
			Buffer.Unknown5 = 0x10004;
			Buffer.Unknown6 = 4;
			Buffer.Unknown7 = &dw0;
			Status = NtCreateThreadEx(&hRemoteThread, 
									  0x1FFFFF, 
									  NULL, 
									  hProcess, 
									  (LPTHREAD_START_ROUTINE)pThread, 
									  (PVOID)pmy_Structure, 
									  FALSE, 
									  0, 
									  0, 
									  0, 
									  &Buffer);
			if(Status != STATUS_SUCCESS){
				InsertBufferStatus (hWnd, injection_err);
				NtClose(hProcess);
				return -1;
			} else {
				InsertBufferStatus (hWnd, injected_ok);
				NtClose(hProcess);
				return 0;
			}
		}
	} else {
		DWORD dwThreadId;
		HANDLE hRemo;
		hRemo = CreateRemoteThread(hProcess ,0,0,(DWORD (__stdcall *)(void *))pThread ,pmy_Structure,0,&dwThreadId);
		if(hRemo == NULL){
			InsertBufferStatus (hWnd, injection_err);
			NtClose(hProcess);
			return -1;
		} else {
			InsertBufferStatus (hWnd, injected_ok);
			NtClose(hProcess);
		return 0;
		}
	}
return -1;
}