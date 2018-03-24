

#pragma warning( disable : 4996 )

typedef NTSTATUS (NTAPI *Rm_ZwSetSystemInformation)(DWORD, PVOID, ULONG);
typedef NTSTATUS (NTAPI *Rm_NtLoadDriver)( IN PUNICODE_STRING DriverServiceName );
typedef NTSTATUS (NTAPI *Rm_NtUnloadDriver)( IN PUNICODE_STRING DriverServiceName );
typedef LONG (WINAPI *Rm_RegSetValueExW)(HKEY hKey, LPCTSTR lpValueName, DWORD Reserved,
										DWORD dwType, const BYTE *lpData, DWORD cbData);
typedef LONG (WINAPI *Rm_RegCreateKeyW)(HKEY hKey, LPCTSTR lpSubKey, PHKEY phkResult);
typedef LONG (WINAPI *Rm_RegCloseKey)( HKEY hKey);
typedef DWORD (WINAPI *Rm_SHDeleteKeyW)(HKEY hkey, LPCTSTR pszSubKey);
typedef VOID (__stdcall *Rm_RtlZeroMemory)(VOID UNALIGNED  *Destination, SIZE_T Length);
typedef LONG (__stdcall *Rm_RtlAdjustPrivilege)(int,BOOL,BOOL,BOOL *);
typedef NTSTATUS (NTAPI *Rm_NtCreateKey)(PHANDLE pKeyHandle, ACCESS_MASK DesiredAccess, 
										POBJECT_ATTRIBUTES ObjectAttributes, 
										ULONG TitleIndex, PUNICODE_STRING Class, 
										ULONG CreateOptions, PULONG Disposition);
typedef NTSTATUS (NTAPI *Rm_NtSetValueKey)(HANDLE KeyHandle, PUNICODE_STRING ValueName, 
										   ULONG TitleIndex OPTIONAL, ULONG Type, 
										   PVOID Data, ULONG DataSize);
typedef NTSTATUS (NTAPI *Rm_NtDeleteKey)(HANDLE KeyHandle); 
typedef NTSTATUS (NTAPI *Rm_NtOpenKey)(PHANDLE pKeyHandle, ACCESS_MASK DesiredAccess,
										POBJECT_ATTRIBUTES ObjectAttributes );

typedef struct _StructureEx {
PVOID RmNtCreateKey;
PVOID RmNtSetValueKey;
PVOID RmNtDeleteKey;
PVOID RmNtOpenKey;
PVOID RmRtlInitUnicodeString;		// x
PVOID RmNtTerminateThread;			// x
PVOID RmMessageBoxW;				// x
PVOID RmDeleteFileW;				// x
PVOID RmZwSetSystemInformation;		// x
PVOID RmNtLoadDriver;				// x
PVOID RmNtUnloadDriver;				// x
PVOID RmRtlAdjustPrivilege;			// x
PVOID RmRegSetValueExW;				// x
PVOID RmRegCreateKeyW;				// x
PVOID RmNtClose;					// x
PVOID RmRegCloseKey;				// x
PVOID RmSHDeleteKeyW;				// x
PVOID RmRtlZeroMemory;				// x
PVOID RmNtDeleteFile;
PVOID RmOutputDebugStringW;

wchar_t ModulePath[1024];
wchar_t LoadError[MAX_PATH];
wchar_t UnloadError[MAX_PATH];
wchar_t SysDeleteError[MAX_PATH];
wchar_t SysDeleteOk[MAX_PATH];
wchar_t SysLoadSuccess[MAX_PATH];
wchar_t SysUnloadSuccess[MAX_PATH];
wchar_t SysDelRegError[MAX_PATH];

BOOL mode;
BOOL en;
HANDLE hFile;
NTSTATUS Status;
SYSTEM_LOAD_AND_CALL_IMAGE img;
ADJUST_PRIVILEGE_TYPE AdjustCurrentProcess;
SIZE_T BombSize;
UNICODE_STRING u_str;
//SC_HANDLE ServiceHandle;
//SC_HANDLE ServiceHandleEx;
//SERVICE_STATUS status;
HKEY hk;
wchar_t RegUniPath[1024];
DWORD Type;
wchar_t ImagePathValue[MAX_PATH];
wchar_t TypeValue[MAX_PATH];
wchar_t ImagePath[1024];
wchar_t RegPath[1024];
wchar_t ServiceName[MAX_PATH];
wchar_t DriverPath[1024];
wchar_t RegUniPath2[1024];
wchar_t RegUniPath3[1024];
SIZE_T LoadPathLen;

OBJECT_ATTRIBUTES oBj;
HANDLE mainDrvHandle;
HANDLE drvKeyHandle;
UNICODE_STRING MainKey;
UNICODE_STRING ValueNameDrv;
UNICODE_STRING DrvTypeValue;
UNICODE_STRING RegEnum;
unsigned long Disposition;
HANDLE hKey;

UNICODE_STRING PathNameString;
OBJECT_ATTRIBUTES ObjectAttributes;
wchar_t lpPathName[1024];

int IfUnload;
int IfDelete;
int ImagePathLen;
} StructureEx;
StructureEx my_StructureEx,*pmy_StructureEx;

DWORD RemoteLoadDriver(StructureEx *Parameter){
Rm_NtTerminateThread myNtTerminateThread = (Rm_NtTerminateThread)Parameter->RmNtTerminateThread;
Rm_NtCreateKey myNtCreateKey = (Rm_NtCreateKey)Parameter->RmNtCreateKey;
Rm_NtSetValueKey myNtSetValueKey = (Rm_NtSetValueKey)Parameter->RmNtSetValueKey;
Rm_NtDeleteKey myNtDeleteKey = (Rm_NtDeleteKey)Parameter->RmNtDeleteKey;
Rm_NtOpenKey myNtOpenKey = (Rm_NtOpenKey)Parameter->RmNtOpenKey;
Rm_OutputDebugStringW myOutputDebugStringW = (Rm_OutputDebugStringW)Parameter->RmOutputDebugStringW;
Rm_NtClose myNtClose = (Rm_NtClose)Parameter->RmNtClose;
Rm_NtDeleteFile myNtDeleteFile = (Rm_NtDeleteFile)Parameter->RmNtDeleteFile;
Rm_RtlInitUnicodeString myRtlInitUnicodeString = (Rm_RtlInitUnicodeString)Parameter->RmRtlInitUnicodeString;
Rm_ZwSetSystemInformation myZwSetSystemInformation = (Rm_ZwSetSystemInformation)Parameter->RmZwSetSystemInformation;
Rm_NtLoadDriver myNtLoadDriver = (Rm_NtLoadDriver)Parameter->RmNtLoadDriver;
Rm_NtUnloadDriver myNtUnloadDriver = (Rm_NtUnloadDriver)Parameter->RmNtUnloadDriver;
Rm_RegSetValueExW myRegSetValueExW = (Rm_RegSetValueExW)Parameter->RmRegSetValueExW;
Rm_RegCreateKeyW myRegCreateKeyW = (Rm_RegCreateKeyW)Parameter->RmRegCreateKeyW;
Rm_RegCloseKey myRegCloseKey = (Rm_RegCloseKey)Parameter->RmRegCloseKey;
Rm_SHDeleteKeyW mySHDeleteKeyW = (Rm_SHDeleteKeyW)Parameter->RmSHDeleteKeyW;
Rm_RtlAdjustPrivilege myRtlAdjustPrivilege = (Rm_RtlAdjustPrivilege)Parameter->RmRtlAdjustPrivilege;

	myRtlInitUnicodeString(&Parameter->u_str, Parameter->RegUniPath); 
	myRtlInitUnicodeString(&Parameter->RegEnum, Parameter->RegUniPath3); 
	myRtlAdjustPrivilege(10, TRUE, Parameter->AdjustCurrentProcess, &Parameter->en);
	if(Parameter->mode == TRUE){	// we are loading driver

		myRtlInitUnicodeString(&Parameter->MainKey, Parameter->RegUniPath2);
		InitializeObjectAttributes( &Parameter->oBj, &Parameter->MainKey, OBJ_CASE_INSENSITIVE, NULL, NULL ); 
		Parameter->Status = myNtCreateKey(&Parameter->mainDrvHandle, 
										KEY_ALL_ACCESS, 
										&Parameter->oBj, 
										0,  
										NULL, 
										REG_OPTION_NON_VOLATILE, 
										&Parameter->Disposition);
		if(Parameter->Status != STATUS_SUCCESS){
			myOutputDebugStringW(Parameter->LoadError);
			myNtTerminateThread((HANDLE)-2, 0);
		}
		myRtlInitUnicodeString(&Parameter->MainKey, Parameter->ServiceName);
		InitializeObjectAttributes( &Parameter->oBj, &Parameter->MainKey, OBJ_CASE_INSENSITIVE, Parameter->mainDrvHandle, NULL );
		Parameter->Status = myNtCreateKey(&Parameter->drvKeyHandle, 
											KEY_ALL_ACCESS, 
											&Parameter->oBj, 
											0, 
											NULL, 
											REG_OPTION_NON_VOLATILE,
											&Parameter->Disposition );
		if(Parameter->Status != STATUS_SUCCESS){
			myOutputDebugStringW(Parameter->LoadError);
			myNtTerminateThread((HANDLE)-2, 0);
		}
		myRtlInitUnicodeString(&Parameter->ValueNameDrv, Parameter->ImagePathValue);
		myRtlInitUnicodeString(&Parameter->DrvTypeValue, Parameter->TypeValue);

		Parameter->Status = myNtSetValueKey(Parameter->drvKeyHandle, 
											&Parameter->ValueNameDrv, 
											0, 
											REG_SZ, 
											Parameter->ImagePath, 
											Parameter->LoadPathLen);
		if(Parameter->Status != STATUS_SUCCESS){
			myNtDeleteKey(Parameter->drvKeyHandle);
			myNtClose(Parameter->drvKeyHandle);
			myNtClose(Parameter->mainDrvHandle);
			myOutputDebugStringW(Parameter->LoadError);
			myNtTerminateThread((HANDLE)-2, 0);
		}
		Parameter->Status = myNtSetValueKey(Parameter->drvKeyHandle, 
											&Parameter->DrvTypeValue, 
											0, 
											REG_DWORD, 
											&Parameter->Type, 
											sizeof(DWORD));
		if(Parameter->Status != STATUS_SUCCESS){
			myNtDeleteKey(Parameter->drvKeyHandle);
			myNtClose(Parameter->drvKeyHandle);
			myNtClose(Parameter->mainDrvHandle);
			myOutputDebugStringW(Parameter->LoadError);
			myNtTerminateThread((HANDLE)-2, 0);
		}

//	if (myRegCreateKeyW(HKEY_LOCAL_MACHINE, Parameter->RegPath, &Parameter->hk) != STATUS_SUCCESS){	// if key has been created
//		myOutputDebugStringW(Parameter->LoadError);
//		myNtTerminateThread((HANDLE)-2, 0);
//	}
//		myRegSetValueExW(Parameter->hk, Parameter->ImagePathValue, 0, REG_SZ, (LPBYTE)Parameter->ImagePath, Parameter->ImagePathLen);
//		myRegSetValueExW(Parameter->hk, Parameter->TypeValue, 0, REG_DWORD, (LPBYTE)&Parameter->Type, sizeof(DWORD)); 
//		myRegCloseKey(Parameter->hk); 
		if(myNtLoadDriver(&Parameter->u_str) != STATUS_SUCCESS){	// if driver hasnt been loaded
			myNtDeleteKey(Parameter->drvKeyHandle);
			myNtClose(Parameter->drvKeyHandle);
			myNtClose(Parameter->mainDrvHandle);
			myOutputDebugStringW(Parameter->LoadError);
			myNtTerminateThread((HANDLE)-2, 0);
		} else {	// driver was loaded with ntloaddriver ! kewl xD ><
			myOutputDebugStringW(Parameter->SysLoadSuccess);
			if(Parameter->IfUnload == 1){
				if(myNtUnloadDriver(&Parameter->u_str) != STATUS_SUCCESS){	// we want to unload driver but it wasnt!
					myOutputDebugStringW(Parameter->UnloadError);
					myNtTerminateThread((HANDLE)-2, 0);
				} else {	// driver unloaded
					InitializeObjectAttributes(&Parameter->oBj, &Parameter->RegEnum, OBJ_CASE_INSENSITIVE, NULL, NULL);
					Parameter->Status = myNtOpenKey(&Parameter->hKey, KEY_ALL_ACCESS, &Parameter->oBj);
					if(Parameter->Status != STATUS_SUCCESS){
						myOutputDebugStringW(Parameter->SysDelRegError);
					} else {
						Parameter->Status = myNtDeleteKey(Parameter->hKey);
						if(Parameter->Status != STATUS_SUCCESS){
							myOutputDebugStringW(Parameter->SysDelRegError);
						} else {
							myNtClose(Parameter->hKey);
						}
					}
					InitializeObjectAttributes(&Parameter->oBj, &Parameter->u_str, OBJ_CASE_INSENSITIVE, NULL, NULL);
					Parameter->Status = myNtOpenKey(&Parameter->hKey, KEY_ALL_ACCESS, &Parameter->oBj);
					if(Parameter->Status != STATUS_SUCCESS){
						myOutputDebugStringW(Parameter->SysDelRegError);
					} else {
						Parameter->Status = myNtDeleteKey(Parameter->hKey);
						if(Parameter->Status != STATUS_SUCCESS){
							myOutputDebugStringW(Parameter->SysDelRegError);
						} else {
							myNtClose(Parameter->hKey);
						}
					}
					myOutputDebugStringW(Parameter->SysUnloadSuccess);
	//				mySHDeleteKeyW(HKEY_LOCAL_MACHINE, Parameter->RegPath);
				}

			}
			if(Parameter->IfDelete == 1){
				myRtlInitUnicodeString(&Parameter->PathNameString, Parameter->lpPathName);
				InitializeObjectAttributes( &Parameter->ObjectAttributes, 
					&Parameter->PathNameString, OBJ_CASE_INSENSITIVE, NULL, NULL );
				Parameter->Status = myNtDeleteFile(&Parameter->ObjectAttributes);
				if(Parameter->Status != STATUS_SUCCESS){
					myOutputDebugStringW(Parameter->SysDeleteError);
					myNtTerminateThread((HANDLE)-2, 0);
				} else {
					myOutputDebugStringW(Parameter->SysDeleteOk);
				}
			}
		}
//	}	// end of 'if registry key was created' check
//	else {
//		myOutputDebugStringW(Parameter->LoadError);
//	}
	}	// end of 'we are loading driver'
	else {	// we are only unloading driver
		if(myNtUnloadDriver(&Parameter->u_str) != STATUS_SUCCESS){
			myOutputDebugStringW(Parameter->UnloadError);
			myNtTerminateThread((HANDLE)-2, 0);
		} else {
					InitializeObjectAttributes(&Parameter->oBj, &Parameter->RegEnum, OBJ_CASE_INSENSITIVE, NULL, NULL);
					Parameter->Status = myNtOpenKey(&Parameter->hKey, KEY_ALL_ACCESS, &Parameter->oBj);
					if(Parameter->Status != STATUS_SUCCESS){
						myOutputDebugStringW(Parameter->SysDelRegError);
					} else {
						Parameter->Status = myNtDeleteKey(Parameter->hKey);
						if(Parameter->Status != STATUS_SUCCESS){
							myOutputDebugStringW(Parameter->SysDelRegError);
						} else {
							myNtClose(Parameter->hKey);
						}
					}
					InitializeObjectAttributes(&Parameter->oBj, &Parameter->u_str, OBJ_CASE_INSENSITIVE, NULL, NULL);
					Parameter->Status = myNtOpenKey(&Parameter->hKey, KEY_ALL_ACCESS, &Parameter->oBj);
					if(Parameter->Status != STATUS_SUCCESS){
						myOutputDebugStringW(Parameter->SysDelRegError);
					} else {
						Parameter->Status = myNtDeleteKey(Parameter->hKey);
						if(Parameter->Status != STATUS_SUCCESS){
							myOutputDebugStringW(Parameter->SysDelRegError);
						} else {
							myNtClose(Parameter->hKey);
						}
					}
//			mySHDeleteKeyW(HKEY_LOCAL_MACHINE, Parameter->RegPath);
			myOutputDebugStringW(Parameter->SysUnloadSuccess);
		}
		if(Parameter->IfDelete == 1){
			myRtlInitUnicodeString(&Parameter->PathNameString, Parameter->lpPathName);
			InitializeObjectAttributes( &Parameter->ObjectAttributes, 
				&Parameter->PathNameString, OBJ_CASE_INSENSITIVE, NULL, NULL );
			Parameter->Status = myNtDeleteFile(&Parameter->ObjectAttributes);
			if(Parameter->Status != STATUS_SUCCESS){
				myOutputDebugStringW(Parameter->SysDeleteError);
				myNtTerminateThread((HANDLE)-2, 0);
			} else {
				myOutputDebugStringW(Parameter->SysDeleteOk);
			}
		}
	}

myNtTerminateThread((HANDLE)-2, 0);
return 0;
}

DWORD __stdcall SysInjection(wchar_t *DllPath, 
							 BOOL Mode, 
							 wchar_t *TargetProc,
							 HWND hWnd,
							 int IfUnload,
							 int IfDelete){
CLIENT_ID ClientId;
SIZE_T dwThreadSize = 5000;
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

		Status = NtWriteVirtualMemory(hProcess, pThread, (void *)RemoteLoadDriver, dwThreadSize,0);
		if(Status != STATUS_SUCCESS){
			InsertBufferStatus (hWnd, virtmemwrite_failed);
			return -1;
		} else {
			InsertBufferStatus (hWnd, virtmemwrite_ok);
		}

SecureZeroMemory(&my_StructureEx,sizeof(StructureEx));

my_StructureEx.RmNtTerminateThread = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), 
													"NtTerminateThread");
my_StructureEx.RmMessageBoxW = (void *)GetProcAddress(LoadLibraryW(L"User32.dll"), 
													"MessageBoxW");
my_StructureEx.RmDeleteFileW = (void *)GetProcAddress(LoadLibraryW(L"Kernel32.dll"), 
													"DeleteFileW");
my_StructureEx.RmRtlInitUnicodeString = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), 
													"RtlInitUnicodeString");
my_StructureEx.RmNtClose = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), 
													"NtClose");
my_StructureEx.RmZwSetSystemInformation = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), 
													"ZwSetSystemInformation");
my_StructureEx.RmNtLoadDriver = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), 
													"NtLoadDriver");
my_StructureEx.RmNtUnloadDriver = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), 
													"NtUnloadDriver");
my_StructureEx.RmRtlAdjustPrivilege = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), 
													"RtlAdjustPrivilege");
my_StructureEx.RmRtlZeroMemory = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), 
													"RtlZeroMemory");
my_StructureEx.RmRegSetValueExW = (void *)GetProcAddress(LoadLibraryW(L"Advapi32.dll"), 
													"RegSetValueExW");
my_StructureEx.RmRegCreateKeyW = (void *)GetProcAddress(LoadLibraryW(L"Advapi32.dll"), 
													"RegCreateKeyW");
my_StructureEx.RmRegCloseKey = (void *)GetProcAddress(LoadLibraryW(L"Advapi32.dll"), 
													"RegCloseKey");
my_StructureEx.RmSHDeleteKeyW = (void *)GetProcAddress(LoadLibraryW(L"Shlwapi.dll"), 
													"SHDeleteKeyW");
my_StructureEx.RmNtDeleteFile = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), 
													"NtDeleteFile");
my_StructureEx.RmOutputDebugStringW = (void *)GetProcAddress(LoadLibraryW(L"Kernel32.dll"), 
													"OutputDebugStringW");
my_StructureEx.RmNtCreateKey = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), 
													"NtCreateKey");
my_StructureEx.RmNtSetValueKey = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), 
													"NtSetValueKey");
my_StructureEx.RmNtDeleteKey = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), 
													"NtDeleteKey");
my_StructureEx.RmNtOpenKey = (void *)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), 
													"NtOpenKey");

my_StructureEx.Type = SERVICE_KERNEL_DRIVER;
my_StructureEx.mode = Mode;
my_StructureEx.IfUnload = IfUnload;
my_StructureEx.IfDelete = IfDelete;
wcscpy(my_StructureEx.ImagePathValue, L"ImagePath");
wcscpy(my_StructureEx.TypeValue, L"Type");
wcscpy(my_StructureEx.RegUniPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\");
wcscat(my_StructureEx.RegUniPath, PathFindFileNameW(DllPath));
wcscpy(my_StructureEx.RegUniPath2, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\");
wcscpy(my_StructureEx.RegUniPath3, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\");
wcscat(my_StructureEx.RegUniPath3, PathFindFileNameW(DllPath));
wcscat(my_StructureEx.RegUniPath3, L"\\Enum");

wcscpy(my_StructureEx.RegPath, L"SYSTEM\\CurrentControlSet\\Services\\");	// dont need this
wcscat(my_StructureEx.RegPath, PathFindFileNameW(DllPath));					// dont need this
wcscpy(my_StructureEx.ImagePath, L"\\??\\");	// for registry 
wcscat(my_StructureEx.ImagePath, DllPath);		// for registry
wcscpy(my_StructureEx.ServiceName, PathFindFileNameW(DllPath));	// service name, we dont need this anymore
wcscpy(my_StructureEx.DriverPath, DllPath);		// driver normal path
wcscpy(my_StructureEx.lpPathName, L"\\??\\");	// for delete file
wcscat(my_StructureEx.lpPathName, DllPath);		// for delete driver file cdn
my_StructureEx.LoadPathLen = wcslen(my_StructureEx.lpPathName) * sizeof(WCHAR) + sizeof(WCHAR);
wcscpy(my_StructureEx.SysDelRegError, L"Deleteting registry keys error! Delete it manualy.\n");
wcscpy(my_StructureEx.LoadError, L"[RP] ");
wcscat(my_StructureEx.LoadError, L"Error Loading Driver!");

wcscpy(my_StructureEx.UnloadError, L"[RP] ");
wcscat(my_StructureEx.UnloadError, L"Error Unloading Driver!");

wcscpy(my_StructureEx.SysDeleteError, L"[RP] ");
wcscat(my_StructureEx.SysDeleteError, L"Driver File could not be deleted!\n");

wcscpy(my_StructureEx.SysLoadSuccess, L"[RP] ");
wcscat(my_StructureEx.SysLoadSuccess, L"Driver Loaded Successfuly!\n");

wcscpy(my_StructureEx.SysUnloadSuccess, L"[RP] ");
wcscat(my_StructureEx.SysUnloadSuccess, L"Driver Unloaded Successfuly!\n");

wcscpy(my_StructureEx.SysDeleteOk, L"[RP] ");
wcscat(my_StructureEx.SysDeleteOk, L"Driver Deleted Successfuly!\n");

my_StructureEx.BombSize = sizeof(SYSTEM_LOAD_AND_CALL_IMAGE);
my_StructureEx.ImagePathLen = wcslen(my_StructureEx.ImagePath) * sizeof(wchar_t);

dwSize = sizeof(StructureEx);

		pmy_StructureEx = (StructureEx *)NtVirtualAlloc (hProcess ,0,sizeof(StructureEx),MEM_COMMIT,PAGE_READWRITE);
		NtWriteVirtualMemory(hProcess ,pmy_StructureEx,&my_StructureEx,sizeof(my_StructureEx),0);

	if(RtlCreateUserThread) {
		Status = RtlCreateUserThread(hProcess, NULL,FALSE, 0, 0, 0,(LPTHREAD_START_ROUTINE)pThread,(PVOID)pmy_StructureEx, 0, 0);
		if(Status != STATUS_SUCCESS){
			InsertBufferStatus (hWnd, firstinj_err);
			goto __SecondImpact;
		} else {
			InsertBufferStatus (hWnd, injected_ok);
			NtClose(hProcess);
			return 0;
		}
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
									  (PVOID)pmy_StructureEx, 
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
		hRemo = CreateRemoteThread(hProcess ,0,0,(DWORD (__stdcall *)(void *))pThread ,pmy_StructureEx,0,&dwThreadId);
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