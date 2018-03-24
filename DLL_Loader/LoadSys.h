
BOOL RunDriverWithServiceManager(wchar_t *ServiceName, wchar_t *DriverPath){
BOOL Status = FALSE;

	SC_HANDLE ServiceHandle = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	if (ServiceHandle == NULL) return FALSE;

	SC_HANDLE ServiceHandleEx = CreateServiceW(ServiceHandle, ServiceName, ServiceName,  
		SERVICE_START | DELETE | SERVICE_STOP, SERVICE_KERNEL_DRIVER, 
		SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, DriverPath, NULL, 
		NULL, NULL, NULL, NULL);
		
	if(ServiceHandleEx == NULL){		
		ServiceHandleEx = OpenServiceW(ServiceHandle, ServiceName, SERVICE_START | DELETE | SERVICE_STOP);
		if(ServiceHandleEx == NULL)	goto end;
	}

	if (!StartServiceW(ServiceHandleEx, 0, NULL)) goto end;

	Status = TRUE;

end:
	CloseServiceHandle(ServiceHandleEx);
	CloseServiceHandle(ServiceHandle);
	
	return Status;
}

BOOL RemoveDriverWithServiceManager(wchar_t *ServiceName, wchar_t *DriverPath){
	SC_HANDLE ServiceHandle = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
	if (ServiceHandle == NULL) return FALSE;

	SC_HANDLE ServiceHandleEx = OpenServiceW(ServiceHandle, ServiceName, SERVICE_START | DELETE | SERVICE_STOP);
	if(ServiceHandleEx == NULL)	return FALSE;
	
	SERVICE_STATUS status;
	ControlService(ServiceHandleEx, SERVICE_CONTROL_STOP, &status);

    DeleteService(ServiceHandleEx);
    CloseServiceHandle(ServiceHandleEx);
	CloseServiceHandle(ServiceHandle);

	return TRUE;     
     
}

int __stdcall NativeLoadDriver(wchar_t *DriverPath, HWND hWnd){
	wchar_t ImagePath[1024] = L"\\??\\"; 
	NTSTATUS Status;
	unsigned long Disposition;
	DWORD Type = SERVICE_KERNEL_DRIVER;
	UNICODE_STRING u_str;
	WCHAR DrvImagePath[]= L"ImagePath";
	WCHAR DrvKeyType[] = L"Type";
	UNICODE_STRING MainKey, ValueNameDrv, DrvTypeValue;
	HANDLE mainDrvHandle, drvKeyHandle;
	OBJECT_ATTRIBUTES oBj;
	BOOL en, St;
	WCHAR RegUniPath[1024] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\";
	WCHAR RegUniPath2[1024] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\";
	WCHAR RegPath[1024] = L"SYSTEM\\CurrentControlSet\\Services\\";

	if(LoaderOptions.nt_api == 1){
		wcscat(ImagePath, DriverPath); 
		wcscat(RegPath, PathFindFileNameW(DriverPath));
		wcscat(RegUniPath2, PathFindFileNameW(DriverPath));
		RtlInitUnicodeString(&u_str, RegUniPath2);

		RtlInitUnicodeString(&MainKey, RegUniPath);
		InitializeObjectAttributes( &oBj, &MainKey, OBJ_CASE_INSENSITIVE, NULL, NULL ); 
		Status = NtCreateKey( &mainDrvHandle, KEY_ALL_ACCESS, &oBj, 0,  NULL, REG_OPTION_NON_VOLATILE,&Disposition );
		if(Status != STATUS_SUCCESS){
			return -1;
		}
		RtlInitUnicodeString(&MainKey, PathFindFileNameW(DriverPath)); 
		InitializeObjectAttributes( &oBj, &MainKey, OBJ_CASE_INSENSITIVE, mainDrvHandle, NULL );
		Status = NtCreateKey(&drvKeyHandle, KEY_ALL_ACCESS, &oBj, 0, NULL, REG_OPTION_NON_VOLATILE,&Disposition );
		if(Status != STATUS_SUCCESS){
			return -1;
		}
		RtlInitUnicodeString(&ValueNameDrv, DrvImagePath);
		RtlInitUnicodeString(&DrvTypeValue, DrvKeyType);
	
		Status = NtSetValueKey(drvKeyHandle, &ValueNameDrv, 0, REG_SZ, ImagePath, wcslen(ImagePath) * sizeof(WCHAR) + sizeof(WCHAR));
		if(Status != STATUS_SUCCESS){
			NtDeleteKey(drvKeyHandle);
			NtClose(drvKeyHandle);
			NtClose(mainDrvHandle);
			return -1;
		}

		Status = NtSetValueKey(drvKeyHandle, &DrvTypeValue, 0, REG_DWORD, &Type, sizeof(DWORD) );
		if(Status != STATUS_SUCCESS){
			NtDeleteKey(drvKeyHandle);
			NtClose(drvKeyHandle);
			NtClose(mainDrvHandle);
			return -1;
		}

		RtlAdjustPrivilege(10, TRUE, AdjustCurrentProcess, &en);
		Status = NtLoadDriver(&u_str);
		if(Status != STATUS_SUCCESS){
			NtDeleteKey(drvKeyHandle);
			NtClose(drvKeyHandle);
			NtClose(mainDrvHandle);
			return -1;
		}
		NtClose(drvKeyHandle);
		NtClose(mainDrvHandle);
	} else {
		St = RunDriverWithServiceManager(PathFindFileNameW(DriverPath), DriverPath);
		if(St){
			InsertBufferStatus (hWnd, L"[+] winapi!RunDriver OK. Status: %d\r\n", St);
		} else { 
			InsertBufferStatus (hWnd, L"[-] winapi!RunDriver ERROR. Status: %d\r\n", St);
			return -1;
		}
	}
	return 0;
}

int __stdcall NativeUnloadDriver(wchar_t *DriverPath, HWND hWnd){
	UNICODE_STRING u_str, RegEnum;
	NTSTATUS Status;
	HANDLE hKey;
	wchar_t debug[MAX_PATH] = {0};
	OBJECT_ATTRIBUTES ObjectAttributes;
	BOOL en, St;
	wchar_t RegUniPath[1024] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\";
	wchar_t RegUniPath2[1024] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\";
	wchar_t RegPath[1024] = L"SYSTEM\\CurrentControlSet\\Services\\";

	if(LoaderOptions.nt_api == 1){
		wcscat(RegUniPath, PathFindFileNameW(DriverPath));
		wcscat(RegUniPath2, PathFindFileNameW(DriverPath));
		wcscat(RegUniPath2, L"\\Enum");
		wcscat(RegPath, PathFindFileNameW(DriverPath));
	
		RtlInitUnicodeString(&u_str, RegUniPath); 
		RtlInitUnicodeString(&RegEnum, RegUniPath2); 
		RtlAdjustPrivilege(10, TRUE, AdjustCurrentProcess, &en);

		if(Status = NtUnloadDriver(&u_str) != STATUS_SUCCESS){
			InsertBufferStatus(hWnd, L"NtUnloadDriver status: 0x%08x\r\n", Status);
			return -1;
		} else {
			InitializeObjectAttributes(&ObjectAttributes, &RegEnum, OBJ_CASE_INSENSITIVE, NULL, NULL);
			Status = NtOpenKey(&hKey, KEY_ALL_ACCESS, &ObjectAttributes);
			if(Status != STATUS_SUCCESS){
				InsertBufferStatus(hWnd, L"NtOpenKey status: 0x%08x\r\n", Status);
				return -2;
			}
			Status = NtDeleteKey(hKey);
			if(Status != STATUS_SUCCESS){
				InsertBufferStatus(hWnd, L"NtDeleteKey status: 0x%08x\r\n", Status);
				return -2;
			}
			NtClose(hKey);
			InitializeObjectAttributes(&ObjectAttributes, &u_str, OBJ_CASE_INSENSITIVE, NULL, NULL);
			Status = NtOpenKey(&hKey, KEY_ALL_ACCESS, &ObjectAttributes);
			if(Status != STATUS_SUCCESS){
				InsertBufferStatus(hWnd, L"NtOpenKey status: 0x%08x\r\n", Status);
				return -2;
			}
			Status = NtDeleteKey(hKey);
			if(Status != STATUS_SUCCESS){
				InsertBufferStatus(hWnd, L"NtOpenKey status: 0x%08x\r\n", Status);
				return -2;
			}
			NtClose(hKey);
		}
	} else {
		St = RemoveDriverWithServiceManager(PathFindFileNameW(DriverPath), DriverPath);
		if(St){
			InsertBufferStatus (hWnd, L"[+] winapi!StopDriver OK. Status: %d\r\n", St);
		} else { 
			InsertBufferStatus (hWnd, L"[-] winapi!StopDriver ERROR. Status: %d\r\n", St);
			return -1;
		}
	}
return 0;
}

int __stdcall LoadDriverBadWay(wchar_t *ModulePath){
	SYSTEM_LOAD_AND_CALL_IMAGE img;
	BOOL en;
	wchar_t driver_full_path[1024] = L"\\??\\";
	wcscat(driver_full_path, ModulePath);
	RtlInitUnicodeString(&(img.ModuleName),driver_full_path);
	RtlAdjustPrivilege(10, TRUE, AdjustCurrentProcess, &en);
	if(ZwSetSystemInformation(SystemLoadAndCallImage, &img,
		sizeof(SYSTEM_LOAD_AND_CALL_IMAGE)) != STATUS_SUCCESS){
		return -1;
	} else {
		return 0;
	}
return -1;
}

int __stdcall LoadKernelModule(wchar_t *ModulePath, 
							   HWND hWnd,
							   int IfUnload,
							   int IfDelete)
{
	int Status;
	BOOL St;
	Status = NativeLoadDriver(ModulePath, hWnd);
	if(Status == -1){
			int mbID = MessageBoxW(0, L"Would you like to use ZwSetSystemInformation?", 
										L"Chose your destiny", MB_YESNO);
			switch(mbID){
				case IDYES:
					{
					int Sta = LoadDriverBadWay(ModulePath);
						if(Sta == 0){
							InsertBufferStatus (hWnd, sys_loaded);
						} else {
							InsertBufferStatus (hWnd, sys_load_failed);
						}
					}
				break;
				case IDNO:
					{
					InsertBufferStatus (hWnd, sys_load_failed);
					return -1;
					}
				break;
			}
	} else if(Status == -2){
		InsertBufferStatus (hWnd, L"Driver registry keys still present. Delete them manualy.\r\n");
	} else {
		InsertBufferStatus (hWnd, sys_loaded);
	}
	if(IfUnload == 1){ // we want to unload driver right away...
		Status = NativeUnloadDriver(ModulePath, hWnd);
		if(Status != 0){
				InsertBufferStatus (hWnd, sys_unload_failed);
				return -1;
			} else {
				InsertBufferStatus (hWnd, sys_unloaded);
			}
	}
	if(IfDelete == 1){	// we want to delete driver file
		if(LoaderOptions.nt_api == 1){
			NtRemoveFile(ModulePath, hWnd);
		} else {
			St = DeleteFileW(ModulePath);
			if(St)
				InsertBufferStatus (hWnd, L"[+] kernel32!DeleteFileW Status: %d\r\n", St);
			else 
				InsertBufferStatus (hWnd, L"[-] kernel32!DeleteFileW Status: %d\r\n", St);
		}
	}
return 0;
}

int __stdcall UnloadKernelModule(wchar_t *ModulePath,
								 HWND hWnd,
								 int IfDelete)
{
	int Status;
	BOOL St;
		Status = NativeUnloadDriver(ModulePath, hWnd);
		if(Status == -1){
				InsertBufferStatus (hWnd, sys_unload_failed);
				return -1;
		} else if(Status == -2){
			InsertBufferStatus (hWnd, L"Driver registry keys still present. Delete them manualy.\r\n");
		} else {
			InsertBufferStatus (hWnd, sys_unloaded);
		}
	if(IfDelete == 1){	// we want to delete driver file
		if(LoaderOptions.nt_api == 1){
			NtRemoveFile(ModulePath, hWnd);
		} else {
			St = DeleteFileW(ModulePath);
			if(St)
				InsertBufferStatus (hWnd, L"[+] kernel32!DeleteFileW Status: %d\r\n", St);
			else 
				InsertBufferStatus (hWnd, L"[-] kernel32!DeleteFileW Status: %d\r\n", St);
		}
	}
return 0;
}