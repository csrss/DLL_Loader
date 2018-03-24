
#define DLL_UNLOAD_MODULE			3001
#define DLL_UNLOAD_DELETE_MODULE	3002
#define DLL_CALL_FUNCTION			3003
#define DLL_FUNCTION_DETAILS		3004
#define DLL_FUNC_ADD_DETAILS		3005
#define DLL_FUNC_MOD_DETAILS		3006
#define DLL_FUNCTION_TRASH_IT		3007
#define SYS_SEND_CUSTOM_IOCTL		3008

wchar_t * AnsiToUnicode2(char * pstr){
	LPWSTR pwstr;
	DWORD dwWritten;
	int wcsChars;// = strlen(pstr);
	if(!pstr)return NULL;
	if((int)strlen(pstr) <= 0) return NULL;
	wcsChars = (int)strlen(pstr);
	pwstr = (wchar_t *)malloc(wcsChars * sizeof WCHAR + 1);
	dwWritten = MultiByteToWideChar(CP_UTF8, 0, pstr, -1, pwstr, (wcsChars * sizeof WCHAR + 1));
//	pwstr[dwWritten+1] = '\0';
	return pwstr;
}

int __stdcall VerifyFilePresence(wchar_t *RelativePath){
	IO_STATUS_BLOCK    ioStatusBlock;
	DWORD dwShit;
	NTSTATUS Status;
	HANDLE hFile;
	UNICODE_STRING PathNameString;
	OBJECT_ATTRIBUTES ObjectAttributes;
	wchar_t lpPathName[1024] = {0x5c, 0x3f, 0x3f, 0x5c, 0x00};
	wchar_t Current[512];
	DWORD cLen = sizeof(Current);
	NtZeroMemory(Current, cLen);

	dwShit = GetCurrentDirectoryW(cLen, Current);
	if(dwShit > cLen){
		qmb(L"ERROR", L"Fatal Error!");
		return -1;
	}
	wcscat(lpPathName, Current);
	wcscat(lpPathName, L"\\");
	wcscat(lpPathName, RelativePath);
	RtlInitUnicodeString(&PathNameString, lpPathName);
	InitializeObjectAttributes( &ObjectAttributes, &PathNameString, OBJ_CASE_INSENSITIVE, NULL, NULL );
	Status = NtCreateFile(	&hFile,
							GENERIC_READ,
							&ObjectAttributes,
							&ioStatusBlock,
							NULL,
							FILE_ATTRIBUTE_NORMAL,
							FILE_SHARE_READ,
							0x00000001,		//FILE_OPEN
							0x00000040,		//FILE_NON_DIRECTORY_FILE
							NULL,
							0);
	if(Status == STATUS_SUCCESS){
		NtClose(hFile);
		return 1;
	} else {
		return 0;
	}
return -1;
}

wchar_t *LocateIniFile(){
	DWORD dwRet;
	static wchar_t *output;
	size_t Len;
	dwRet = GetCurrentDirectoryW(0, NULL);
	Len = sizeof(wchar_t) * dwRet + MAX_PATH;
	output = (wchar_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Len);
	GetCurrentDirectoryW(Len, output);
	wcscat(output, L"\\Settings.ini");
	return output;
}

int __stdcall InitSettings(){
	wchar_t buffer[MAX_PATH];
	size_t buffLen = sizeof(buffer);
	Clear(buffer);

	GetPrivateProfileStringW(L"NTAPI", L"value", NULL, buffer, buffLen, LocateIniFile());
	if(wcscmp(buffer, L"TRUE") == 0) LoaderOptions.nt_api = 1;
	else LoaderOptions.nt_api = 0;
	Clear(buffer);

	GetPrivateProfileStringW(L"AutoClearBuffer", L"value", NULL, buffer, buffLen, LocateIniFile());
	if(wcscmp(buffer, L"TRUE") == 0) LoaderOptions.auto_buffer_clear = 1;
	else LoaderOptions.auto_buffer_clear = 0;
	Clear(buffer);

	GetPrivateProfileStringW(L"DllResolveExports", L"value", NULL, buffer, buffLen, LocateIniFile());
	if(wcscmp(buffer, L"TRUE") == 0) LoaderOptions.dll_resolve_exports = 1;
	else LoaderOptions.dll_resolve_exports = 0;
	Clear(buffer);

	GetPrivateProfileStringW(L"DllResolveBase", L"value", NULL, buffer, buffLen, LocateIniFile());
	if(wcscmp(buffer, L"TRUE") == 0) LoaderOptions.dll_resolve_base = 1;
	else LoaderOptions.dll_resolve_base = 0;
	Clear(buffer);

	GetPrivateProfileStringW(L"DllResolvePath", L"value", NULL, buffer, buffLen, LocateIniFile());
	if(wcscmp(buffer, L"TRUE") == 0) LoaderOptions.dll_resolve_path = 1;
	else LoaderOptions.dll_resolve_path = 0;
	Clear(buffer);

	GetPrivateProfileStringW(L"VistaGlass", L"value", NULL, buffer, buffLen, LocateIniFile());
	if(wcscmp(buffer, L"TRUE") == 0) LoaderOptions.vista_glass = STATUS_VISTA_GLASS;
	else LoaderOptions.vista_glass = STATUS_NO_GLASS;
	Clear(buffer);

	GetPrivateProfileStringW(L"OsInfo", L"value", NULL, buffer, buffLen, LocateIniFile());
	if(wcscmp(buffer, L"TRUE") == 0) LoaderOptions.show_os_info = 1;
	else LoaderOptions.show_os_info = 0;
	Clear(buffer);

	GetPrivateProfileStringW(L"SysResolveNames", L"value", NULL, buffer, buffLen, LocateIniFile());
	if(wcscmp(buffer, L"TRUE") == 0) LoaderOptions.resolve_module_names = 1;
	else LoaderOptions.resolve_module_names = 0;
	Clear(buffer);

	GetPrivateProfileStringW(L"DefaultUserLanguage", L"value", NULL, buffer, buffLen, LocateIniFile());
	if(wcscmp(buffer, L"EN") == 0) LoaderOptions.user_default_lang = EN;
	else if(wcscmp(buffer, L"PL") == 0) LoaderOptions.user_default_lang = PL;
	else if(wcscmp(buffer, L"RU") == 0) LoaderOptions.user_default_lang = RU;
	else LoaderOptions.user_default_lang = EN;
	Clear(buffer);

	return 0;
}

wchar_t * __stdcall GetComboText(__in int ControlId, __in HWND hWnd){
	LPTSTR lpszString; 
	int nCurSel;
	nCurSel = SendDlgItemMessage(hWnd, ControlId, CB_GETCURSEL, 0, 0);
	if (nCurSel != -1){
		lpszString = (LPTSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 
		sizeof(TCHAR)*(SendDlgItemMessage(hWnd, ControlId, CB_GETLBTEXTLEN, nCurSel, 0) + 1));
		if (lpszString != NULL){
			SendDlgItemMessage(hWnd, ControlId, CB_GETLBTEXT, nCurSel, (LPARAM)lpszString);
			return lpszString;
		}
	//	HeapFree(GetProcessHeap(), 0, (LPVOID)lpszString);
	}
}

int __stdcall SwitchParams(int Param,
						   wchar_t *Section, 
						   HWND hWnd,
						   int ID,
						   bool IsRadio)
{
	if(!IsRadio){
		if(Param == 1){
			Param = 0;
			CheckDlgButton(hWnd, ID, BST_UNCHECKED);
			WritePrivateProfileStringW(Section, L"value", L"FALSE", LocateIniFile());
			return Param;
		} else {
			Param = 1;
			CheckDlgButton(hWnd, ID, BST_CHECKED);
			WritePrivateProfileStringW(Section, L"value", L"TRUE", LocateIniFile());
			return Param;
		}
	} else {
		return Param;
	}
return -1;
}

int __stdcall SetStyleEx(HWND hWnd, int ControlID){
	wchar_t *Explo = L"Explorer";
	HWND hItem = GetDlgItem(hWnd, ControlID);
	DWORD SetWindowTheme = (DWORD)GetAddr("SetWindowTheme", L"UxTheme.dll");
	if(!SetWindowTheme) return -1;
	__asm {
		push 0
		push Explo
		push hItem
		call dword ptr SetWindowTheme
	}
}

char* GetProcessName( DWORD processID)
{
	static char szProcessName[MAX_PATH];
 //   BOOL bRC = FALSE;
 
    // Get a handle to the process.
 
    HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION |
                                   PROCESS_VM_READ,
                                   FALSE, processID );
 
    // Get the process name.
 
    if (NULL != hProcess )
    {
        HMODULE hMod;
        DWORD cbNeeded;
 
        if ( EnumProcessModules( hProcess, &hMod, sizeof(hMod),
             &cbNeeded) )
        {
            GetModuleBaseNameA( hProcess, hMod, szProcessName,
                               MAX_PATH );
 
   //         bRC = TRUE;
        }
    }
 
    CloseHandle( hProcess );
 
    return szProcessName;
}

/**************/
HANDLE bufferready;
HANDLE dataready;
HANDLE buffer;
void * str;
/****************/

DWORD __stdcall OutputDebugStringCatch(LPVOID lParam){
	SECURITY_ATTRIBUTES sa; 
	SECURITY_DESCRIPTOR sd; 
	sa.nLength = sizeof(SECURITY_ATTRIBUTES); 
	sa.bInheritHandle = TRUE; 
	sa.lpSecurityDescriptor = &sd; 

	InsertBufferStatus((HWND)lParam, L"[+] Debug Monitor Started\n"); 

	if(InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION) == FALSE){ 
		InsertBufferStatus((HWND)lParam, L"[-] InitializeSecurityDescriptor failed\n"); 
		return 1; 
	} 

	if(SetSecurityDescriptorDacl(&sd, TRUE, (PACL)NULL, FALSE) == FALSE){ 
		InsertBufferStatus ((HWND)lParam, L"[-] SetSecurityDescriptorDacl failed\n"); 
		return 1; 
	} 

	bufferready = CreateEvent(&sa, FALSE, FALSE, L"DBWIN_BUFFER_READY"); 
	if (bufferready == NULL){ 
		InsertBufferStatus ((HWND)lParam, L"[-] CreateEvent failed\n"); 
		return 1; 
	} 

	if (GetLastError() == ERROR_ALREADY_EXISTS){ 
		InsertBufferStatus((HWND)lParam, L"[*] Debugger Already Running\n"); 
		return 1;	
	} 

	dataready = CreateEvent(&sa, FALSE, FALSE, L"DBWIN_DATA_READY"); 
	if (dataready == NULL){ 
		InsertBufferStatus((HWND)lParam, L"[-] CreateEvent failed\n"); 
		CloseHandle(bufferready); 
		return 1; 
	} 

	buffer = CreateFileMapping(INVALID_HANDLE_VALUE, 
										&sa, 
										PAGE_READWRITE, 
										0, 
										4096, 
										L"DBWIN_BUFFER"); 
	if (buffer == NULL){ 
		InsertBufferStatus ((HWND)lParam, L"[-] CreateFileMapping failed\n"); 
		CloseHandle(bufferready); 
		CloseHandle(dataready); 
		return 1; 
	} 

	str = MapViewOfFile(buffer, FILE_MAP_READ, 0, 0, 4096); 

	if (str == NULL){ 
		InsertBufferStatus((HWND)lParam, L"[-] MapViewOfFile failed\n"); 
		CloseHandle(bufferready); 
		CloseHandle(dataready); 
		CloseHandle(buffer); 
		return 1; 
	} 

	char * string = (char *)str + sizeof(DWORD); 
	DWORD lastpid = 0xffffffff; 
	bool cr = true; 

	while (true){ 
		if (SetEvent(bufferready) == FALSE){ 
			InsertBufferStatus((HWND)lParam, L"[-] SetEvent failed\n"); 
			CloseHandle(bufferready); 
			CloseHandle(dataready); 
			UnmapViewOfFile(str); 
			CloseHandle(buffer); 
			return 1; 
		} 

		if (WaitForSingleObject(dataready, INFINITE) != WAIT_OBJECT_0){ 
			break; 
		} else { 
			char container[1024] = {0};
			DWORD pid = *(DWORD *)str; 
			if (lastpid != pid) { 
				lastpid = pid; 
				if (!cr){ 
					cr = true; 
				} 
			} 

		if (cr){ 
			sprintf(container, "[%s] : %s", GetProcessName(lastpid), (char*)string);
		} else {
			sprintf(container, "[||] : %s", (char*)string);
		}
		wchar_t *shit = AnsiToUnicode2(container);
		InsertBufferStatus((HWND)lParam, shit);
		} 
	} 

	InsertBufferStatus((HWND)lParam, L"[-] WaitForSingleObject failed\n"); 
	CloseHandle(bufferready); 
	CloseHandle(dataready); 
	UnmapViewOfFile(str); 
	CloseHandle(buffer); 
	return 0; 
}
