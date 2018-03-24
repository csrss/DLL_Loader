
#define NERR_BASE 2100
#define MAX_NERR (NERR_BASE+899)

void DisplayErrorText(DWORD dwLastError, HWND hWnd){
	HMODULE hModule = 0; // default to system source
	LPWSTR MessageBuffer;
	DWORD dwBufferLength;

	DWORD dwFormatFlags =	FORMAT_MESSAGE_ALLOCATE_BUFFER |
							FORMAT_MESSAGE_IGNORE_INSERTS |
							FORMAT_MESSAGE_FROM_SYSTEM;

// If dwLastError is in the network range, load the message source
	if((dwLastError >= NERR_BASE) && (dwLastError <= MAX_NERR)){
		hModule = LoadLibraryEx(TEXT("netmsg.dll"), NULL, LOAD_LIBRARY_AS_DATAFILE);
		if(hModule)
			dwFormatFlags |= FORMAT_MESSAGE_FROM_HMODULE;
	}

// Call FormatMessage() to allow for message text to be acquired from the system
// or from the supplied module handle
	if(dwBufferLength = FormatMessageW(	dwFormatFlags,
										hModule,
										dwLastError,
										MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
										(LPWSTR) &MessageBuffer,
										0, 0))
	{
	SetDlgItemTextW(hWnd, IDC_EDIT2, MessageBuffer);
	LocalFree(MessageBuffer);
	}

// If we loaded a message source, unload it.
	if(hModule) FreeLibrary(hModule);
}

static BOOL NetStatusDialogProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam){
	wchar_t Code[MAX_PATH] = {0};
	switch(uMsg){

		case WM_INITDIALOG:
			{
				InitTreeViewHeader(hWnd, IDC_LIST1);

				CreateToolTip(IDC_EDIT1, hWnd, L"Input error code here.");
				CreateToolTip(IDC_EDIT2, hWnd, L"Here you see what means what.");
			}
		return TRUE;

		case WM_DESTROY:
			EndDialog(hWnd, 0);
		return TRUE;

		case WM_COMMAND:
			switch (LOWORD(wParam)) {
				case IDOK:
					{
						GetDlgItemText(hWnd, IDC_EDIT1, Code, sizeof Code);
						if(Code == NULL || wcscmp(Code, L"") == 0){
							SetDlgItemTextW(hWnd, IDC_EDIT2, L"No code specified!");
							return -1;
						} else {
							DisplayErrorText(_wtoi(Code), hWnd);
						}
					}
					break;

				case IDCANCEL:
					EndDialog(hWnd, 0);
					break;

				case IDC_BUTTON1:
					{
						InsertBufferStatus(hWnd, L"suchak xD ><");
					}
				break;

				case IDC_BUTTON2:
					{
						ClearAllBuffer(hWnd, IDC_LIST1);
					}
				break;
			}
		return TRUE;
	}
	return FALSE;
}