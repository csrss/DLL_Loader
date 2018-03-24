#pragma warning(disable: 4996)

wchar_t file_not_selected[MAX_PATH] = L"[-] File not specified!\r\n";
wchar_t no_proc_for_inj[MAX_PATH] = L"[-] Injection specified but no process selected!\r\n";
wchar_t cannot_open_file[MAX_PATH] = L"[-] Could not open File!\r\n";
wchar_t cannot_check_file[MAX_PATH] = L"[-] Could not check file!\r\n";
wchar_t not_win_exe[MAX_PATH] = L"[-] Looks like it is not windows executable!\r\n";
wchar_t dll_detected[MAX_PATH] = L"[+] DLL Detected.\r\n";
wchar_t sys_detected[MAX_PATH] = L"[+] Driver Detected.\r\n";
wchar_t unknown_file[MAX_PATH] = L"[-] File format not recognized.\r\n";

wchar_t loading_file[MAX_PATH] = L"Loading file";
wchar_t unloading_file[MAX_PATH] = L"Unloading file";
wchar_t dll_unloaded[MAX_PATH] = L"[+] Dll Successfuly Unloaded.\r\n";
wchar_t dll_loaded[MAX_PATH] = L"[+] Dll Successfuly Loaded.\r\n";
wchar_t sys_unloaded[MAX_PATH] = L"[+] Driver Successfuly Unloaded.\r\n";
wchar_t sys_loaded[MAX_PATH] = L"[+] Driver Successfuly Loaded.\r\n";
wchar_t file_deleted[MAX_PATH] = L"[+] File Successfuly Deleted.\r\n";
wchar_t dll_not_found_mem[MAX_PATH] = L"[-] DLL not found in process memory.\r\n";
wchar_t dll_found_mem[MAX_PATH] = L"[+] DLL found in process memory.\r\n";
wchar_t dll_unload_failed[MAX_PATH] = L"[-] Unable to unload DLL!\r\n";
wchar_t sys_unload_failed[MAX_PATH] = L"[-] Driver could not be unloaded!\r\n";
wchar_t sys_load_failed[MAX_PATH] = L"[-] Driver could not be loaded!\r\n";
wchar_t dll_load_failed[MAX_PATH] = L"[-] Loading Dll Failed!\r\n";

wchar_t pid_failed[MAX_PATH] = L"[-] Unable to get target process ID!\r\n";
wchar_t pid_ok[MAX_PATH] = L"[+] Got proc ID.\r\n";
wchar_t proc_open_failed[MAX_PATH] = L"[-] Unable to open target process!\r\n";
wchar_t proc_open_ok[MAX_PATH] = L"[+] Target proc opened.\r\n";
wchar_t virtmemaloc_failed[MAX_PATH] = L"[-] Unable to alocate virtual memory!\r\n";
wchar_t virtmemaloc_ok[MAX_PATH] = L"[+] Virtual memory alocated.\r\n";
wchar_t virtmemwrite_failed[MAX_PATH] = L"[-] Unable to write virtual memory!\r\n";
wchar_t virtmemwrite_ok[MAX_PATH] = L"[+] Virtual memory written.\r\n";

wchar_t file_not_found[MAX_PATH] = L"Dll Not Found!";
wchar_t load_dll_failed[MAX_PATH] = L"Dll Loading error!";
wchar_t unload_dll_failed[MAX_PATH] = L"Dll unloading error!";
wchar_t dllisnotinmem[MAX_PATH] = L"Dll is not in this process's memory!";
wchar_t injected_ok[MAX_PATH] = L"[+] Injected!\r\n";
wchar_t injection_err[MAX_PATH] = L"[-] Injection failed! Giving up.\r\n";
wchar_t firstinj_err[MAX_PATH] = L"[-] First injection attempt failed! Trying another way...\r\n";

#include "resource.h"
#include "ui.h"
#include "nt.h"
//	SendDlgItemMessage (hWnd, IDC_EDIT1, EM_REPLACESEL, 0, (LPARAM)StatusText);
//int __stdcall AddStatus(HWND hWnd, wchar_t *StatusText){
//	return InsertBufferStatus(hWnd, IDC_LIST1, StatusText);
//}

typedef struct _LOADER_OPTIONS {
	int nt_api;
	int auto_buffer_clear;
	int dll_resolve_exports;
	int dll_resolve_base;
	int dll_resolve_path;
	int vista_glass;
	int show_os_info;
	int user_default_lang;
	int resolve_module_names;
} LOADER_OPTIONS, *PLOADER_OPTIONS;
LOADER_OPTIONS LoaderOptions;

CLIENT_ID idCleaner;
HANDLE hCleaner;

int __stdcall NtRemoveFile(wchar_t *FileName, HWND hWnd){
wchar_t lpPathName[1024] = { 0x5c, 0x3f, 0x3f, 0x5c, 0x00};
NTSTATUS Status;
UNICODE_STRING PathNameString;
OBJECT_ATTRIBUTES ObjectAttributes;

wcscat(lpPathName, FileName);
PathNameString.Buffer = lpPathName;
PathNameString.Length = wcslen(lpPathName) * sizeof(wchar_t);
InitializeObjectAttributes( &ObjectAttributes, &PathNameString, OBJ_CASE_INSENSITIVE, NULL, NULL );
Status = NtDeleteFile(&ObjectAttributes);
	if(Status != STATUS_SUCCESS){
		InsertBufferStatus(hWnd, L"[-] NtDeleteFile Error. Status: 0x%08x\r\n", Status);
		return -1;
	} else {
		InsertBufferStatus(hWnd, file_deleted);
	}
return 0;
}

DWORD __stdcall DllInjection(wchar_t *DllPath, 
							 BOOL Mode, 
							 wchar_t *TargetProc,
							 HWND hWnd,
							 int IfUnload,
							 int IfDelete);

DWORD __stdcall SysInjection(wchar_t *DllPath, 
							 BOOL Mode, 
							 wchar_t *TargetProc,
							 HWND hWnd,
							 int IfUnload,
							 int IfDelete);

#include "core.h"
#include "DllInjection.h"
#include "SysInjection.h"

#define TERMINATE_HOT_KEY		666
#define TRAY_HOT_KEY			667
#define FROMTRAY_HOT_KEY		668
#define SYS_ABOUT_INFO			669
#define SYS_QUIT				670
#define SYS_REBOOT				671
#define SYS_SHUTDOWN			672
#define ERROR_LOOKUP			673
#define SYS_CATCH_W32DEBUG		674
#define SYS_CATCH_VKRNLDEBUG	675

int load_dll_mode = 1;
int unload_dll_mode = 0;
int injection_mode = 0;
int not_injection_mode = 1;
int proc_list = 0;
int unload_file_option = 1;
int delete_file_option = 0;

#pragma warning(disable:4996) 

#define ID_TRAY_APP_ICON                5000
#define ID_TRAY_EXIT_CONTEXT_MENU_ITEM  3000
#define WM_TRAYICON ( WM_USER + 1 )
unsigned int WM_TASKBARCREATED = 0;
NOTIFYICONDATA g_notifyIconData;
HMENU g_menu;
HWND g_hwnd;
HINSTANCE hMainIn;
HANDLE MainMutex;
#define MUTEXRUN	L"dll_loader_unloader_injector_uninjector_running"

int __stdcall KillSelf(){
	__asm push 0;
	__asm push -1;
	__asm call dword ptr NtTerminateProcess;
}

int __stdcall ProgInfo(){
	wchar_t Caption[] = L"Ultima Loader Information";
	wchar_t Message[] = L"Ultima Loader™\n\
by Machinized Fractals\n\
http://www.machinized.com\n\n\
Utility for loading DLLs and Kernel Mode Drivers.\n\
Loader detects which file type has been chosen and \n\
depends on that loads it the way it has to be loaded.\n\
Ultima Loader can inject loading routine inside another\n\
process, it can inject into Win32 processes( for example \n\
explorer.exe) and NT processes(for example csrss.exe).\n\
It can inject into current user processes and \n\
SYSTEM processes. It is the easiest and the most \n\
userfriendly application for loading both drivers and \n\
dlls. Read extended manual in 'Manual' folder.";
	MessageBoxW(0, Message, Caption, MB_ICONINFORMATION);
	return 0;
}

void Restore(){
  Shell_NotifyIcon(NIM_DELETE, &g_notifyIconData);
  ShowWindow(g_hwnd, SW_SHOW);
}

void Minimize(){
  Shell_NotifyIcon(NIM_ADD, &g_notifyIconData);
  ShowWindow(g_hwnd, SW_HIDE);
}

void InitNotifyIconData(){
  NtZeroMemory( &g_notifyIconData, sizeof( NOTIFYICONDATA ) ) ;
  g_notifyIconData.cbSize = sizeof(NOTIFYICONDATA);
  g_notifyIconData.hWnd = g_hwnd;
  g_notifyIconData.uID = ID_TRAY_APP_ICON;
  g_notifyIconData.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP; 
  g_notifyIconData.uCallbackMessage = WM_TRAYICON;
  g_notifyIconData.hIcon = (HICON)LoadImage( hMainIn, MAKEINTRESOURCE(IDI_ICON1), IMAGE_ICON, 0, 0, 0  ) ;
  wcscpy(g_notifyIconData.szTip, L"DLL Loader");
}

wchar_t *GetDLL(LPVOID lParam){

OPENFILENAME ofn; 
static wchar_t dll_global[1024];
wchar_t szFile[MAX_PATH]; 
NtZeroMemory(&ofn, sizeof(ofn));
ofn.lStructSize = sizeof(ofn);
ofn.hwndOwner = GetDesktopWindow();
ofn.lpstrFile = szFile;
ofn.lpstrFile[0] = '\0';
ofn.nMaxFile = sizeof(szFile);
ofn.lpstrFilter = L"All\0*.*\0Dll's\0*.DLL\0Drivers\0*.SYS\0";
ofn.nFilterIndex = 1;
ofn.lpstrFileTitle = NULL;
ofn.nMaxFileTitle = 0;
ofn.lpstrInitialDir = NULL;
ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

if (GetOpenFileName(&ofn)==TRUE) {
	if(wcslen(ofn.lpstrFile) > 0){
		NtZeroMemory(&dll_global, sizeof(dll_global));
		wcscpy(dll_global, ofn.lpstrFile);
		SetDlgItemText((HWND)lParam, IDC_BUTTON1, PathFindFileNameW(ofn.lpstrFile));
	}
}
return dll_global;
}

wchar_t *SysInfoGet(){
OSVERSIONINFO VersionInfo;
static wchar_t output[1024] = {0};
//Clear(output);
NtZeroMemory(&VersionInfo, sizeof(VersionInfo));
VersionInfo.dwOSVersionInfoSize = sizeof(VersionInfo);
	if(!GetVersionEx(&VersionInfo)){
		swprintf(output, 1024, L"Uknown");
	} else {
		swprintf(output, 1024, L"Windows %d.%d.%d %s", VersionInfo.dwMajorVersion, VersionInfo.dwMinorVersion, VersionInfo.dwBuildNumber, VersionInfo.szCSDVersion);
	}
return output;
}

// this will determine which language to set
LCID GetLocalLanguage(){
	LCID Cl;
	wchar_t buffer[MAX_PATH];
	size_t buffLen = sizeof(buffer);
	NTSTATUS st;
	if(!NtQueryDefaultLocale) { 
		return 0x0000;
	} else {
		GetPrivateProfileStringW(L"DefaultUserLanguage", L"value", NULL, buffer, buffLen, LocateIniFile());
		if(wcscmp(buffer, L"EN") == 0) { 
			LoaderOptions.user_default_lang = EN;
			Cl = 0x0409;
		} else if(wcscmp(buffer, L"PL") == 0) { 
			LoaderOptions.user_default_lang = PL;
			Cl = 0x0415;
		} else if(wcscmp(buffer, L"RU") == 0) {
			LoaderOptions.user_default_lang = RU;
			Cl = 0x0419;
		} else {
			st = NtQueryDefaultLocale(FALSE, &Cl);
			if(st != STATUS_SUCCESS) 
				return 0x0000;
		}
	}
	return Cl;
}

int __stdcall NtReboot(HWND hWnd, BOOL Mode){
	NTSTATUS Status;
	BOOL en;
	int id;
	wchar_t debug[MAX_PATH] = {0};
	if(Mode == FALSE){
		id = MessageBoxW(0, L"Reboot machine?", L"QUESTION", MB_ICONQUESTION | MB_YESNO);
	} else if(Mode == TRUE){
		id = MessageBoxW(0, L"Shutdown machine?", L"QUESTION", MB_ICONQUESTION | MB_YESNO);
	}
	switch(id){
		case IDYES:
			{
				RtlAdjustPrivilege(19, TRUE, AdjustCurrentProcess, &en);
				if(Mode == FALSE){
					Status = NtShutdownSystem(ShutdownReboot);
				} else if(Mode == TRUE){
					Status = NtShutdownSystem(ShutdownPowerOff);
				}
				if(Status != STATUS_SUCCESS){
					swprintf(debug, MAX_PATH, L"[-] Machine reboot failed! Status: 0x%08x", Status);
					InsertBufferStatus(hWnd, debug);
					return -1;
				} else {
					return 0;
				}
			}
		break;
		case IDNO:
		break;
	}
return 1;
}

DWORD GetPEB(){
	DWORD result;
	__asm {
		mov eax,dword ptr fs:[0x30]
		mov result,eax;
	}
return result;
}
/*
HANDLE __stdcall AsmGetProcessHeap(){
	__asm {
		mov eax,dword ptr fs:[00000018h]
		mov eax,dword ptr [eax+30h]
		mov eax,dword ptr [eax+18h]
		ret
	}
}
*/ 
wchar_t *RetnPEB(){
	DWORD pPEB = GetPEB();
	DWORD PEB_LDR_DATA = (unsigned long)*(DWORD*)(pPEB+0x0C);
	static wchar_t out[MAX_PATH] = {0};
	swprintf(out, MAX_PATH, L"PEB: 0x%08x ::: PEB_LDR_DATA: 0x%08x", pPEB, PEB_LDR_DATA);
	return out;
}

wchar_t *RetnCM(){
	static wchar_t out[MAX_PATH] = {0};
	DWORD pPEB = GetPEB();
	DWORD PEB_LDR_DATA = (unsigned long)*(DWORD*)(pPEB+0x0C);
	DWORD InLoadOrderModuleListHead = (unsigned long)*(DWORD*)(PEB_LDR_DATA+0x0C);
	DWORD ModuleFileName = (unsigned long)*(PDWORD*)(InLoadOrderModuleListHead+0x28);
	swprintf(out, MAX_PATH, L"Current Module: 0x%08x", ModuleFileName);
	return out;
}

DWORD __stdcall LogsAutoCleaner(LPVOID lParam){
	HWND hWnd = (HWND)lParam;
	LARGE_INTEGER Value;
	size_t TextLen;
	wchar_t out[1024] = {0};
	Value.QuadPart = NTRELATIVE(SECONDS(10));
	while(TRUE){
		NtDelayExecution(FALSE, &Value);
		GetDlgItemTextW(hWnd, IDC_EDIT1, out, 1024);
		TextLen = wcslen(out);
		if(TextLen >= 512){
			SetDlgItemText (hWnd, IDC_EDIT1, L"");
		}
		Clear(out);
	}
	return 1;
}

int __stdcall InitAutoCleaner(HWND hWnd){
	NTSTATUS Status;
	wchar_t debug[MAX_PATH] = {0};
	Clear(debug);
	Status = RtlCreateUserThread((HANDLE)-1, NULL, FALSE, 0, 0, 0, LogsAutoCleaner, hWnd, &hCleaner, &idCleaner);
	if(Status != STATUS_SUCCESS){
		swprintf(debug, MAX_PATH, L"[-] AutoCleaner creation failed! Status: 0x%08x\r\n", Status);
		InsertBufferStatus(hWnd, debug);
		return -1;
	} else {
		swprintf(debug, MAX_PATH, L"[+] AutoCleaner created!\r\n");
		InsertBufferStatus(hWnd, debug);
		return 0;
	}
return 1;
}

#define ANIMATION_TIMER						1234
#define ANIMATION_COLLASE					1235
#define ANIMATION_LIMIT						8
#define ANIMATION_OFFSET					4
#define EXPAND_MAX_STEPS					20
int m_nAnimationCount = 0;
int n_nAnimationCount = 0;
int hidden = 0;

int __stdcall ShowHideBottomPanel(HWND hWnd, bool Mode){
// ShowWindow(frame, Mode ? SW_HIDE : SW_SHOW);
	HWND gropu1 = GetDlgItem(hWnd, IDC_STATIC_GR1);
	HWND group2 = GetDlgItem(hWnd, IDC_STATIC_GR2);
	HWND text1 = GetDlgItem(hWnd, IDC_STATIC_TEXT1);
	HWND text2 = GetDlgItem(hWnd, IDC_STATIC_TEXT2);
	HWND edit1 = GetDlgItem(hWnd, IDC_EDIT1);
	HWND edit2 = GetDlgItem(hWnd, IDC_EDIT2);
	HWND tree1 = GetDlgItem(hWnd, IDC_TREE1);
	HWND tree2 = GetDlgItem(hWnd, IDC_TREE2);
	HWND check7 = GetDlgItem(hWnd, IDC_CHECK7);
	HWND check8 = GetDlgItem(hWnd, IDC_CHECK8);
	HWND check9 = GetDlgItem(hWnd, IDC_CHECK9);
	HWND check3 = GetDlgItem(hWnd, IDC_CHECK3);
	HWND check4 = GetDlgItem(hWnd, IDC_CHECK4);
	HWND check5 = GetDlgItem(hWnd, IDC_CHECK5);

	ShowWindow(gropu1, Mode ? SW_HIDE : SW_SHOW);
	ShowWindow(group2, Mode ? SW_HIDE : SW_SHOW);
	ShowWindow(text1, Mode ? SW_HIDE : SW_SHOW);
	ShowWindow(text2, Mode ? SW_HIDE : SW_SHOW);
	ShowWindow(edit1, Mode ? SW_HIDE : SW_SHOW);
	ShowWindow(edit2, Mode ? SW_HIDE : SW_SHOW);
	ShowWindow(tree1, Mode ? SW_HIDE : SW_SHOW);
	ShowWindow(tree2, Mode ? SW_HIDE : SW_SHOW);
	ShowWindow(check7, Mode ? SW_HIDE : SW_SHOW);
	ShowWindow(check8, Mode ? SW_HIDE : SW_SHOW);
	ShowWindow(check9, Mode ? SW_HIDE : SW_SHOW);
	ShowWindow(check3, Mode ? SW_HIDE : SW_SHOW);
	ShowWindow(check4, Mode ? SW_HIDE : SW_SHOW);
	ShowWindow(check5, Mode ? SW_HIDE : SW_SHOW);

	return 0;
}