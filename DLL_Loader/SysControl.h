
#include "DrvData.h"

int __stdcall NtUnpackDriver(HWND hWnd){
	NTSTATUS Status;
	UNICODE_STRING PathNameString;
	HANDLE hFile;
	IO_STATUS_BLOCK    ioStatusBlock;
	OBJECT_ATTRIBUTES ObjectAttributes;
	LARGE_INTEGER   fileSize;
	wchar_t lpPathName[1024] = {0x5c, 0x3f, 0x3f, 0x5c, 0x00};
	wchar_t Current[MAX_PATH];
	NtZeroMemory(Current, sizeof Current);
	DWORD cLen = sizeof(Current);
	GetCurrentDirectoryW(cLen, Current);
	wcscat(lpPathName, Current);
	wcscat(lpPathName, L"\\");
	wcscat(lpPathName, ULTIMA_LOADER_HOOK_DRIVER);
	fileSize.QuadPart = 0;
	RtlInitUnicodeString(&PathNameString, lpPathName);
	InitializeObjectAttributes( &ObjectAttributes, &PathNameString, OBJ_CASE_INSENSITIVE, NULL, NULL );

	int j = VerifyFilePresence(ULTIMA_LOADER_HOOK_DRIVER);
	if(j == 1){
		InsertBufferStatus(hWnd, L"[-] Driver file found! Aborting.\r\n");
//		NtClose(hFile);
		return -1;
	}

	Status = NtCreateFile(	&hFile,
							GENERIC_WRITE | SYNCHRONIZE,
							&ObjectAttributes,
							&ioStatusBlock,
							&fileSize,
							FILE_ATTRIBUTE_NORMAL,
							0,
							FILE_SUPERSEDE,
							FILE_SEQUENTIAL_ONLY|FILE_SYNCHRONOUS_IO_NONALERT,
							NULL,
							0);

	if(Status != STATUS_SUCCESS){
		wchar_t debug[MAX_PATH];
		swprintf(debug, L"[-] NtCreateFile Status: 0x%08x.\r\n", Status);
		InsertBufferStatus(hWnd, debug);
		return -1;
	} else {
		InsertBufferStatus(hWnd, L"[+] Driver file created!\r\n");
	}

	Status = NtWriteFile(hFile,
						 NULL, 
						 NULL, 
						 NULL, 
						 &ioStatusBlock, 
						 DriverData, 
						 sizeof(DriverData), 
						 NULL, 
						 NULL);
	if(Status != STATUS_SUCCESS){
		wchar_t debug[MAX_PATH];
		swprintf(debug, L"[-] NtWriteFile Status: 0x%08x.\r\n", Status);
		InsertBufferStatus(hWnd, debug);
		return -1;
	} else {
		InsertBufferStatus(hWnd, L"[+] Driver deployed!\r\n");
	}

	NtClose(hFile);
	return 0;
}

HANDLE NtOpenDevice(wchar_t *DeviceName, HWND hWnd){
	HANDLE hFile;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK ioStatusBlock;
	UNICODE_STRING PathNameString;
	NTSTATUS Status;
	LARGE_INTEGER   fileSize;
	wchar_t debug[MAX_PATH];
	Clear(debug);
	fileSize.QuadPart = 0;
	RtlInitUnicodeString(&PathNameString, DeviceName);
	InitializeObjectAttributes( &ObjectAttributes, &PathNameString, OBJ_CASE_INSENSITIVE, NULL, NULL );
	Status = NtCreateFile(	&hFile,
							GENERIC_READ | GENERIC_WRITE,
							&ObjectAttributes,
							&ioStatusBlock,
							&fileSize,
							FILE_ATTRIBUTE_NORMAL,
							FILE_SHARE_READ | FILE_SHARE_WRITE,
							0x00000001,		//FILE_OPEN
							0,		//FILE_NON_DIRECTORY_FILE
							NULL,
							0);
	if(Status == STATUS_SUCCESS){
		return hFile;
	} else {
		swprintf(debug, L"[-] NtOpenDevice Status = 0x%08x\r\n", Status);
		InsertBufferStatus(hWnd, debug);
		return NULL;
	}
return NULL;
}

int __stdcall NtControlTranslitDevice(DWORD dwIoControlCode,
									  LPVOID lpInBuffer,
									  DWORD nInBufferSize,
									  HWND hWnd)
{
	IO_STATUS_BLOCK    ioStatusBlock;
	unsigned long BytesReturned = 0;
	NTSTATUS Status;
	HANDLE hDevice = NtOpenDevice(ULTIMA_LOADER_HOOK_DEVICE, hWnd);
	if(hDevice == NULL){
		return -1;
	}
	Status = NtDeviceIoControlFile(hDevice, 
								   NULL,
								   NULL,
								   NULL,
								   &ioStatusBlock,
								   (ULONG)dwIoControlCode,
								   lpInBuffer,
								   (ULONG)nInBufferSize,
								   0,
								   BytesReturned);
	if(Status != STATUS_SUCCESS){
		return -2;
	} 
	NtClose(hDevice);
	return 0;
}
