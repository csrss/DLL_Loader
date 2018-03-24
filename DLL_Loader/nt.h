typedef  LONG NTSTATUS;
typedef  LONG KPRIORITY;
#define  NtCurrentProcess()		           ((HANDLE) -1)
#define  STATUS_SUCCESS                    ((NTSTATUS)0x00000000L)
#define  STATUS_INFO_LENGTH_MISMATCH       ((NTSTATUS)0xC0000004L)
#define  OBJ_CASE_INSENSITIVE			   0x00000040L
#define  NtGetProcessHeap()		           (Nt_CurrentTeb()->PebBaseAddress->DefaultHeap)
#if (_WIN32_WINNT >= 0x0400)
#define EXIT_STACK_SIZE 0x188
#else
#define EXIT_STACK_SIZE 0x190
#endif
#define  NT_SUCCESS(Status)					((NTSTATUS)(Status) >= 0)
#define FILE_SUPERSEDE						0x00000000
#define FILE_OPEN							0x00000001
#define FILE_CREATE							0x00000002
#define FILE_OPEN_IF						0x00000003
#define FILE_OVERWRITE						0x00000004
#define FILE_OVERWRITE_IF					0x00000005
#define FILE_MAXIMUM_DISPOSITION			0x00000005
#define FILE_NON_DIRECTORY_FILE				0x00000040
#define	FILE_SEQUENTIAL_ONLY				0x00000004
#define FILE_SYNCHRONOUS_IO_NONALERT		0x00000020
#define PAGE_SIZE 4096
#define NTABSOLUTE(wait) (wait)
#define NTRELATIVE(wait) (-(wait))
#define NANOSECONDS(nanos)(((signed __int64)(nanos)) / 100L)
#define MICROSECONDS(micros)(((signed __int64)(micros)) * NANOSECONDS(1000L))
#define MILLISECONDS(milli)(((signed __int64)(milli)) * MICROSECONDS(1000L))
#define SECONDS(seconds)(((signed __int64)(seconds)) * MILLISECONDS(1000L))

typedef struct _CLIENT_ID{
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
    PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;

typedef enum _KTHREAD_STATE {
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated, 
    Waiting,
    Transition,
    DeferredReady,
} THREAD_STATE, *PTHREAD_STATE;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }
    
typedef enum
{
  Executive,
  FreePage,
  PageIn,
  PoolAllocation,
  DelayExecution,
  Suspended,
  UserRequest,
  WrExecutive,
  WrFreePage,
  WrPageIn,
  WrPoolAllocation,
  WrDelayExecution,
  WrSuspended,
  WrUserRequest,
  WrEventPair,
  WrQueue,
  WrLpcReceive,
  WrLpcReply,
  WrVirtualMemory,
  WrPageOut,
  WrRendezvous,
  Spare2,
  Spare3,
  Spare4,
  Spare5,
  Spare6,
  WrKernel,
  MaximumWaitReason
} KWAIT_REASON;

typedef struct _SYSTEM_THREADS
{
	LARGE_INTEGER KernelTime;       
	LARGE_INTEGER UserTime;            
	LARGE_INTEGER CreateTime;       
	ULONG         WaitTime;         
	PVOID         StartAddress;      
	CLIENT_ID     ClientId;             
	KPRIORITY     Priority;        
	KPRIORITY     BasePriority;     
	ULONG         ContextSwitchCount;    
	THREAD_STATE  State;            
	KWAIT_REASON  WaitReason;    
}SYSTEM_THREADS,*PSYSTEM_THREADS;

typedef struct _VM_COUNTERS
{
	ULONG PeakVirtualSize;              
	ULONG VirtualSize;               
	ULONG PageFaultCount;            
	ULONG PeakWorkingSetSize;            
	ULONG WorkingSetSize;             
	ULONG QuotaPeakPagedPoolUsage;     
	ULONG QuotaPagedPoolUsage;          
	ULONG QuotaPeakNonPagedPoolUsage;    
	ULONG QuotaNonPagedPoolUsage;      
	ULONG PagefileUsage;           
	ULONG PeakPagefileUsage;  
}VM_COUNTERS,*PVM_COUNTERS;

typedef struct _SYSTEM_PROCESSES {
	ULONG  NextEntryDelta;
	ULONG  ThreadCount;
	ULONG  Reserved1[6];
	LARGE_INTEGER  CreateTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  KernelTime;
	UNICODE_STRING  ProcessName;
	KPRIORITY  BasePriority;
	HANDLE  ProcessId;
	HANDLE  InheritedFromProcessId;
	ULONG  HandleCount;
	ULONG  Reserved2[2];
	VM_COUNTERS  VmCounters;
	IO_COUNTERS  IoCounters;
	SYSTEM_THREADS  Threads[1];
} SYSTEM_PROCESSES, *PSYSTEM_PROCESSES;

typedef struct {
	ULONG    	Length;
	ULONG    	Unknown[11];
} RTL_HEAP_DEFINITION, *PRTL_HEAP_DEFINITION;

typedef NTSTATUS(NTAPI * PRTL_HEAP_COMMIT_ROUTINE)(IN PVOID Base,
		IN OUT PVOID *CommitAddress,IN OUT PSIZE_T CommitSize);
		
typedef struct _RTL_HEAP_PARAMETERS {
    ULONG Length;
    SIZE_T SegmentReserve;
    SIZE_T SegmentCommit;
    SIZE_T DeCommitFreeBlockThreshold;
    SIZE_T DeCommitTotalFreeThreshold;
    SIZE_T MaximumAllocationSize;
    SIZE_T VirtualMemoryThreshold;
    SIZE_T InitialCommit;
    SIZE_T InitialReserve;
    PRTL_HEAP_COMMIT_ROUTINE CommitRoutine;
    SIZE_T Reserved[ 2 ];
} RTL_HEAP_PARAMETERS, *PRTL_HEAP_PARAMETERS;

typedef enum _SYSTEM_INFORMATION_CLASS {

SystemBasicInformation, 
SystemProcessorInformation, 
SystemPerformanceInformation, 
SystemTimeOfDayInformation, 
SystemPathInformation, 
SystemProcessInformation, 
SystemCallCountInformation, 
SystemDeviceInformation, 
SystemProcessorPerformanceInformation, 
SystemFlagsInformation, 
SystemCallTimeInformation, 
//SystemModuleInformation, 
SystemLocksInformation, 
SystemStackTraceInformation, 
SystemPagedPoolInformation, 
SystemNonPagedPoolInformation, 
SystemHandleInformation, 
SystemObjectInformation, 
SystemPageFileInformation, 
SystemVdmInstemulInformation, 
SystemVdmBopInformation, 
SystemFileCacheInformation, 
SystemPoolTagInformation, 
SystemInterruptInformation, 
SystemDpcBehaviorInformation, 
SystemFullMemoryInformation, 
SystemLoadGdiDriverInformation, 
SystemUnloadGdiDriverInformation, 
SystemTimeAdjustmentInformation, 
SystemSummaryMemoryInformation, 
SystemNextEventIdInformation, 
SystemEventIdsInformation, 
SystemCrashDumpInformation, 
SystemExceptionInformation, 
SystemCrashDumpStateInformation, 
SystemKernelDebuggerInformation, 
SystemContextSwitchInformation, 
SystemRegistryQuotaInformation, 
SystemExtendServiceTableInformation, 
SystemPrioritySeperation, 
SystemPlugPlayBusInformation, 
SystemDockInformation, 
//SystemPowerInformation, 
SystemProcessorSpeedInformation, 
SystemCurrentTimeZoneInformation, 
SystemLookasideInformation

} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef struct _STRING {
    USHORT Length;
    USHORT MaximumLength;
#ifdef MIDL_PASS
    [size_is(MaximumLength), length_is(Length) ]
#endif // MIDL_PASS
    PCHAR Buffer;
} STRING, *PSTRING;

#define	PROCESS_PARAMETERS_NORMALIZED	1	// pointers in are absolute (not self-relative)
typedef struct _CURDIR
{
   UNICODE_STRING	DosPath;
   HANDLE			Handle;
} CURDIR, *PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	WORD	Flags;
	WORD	Length;
	DWORD	TimeStamp;
	STRING	DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _PROCESS_PARAMETERS
{
    ULONG					MaximumLength;
    ULONG					Length;
    ULONG					Flags;				// PROCESS_PARAMETERS_NORMALIZED
    ULONG					DebugFlags;
    HANDLE					ConsoleHandle;
    ULONG					ConsoleFlags;
    HANDLE					StandardInput;
    HANDLE					StandardOutput;
    HANDLE					StandardError;
    CURDIR					CurrentDirectory;
    UNICODE_STRING			DllPath;
    UNICODE_STRING			ImagePathName;
    UNICODE_STRING			CommandLine;
    PWSTR					Environment;
    ULONG					StartingX;
    ULONG					StartingY;
    ULONG					CountX;
    ULONG					CountY;
    ULONG					CountCharsX;
    ULONG					CountCharsY;
    ULONG					FillAttribute;
    ULONG					WindowFlags;
    ULONG					ShowWindowFlags;
    UNICODE_STRING			WindowTitle;
    UNICODE_STRING			Desktop;
    UNICODE_STRING			ShellInfo;
    UNICODE_STRING			RuntimeInfo;
	RTL_DRIVE_LETTER_CURDIR	CurrentDirectores[32];
} PROCESS_PARAMETERS, *PPROCESS_PARAMETERS;

typedef struct _PEB {
	ULONG AllocationSize;
	ULONG Unknown1;
	HANDLE ProcessInstance;
	PVOID DllList;
	PPROCESS_PARAMETERS ProcessParameters;
	ULONG Unknown2;
	HANDLE DefaultHeap;

} PEB, *PPEB;

typedef struct _TEB {
    struct _EXCEPTION_REGISTRATION_RECORD *ExceptionList;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID SubSystemTib;
    ULONG Version;
    PVOID ArbitraryUserPointer;
    struct _TEB *Self;

	ULONG Unknown1;
	CLIENT_ID ClientID;
	ULONG Unknown2;
	ULONG Unknown3;
	PPEB PebBaseAddress;
	ULONG LastError;
	ULONG Unknown[0x23];
	ULONG Locale;
	ULONG ExitStack[EXIT_STACK_SIZE];

} TEB;
typedef TEB *PTEB;

typedef enum {
     AdjustCurrentProcess,
     AdjustCurrentThread
} ADJUST_PRIVILEGE_TYPE; 

typedef struct{
ULONG Length;
ULONG Unknown1;
ULONG Unknown2;
PULONG Unknown3;
ULONG Unknown4;
ULONG Unknown5;
ULONG Unknown6;
PULONG Unknown7;
ULONG Unknown8;
} UNKNOWN;

typedef struct _SECTION_IMAGE_INFORMATION {
  PVOID                   EntryPoint;
  ULONG                   StackZeroBits;
  ULONG                   StackReserved;
  ULONG                   StackCommit;
  ULONG                   ImageSubsystem;
  WORD                    SubSystemVersionLow;
  WORD                    SubSystemVersionHigh;
  ULONG                   Unknown1;
  ULONG                   ImageCharacteristics;
  ULONG                   ImageMachineType;
  ULONG                   Unknown2[3];
} SECTION_IMAGE_INFORMATION, *PSECTION_IMAGE_INFORMATION;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  ULONG                   MaximumLength;
  ULONG                   Length;
  ULONG                   Flags;
  ULONG                   DebugFlags;
  PVOID                   ConsoleHandle;
  ULONG                   ConsoleFlags;
  HANDLE                  StdInputHandle;
  HANDLE                  StdOutputHandle;
  HANDLE                  StdErrorHandle;
  UNICODE_STRING          CurrentDirectoryPath;
  HANDLE                  CurrentDirectoryHandle;
  UNICODE_STRING          DllPath;
  UNICODE_STRING          ImagePathName;
  UNICODE_STRING          CommandLine;
  PVOID                   Environment;
  ULONG                   StartingPositionLeft;
  ULONG                   StartingPositionTop;
  ULONG                   Width;
  ULONG                   Height;
  ULONG                   CharWidth;
  ULONG                   CharHeight;
  ULONG                   ConsoleTextAttributes;
  ULONG                   WindowFlags;
  ULONG                   ShowWindowFlags;
  UNICODE_STRING          WindowTitle;
  UNICODE_STRING          DesktopName;
  UNICODE_STRING          ShellInfo;
  UNICODE_STRING          RuntimeData;
  RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _RTL_USER_PROCESS_INFORMATION {
  ULONG                   Size;
  HANDLE                  ProcessHandle;
  HANDLE                  ThreadHandle;
  CLIENT_ID               ClientId;
  SECTION_IMAGE_INFORMATION ImageInformation;
} RTL_USER_PROCESS_INFORMATION, *PRTL_USER_PROCESS_INFORMATION;

typedef enum _SHUTDOWN_ACTION{
	ShutdownNoReboot,
	ShutdownReboot,
	ShutdownPowerOff
} SHUTDOWN_ACTION, *PSHUTDOWN_ACTION;

#define SEC_IMAGE         0x1000000     

typedef enum _SECTION_INFORMATION_CLASS{
	SectionBasicInformation,
	SectionImageInformation
}SECTION_INFORMATION_CLASS;

typedef struct _INITIAL_TEB
{
    PVOID PreviousStackBase;
    PVOID PreviousStackLimit;
    PVOID StackBase;
    PVOID StackLimit;
    PVOID AllocatedStackBase;
} INITIAL_TEB, *PINITIAL_TEB;

typedef struct _USER_STACK{
	PVOID	FixedStackBase;
	PVOID	FixedStackLimit;
	PVOID	ExpandableStackBase;
	PVOID	ExpandableStackLimit;
	PVOID	ExpandableStackBottom;
}USER_STACK,*PUSER_STACK;

typedef enum _PROCESS_INFORMATION_CLASS {



    ProcessBasicInformation,
    ProcessQuotaLimits,
    ProcessIoCounters,
    ProcessVmCounters,
    ProcessTimes,
    ProcessBasePriority,
    ProcessRaisePriority,
    ProcessDebugPort,
    ProcessExceptionPort,
    ProcessAccessToken,
    ProcessLdtInformation,
    ProcessLdtSize,
    ProcessDefaultHardErrorMode,
    ProcessIoPortHandlers,
    ProcessPooledUsageAndLimits,
    ProcessWorkingSetWatch,
    ProcessUserModeIOPL,
    ProcessEnableAlignmentFaultFixup,
    ProcessPriorityClass,
    ProcessWx86Information,
    ProcessHandleCount,
    ProcessAffinityMask,
    ProcessPriorityBoost,
    MaxProcessInfoClass


} PROCESS_INFORMATION_CLASS, *PPROCESS_INFORMATION_CLASS;


typedef struct _PORT_MESSAGE
{
     ULONG u1;
     ULONG u2;
     union
     {
          CLIENT_ID ClientId;
          float DoNotUseThisField;
     };
     ULONG MessageId;
     union
     {
          ULONG ClientViewSize;
          ULONG CallbackId;
     };
} PORT_MESSAGE, *PPORT_MESSAGE;

struct CSRSS_MESSAGE {
        ULONG Unknown1;
        ULONG Opcode;
        ULONG Status;
        ULONG Unknown2;
};

struct _csrmsg { 
	PORT_MESSAGE			PortMessage; 
	struct CSRSS_MESSAGE	CsrssMessage; 
	PROCESS_INFORMATION		ProcessInformation; 
	CLIENT_ID				Debugger; 
	ULONG					CreationFlags; 
	ULONG					VdmInfo[2]; 
} csrmsg;


PTEB (NTAPI *Nt_CurrentTeb)(VOID);

NTSTATUS (NTAPI *RtlFreeHeap)(PVOID HeapHandle,
							  ULONG Flags,
							  PVOID MemoryPointer);

NTSTATUS (NTAPI *RtlAllocateHeap)(PVOID HeapHandle,
								  ULONG Flags,
								  ULONG Size);

NTSTATUS (NTAPI *NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, 
										   PVOID SystemInformation, 
										   DWORD SystemInformationLength, 
										   PDWORD ReturnLength);

VOID     (WINAPI *NtZeroMemory)(IN VOID UNALIGNED  *Destination,IN SIZE_T  Length );

LONG 	 (__stdcall *RtlAdjustPrivilege)(int,BOOL,BOOL,BOOL *);

NTSTATUS (NTAPI *NtOpenProcess)(PHANDLE ProcessHandle, 
								ACCESS_MASK AccessMask, 
								POBJECT_ATTRIBUTES ObjectAttributes, 
								PCLIENT_ID ClientId );

NTSTATUS (NTAPI *NtAllocateVirtualMemory)(IN HANDLE ProcessHandle, 
										  IN OUT PVOID *BaseAddress,
										  IN ULONG ZeroBits,
										  IN OUT PULONG RegionSize,
										  IN ULONG AllocationType, 
										  IN ULONG Protect);

NTSTATUS (NTAPI *NtWriteVirtualMemory)(IN HANDLE ProcessHandle, 
									   IN PVOID BaseAddress, 
									   IN PVOID Buffer,
									   IN ULONG NumberOfBytesToWrite, 
									   OUT PULONG  NumberOfBytesWritten OPTIONAL);                

NTSTATUS (NTAPI *RtlCreateUserThread)(IN HANDLE ProcessHandle,
									  IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
									  IN BOOLEAN CreateSuspended,
									  IN ULONG StackZeroBits OPTIONAL,
									  IN SIZE_T StackReserve OPTIONAL,
									  IN SIZE_T StackCommit OPTIONAL,
									  IN LPTHREAD_START_ROUTINE StartAddress,
									  IN PVOID Parameter  OPTIONAL,
									  OUT PHANDLE ThreadHandle OPTIONAL,
									  OUT PCLIENT_ID ClientId OPTIONAL );

NTSTATUS (NTAPI *NtClose)(HANDLE ObjectHandle);

LPVOID NTAPI NtVirtualAlloc(IN HANDLE hProcess,IN LPVOID  lpAddress,IN SIZE_T dwSize,	// VirtualAllocEx
		                     IN DWORD  	flAllocationType, IN DWORD  flProtect) {
     NTSTATUS Status;
     Status = NtAllocateVirtualMemory(hProcess,(PVOID *)&lpAddress,0,&dwSize,flAllocationType,flProtect);
     if (!NT_SUCCESS(Status))return NULL;
     return lpAddress;
}

NTSTATUS (NTAPI *NtCreateThreadEx)(	OUT PHANDLE ThreadHandle,
									IN ACCESS_MASK DesiredAccess,
									IN POBJECT_ATTRIBUTES ObjectAttributes,
									IN HANDLE ProcessHandle,
									IN LPTHREAD_START_ROUTINE InitialEip,
									IN LPVOID InitialValueInStack OPTIONAL,
									IN BOOL ThreadState,
									IN DWORD StackZeroBits,
									IN DWORD SizeOfStackCommit OPTIONAL,
									IN DWORD SizeOfStackReserve OPTIONAL,
									LPVOID LOL
									);

NTSTATUS (NTAPI *NtTerminateProcess)(HANDLE ProcessHandle, 
									 NTSTATUS ExitStatus);

NTSTATUS (NTAPI *LdrUnloadDll)(IN HANDLE ModuleHandle);

NTSTATUS (NTAPI *LdrGetDllHandle)( IN PWORD pwPath OPTIONAL, 
								   IN PVOID Unused OPTIONAL, 
                                   IN PUNICODE_STRING ModuleFileName, 
								   OUT PHANDLE pHModule );

NTSTATUS (NTAPI *LdrLoadDll)( IN PWCHAR PathToFile OPTIONAL, 
							  IN ULONG Flags OPTIONAL, 
                              IN PUNICODE_STRING ModuleFileName, 
							  OUT PHANDLE ModuleHandle );

VOID (NTAPI *RtlInitUnicodeString)(PUNICODE_STRING DestinationString,
								   PCWSTR SourceString);

int is_vista_alike = 0;
int compositions = 0;

NTSTATUS (NTAPI *NtDeleteFile)(POBJECT_ATTRIBUTES   ObjectAttributes);

int __stdcall qmb(wchar_t *Caption, wchar_t *Message){
	DWORD mb = (DWORD)GetProcAddress(LoadLibraryW(L"User32.dll"), "MessageBoxW");
	__asm {
		push 0
		push Caption
		push Message
		push 0
		call mb
	}
}

NTSTATUS (NTAPI *NtLoadDriver)( IN PUNICODE_STRING DriverServiceName );

NTSTATUS (NTAPI *NtUnloadDriver)( IN PUNICODE_STRING DriverServiceName );

NTSTATUS (NTAPI *NtQueryDefaultLocale)( IN BOOLEAN  UserProfile, 
									   OUT PLCID DefaultLocaleId);

typedef struct _SYSTEM_LOAD_AND_CALL_IMAGE
{
UNICODE_STRING ModuleName;
} SYSTEM_LOAD_AND_CALL_IMAGE, *PSYSTEM_LOAD_AND_CALL_IMAGE;

#define SystemLoadAndCallImage 38
typedef struct _IO_STATUS_BLOCK
{
     union
     {
          LONG Status;
          PVOID Pointer;
     };
     ULONG Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

NTSTATUS (NTAPI *ZwSetSystemInformation)(DWORD, PVOID, ULONG);

NTSTATUS (NTAPI *NtCreateFile)(OUT PHANDLE             FileHandle,
							   IN ACCESS_MASK          DesiredAccess,
							   IN POBJECT_ATTRIBUTES   ObjectAttributes,
							   OUT PIO_STATUS_BLOCK    IoStatusBlock,
							   IN PLARGE_INTEGER       AllocationSize OPTIONAL,
							   IN ULONG                FileAttributes,
							   IN ULONG                ShareAccess,
							   IN ULONG                CreateDisposition,
							   IN ULONG                CreateOptions,
							   IN PVOID                EaBuffer OPTIONAL,
							   IN ULONG                EaLength);

NTSTATUS (NTAPI *NtOpenKey)(OUT PHANDLE             pKeyHandle,
							IN ACCESS_MASK          DesiredAccess,
							IN POBJECT_ATTRIBUTES   ObjectAttributes );

NTSTATUS (NTAPI *NtCreateKey)(OUT PHANDLE pKeyHandle, 
							  IN ACCESS_MASK DesiredAccess, 
							  IN POBJECT_ATTRIBUTES ObjectAttributes, 
							  IN ULONG TitleIndex, 
							  IN PUNICODE_STRING Class OPTIONAL, 
							  IN ULONG CreateOptions, 
							  OUT PULONG Disposition OPTIONAL ); 

NTSTATUS (NTAPI *NtSetValueKey)(IN HANDLE KeyHandle, 
								IN PUNICODE_STRING ValueName, 
								IN ULONG TitleIndex OPTIONAL, 
								IN ULONG Type, 
								IN PVOID Data, 
								IN ULONG DataSize );

NTSTATUS (NTAPI *NtDeleteKey)( IN HANDLE KeyHandle ); 

NTSTATUS (NTAPI *DbgPrint)(IN LPCSTR Format, ...);

NTSTATUS (NTAPI *NtOpenFile)(OUT PHANDLE             FileHandle,
							 IN ACCESS_MASK          DesiredAccess,
							 IN POBJECT_ATTRIBUTES   ObjectAttributes,
							 OUT PIO_STATUS_BLOCK    IoStatusBlock,
							 IN ULONG                ShareAccess,
							 IN ULONG                OpenOptions );

NTSTATUS (NTAPI *NtCreateMutant)(OUT PHANDLE             MutantHandle,
								 IN ACCESS_MASK          DesiredAccess,
								 IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
								 IN BOOLEAN              InitialOwner );

NTSTATUS (NTAPI *NtOpenMutant)(OUT PHANDLE             MutantHandle,
							   IN ACCESS_MASK          DesiredAccess,
							   IN POBJECT_ATTRIBUTES   ObjectAttributes );

typedef void (*PIO_APC_ROUTINE)	(PVOID				ApcContext,
                                 PIO_STATUS_BLOCK	IoStatusBlock,
                                 ULONG				Reserved);

NTSTATUS (NTAPI *NtReadFile)(IN HANDLE               FileHandle,
							 IN HANDLE               Event OPTIONAL,
							 IN PIO_APC_ROUTINE      ApcRoutine OPTIONAL,
							 IN PVOID                ApcContext OPTIONAL,
							 OUT PIO_STATUS_BLOCK    IoStatusBlock,
							 OUT PVOID               Buffer,
							 IN ULONG                Length,
							 IN PLARGE_INTEGER       ByteOffset OPTIONAL,
							 IN PULONG               Key OPTIONAL);

NTSTATUS (NTAPI *NtCreateProcess)(OUT PHANDLE           ProcessHandle,
								  IN ACCESS_MASK        DesiredAccess,
								  IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
								  IN HANDLE             ParentProcess,
								  IN BOOLEAN            InheritObjectTable,
								  IN HANDLE             SectionHandle OPTIONAL,
								  IN HANDLE             DebugPort OPTIONAL,
								  IN HANDLE             ExceptionPort OPTIONAL);

NTSTATUS (NTAPI *CsrClientCallServer)(PVOID, DWORD, DWORD, DWORD);
BOOL (NTAPI *RtlDosPathNameToNtPathName_U)(LPWSTR,PUNICODE_STRING,DWORD,DWORD);
NTSTATUS (NTAPI *RtlCreateUserProcess)( IN PUNICODE_STRING      ImagePath,
									    IN ULONG                ObjectAttributes,
									    IN OUT PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
									    IN PSECURITY_DESCRIPTOR ProcessSecurityDescriptor OPTIONAL,
										IN PSECURITY_DESCRIPTOR ThreadSecurityDescriptor OPTIONAL,
										IN HANDLE               ParentProcess,
										IN BOOLEAN              InheritHandles,
										IN HANDLE               DebugPort OPTIONAL,
										IN HANDLE               ExceptionPort OPTIONAL,
										OUT PRTL_USER_PROCESS_INFORMATION ProcessInformation );
NTSTATUS (NTAPI *RtlCreateProcessParameters)(
	OUT PRTL_USER_PROCESS_PARAMETERS  *ProcessParameters,
	IN PUNICODE_STRING  ImageFile,
	IN PUNICODE_STRING  DllPath  OPTIONAL,
	IN PUNICODE_STRING  CurrentDirectory  OPTIONAL,
	IN PUNICODE_STRING  CommandLine  OPTIONAL,
	IN PWSTR  Environment OPTIONAL,
	IN PUNICODE_STRING  WindowTitle  OPTIONAL,
	IN PUNICODE_STRING  DesktopInfo  OPTIONAL,
	IN PUNICODE_STRING  ShellInfo  OPTIONAL,
	IN PUNICODE_STRING  RuntimeInfo  OPTIONAL);
NTSTATUS (NTAPI *RtlDestroyProcessParameters)(
  IN PRTL_USER_PROCESS_PARAMETERS  ProcessParameters);

NTSTATUS (NTAPI *NtResumeThread)(
  IN HANDLE               ThreadHandle,
  OUT PULONG              SuspendCount OPTIONAL );

NTSTATUS (NTAPI *NtWaitForSingleObject)(
  IN HANDLE               ObjectHandle,
  IN BOOLEAN              Alertable,
  IN PLARGE_INTEGER       TimeOut OPTIONAL );

int __stdcall Clear(void *Object){
	unsigned int Size_t = sizeof(Object);
	__asm push Size_t;
	__asm push Object;
	__asm call dword ptr NtZeroMemory;
}

NTSTATUS (NTAPI *NtShutdownSystem)(SHUTDOWN_ACTION Action);
NTSTATUS (NTAPI *NtCreateSection)(OUT PHANDLE             SectionHandle,
								  IN ULONG                DesiredAccess,
								  IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
								  IN PLARGE_INTEGER       MaximumSize OPTIONAL,
								  IN ULONG                PageAttributess,
								  IN ULONG                SectionAttributes,
								  IN HANDLE               FileHandle OPTIONAL );
NTSTATUS (NTAPI *NtQuerySection)(IN HANDLE               SectionHandle,
								 IN SECTION_INFORMATION_CLASS InformationClass,
								 OUT PVOID               InformationBuffer,
								 IN ULONG                InformationBufferSize,
								 OUT PULONG              ResultLength OPTIONAL );
NTSTATUS (NTAPI *NtProtectVirtualMemory)(IN HANDLE               ProcessHandle,
										 IN OUT PVOID            *BaseAddress,
										 IN OUT PULONG           NumberOfBytesToProtect,
										 IN ULONG                NewAccessProtection,
										 OUT PULONG              OldAccessProtection );
NTSTATUS (NTAPI *NtCreateThread)(OUT PHANDLE             ThreadHandle,
								 IN ACCESS_MASK          DesiredAccess,
								 IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
								 IN HANDLE               ProcessHandle,
								 OUT PCLIENT_ID          ClientId,
								 IN PCONTEXT             ThreadContext,
								 IN PUSER_STACK         InitialTeb,
								 IN BOOLEAN              CreateSuspended );
NTSTATUS (NTAPI *NtQueryInformationProcess)(IN HANDLE               ProcessHandle,
											IN PROCESS_INFORMATION_CLASS ProcessInformationClass,
											OUT PVOID               ProcessInformation,
											IN ULONG                ProcessInformationLength,
											OUT PULONG              ReturnLength );
NTSTATUS (NTAPI *NtDelayExecution)(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);

NTSTATUS (NTAPI *NtWriteFile)(	IN HANDLE               FileHandle,
								IN HANDLE               Event OPTIONAL,
								IN PIO_APC_ROUTINE      ApcRoutine OPTIONAL,
								IN PVOID                ApcContext OPTIONAL,
								OUT PIO_STATUS_BLOCK    IoStatusBlock,
								IN PVOID                Buffer,
								IN ULONG                Length,
								IN PLARGE_INTEGER       ByteOffset OPTIONAL,
								IN PULONG               Key OPTIONAL );

NTSTATUS (NTAPI *NtDeviceIoControlFile)(IN HANDLE               FileHandle,
										IN HANDLE               Event OPTIONAL,
										IN PIO_APC_ROUTINE      ApcRoutine OPTIONAL,
										IN PVOID                ApcContext OPTIONAL,
										OUT PIO_STATUS_BLOCK    IoStatusBlock,
										IN ULONG                IoControlCode,
										IN PVOID                InputBuffer OPTIONAL,
										IN ULONG                InputBufferLength,
										OUT PVOID               OutputBuffer OPTIONAL,
										IN ULONG                OutputBufferLength);

NTSTATUS (NTAPI *NtSetDebugFilterState)(ULONG ComponentId, ULONG Level, BOOLEAN State);
NTSTATUS (NTAPI *NtTerminateThread)(IN HANDLE ThreadHandle, IN NTSTATUS ExitStatus);

DWORD __stdcall GetAddr(char *Function, wchar_t *Module){
	__asm {
		push Function
		push Module
		call dword ptr LoadLibraryW
		push eax
		call dword ptr GetProcAddress
	}
	/* returns function address stored in eax register */
}

int __stdcall LoadNT(){
	HMODULE hObsolete       = GetModuleHandle(L"ntdll.dll");
	*(FARPROC *)&Nt_CurrentTeb	= GetProcAddress(hObsolete, "NtCurrentTeb");
	*(FARPROC *)&RtlFreeHeap	= GetProcAddress(hObsolete, "RtlFreeHeap");
	*(FARPROC *)&RtlAllocateHeap	= GetProcAddress(hObsolete, "RtlAllocateHeap");
	*(FARPROC *)&NtQuerySystemInformation	= GetProcAddress(hObsolete, "NtQuerySystemInformation");
	*(FARPROC *)&NtZeroMemory	= GetProcAddress(hObsolete, "RtlZeroMemory");
	*(FARPROC *)&RtlAdjustPrivilege	= GetProcAddress(hObsolete, "RtlAdjustPrivilege");
	*(FARPROC *)&NtOpenProcess	= GetProcAddress(hObsolete, "NtOpenProcess");
	*(FARPROC *)&NtAllocateVirtualMemory	= GetProcAddress(hObsolete, "NtAllocateVirtualMemory");
	*(FARPROC *)&NtWriteVirtualMemory	= GetProcAddress(hObsolete, "NtWriteVirtualMemory");
	*(FARPROC *)&RtlCreateUserThread	= GetProcAddress(hObsolete, "RtlCreateUserThread");
	*(FARPROC *)&NtClose	= GetProcAddress(hObsolete, "NtClose");

	if(is_vista_alike == 1)
	*(FARPROC *)&NtCreateThreadEx	= GetProcAddress(hObsolete, "NtCreateThreadEx");

	*(FARPROC *)&NtTerminateProcess	= GetProcAddress(hObsolete, "NtTerminateProcess");
	*(FARPROC *)&LdrUnloadDll	= GetProcAddress(hObsolete, "LdrUnloadDll");
	*(FARPROC *)&LdrGetDllHandle	= GetProcAddress(hObsolete, "LdrGetDllHandle");
	*(FARPROC *)&LdrLoadDll	= GetProcAddress(hObsolete, "LdrLoadDll");
	*(FARPROC *)&RtlInitUnicodeString	= GetProcAddress(hObsolete, "RtlInitUnicodeString");
	*(FARPROC *)&NtDeleteFile	= GetProcAddress(hObsolete, "NtDeleteFile");
	*(FARPROC *)&NtLoadDriver	= GetProcAddress(hObsolete, "NtLoadDriver");
	*(FARPROC *)&NtUnloadDriver	= GetProcAddress(hObsolete, "NtUnloadDriver");
	*(FARPROC *)&NtQueryDefaultLocale	= GetProcAddress(hObsolete, "NtQueryDefaultLocale");
	*(FARPROC *)&ZwSetSystemInformation	= GetProcAddress(hObsolete, "ZwSetSystemInformation");
	*(FARPROC *)&NtCreateFile	= GetProcAddress(hObsolete, "NtCreateFile");
	*(FARPROC *)&NtCreateKey	= GetProcAddress(hObsolete, "NtCreateKey");
	*(FARPROC *)&NtSetValueKey	= GetProcAddress(hObsolete, "NtSetValueKey");
	*(FARPROC *)&NtDeleteKey	= GetProcAddress(hObsolete, "NtDeleteKey");
	*(FARPROC *)&NtOpenFile	= GetProcAddress(hObsolete, "NtOpenFile");
	*(FARPROC *)&NtCreateMutant	= GetProcAddress(hObsolete, "NtCreateMutant");
	*(FARPROC *)&NtOpenMutant	= GetProcAddress(hObsolete, "NtOpenMutant");
	*(FARPROC *)&NtReadFile	= GetProcAddress(hObsolete, "NtReadFile");
	*(FARPROC *)&NtOpenKey	= GetProcAddress(hObsolete, "NtOpenKey");
	*(FARPROC *)&DbgPrint	= GetProcAddress(hObsolete, "DbgPrint");

	*(FARPROC *)&CsrClientCallServer	= GetProcAddress(hObsolete, "CsrClientCallServer");
	*(FARPROC *)&RtlDosPathNameToNtPathName_U	= GetProcAddress(hObsolete, "RtlDosPathNameToNtPathName_U");
	*(FARPROC *)&RtlCreateUserProcess	= GetProcAddress(hObsolete, "RtlCreateUserProcess");
	*(FARPROC *)&RtlCreateProcessParameters	= GetProcAddress(hObsolete, "RtlCreateProcessParameters");
	*(FARPROC *)&NtResumeThread	= GetProcAddress(hObsolete, "NtResumeThread");
	*(FARPROC *)&NtWaitForSingleObject	= GetProcAddress(hObsolete, "NtWaitForSingleObject");
	*(FARPROC *)&NtShutdownSystem	= GetProcAddress(hObsolete, "NtShutdownSystem");
	*(FARPROC *)&NtCreateSection	= GetProcAddress(hObsolete, "NtCreateSection");
	*(FARPROC *)&NtQuerySection	= GetProcAddress(hObsolete, "NtQuerySection");
	*(FARPROC *)&NtProtectVirtualMemory	= GetProcAddress(hObsolete, "NtProtectVirtualMemory");
	*(FARPROC *)&NtCreateThread	= GetProcAddress(hObsolete, "NtCreateThread");
	*(FARPROC *)&NtQueryInformationProcess	= GetProcAddress(hObsolete, "NtQueryInformationProcess");
	*(FARPROC *)&NtDelayExecution	= GetProcAddress(hObsolete, "NtDelayExecution");
	*(FARPROC *)&NtWriteFile	= GetProcAddress(hObsolete, "NtWriteFile");
	*(FARPROC *)&NtDeviceIoControlFile	= GetProcAddress(hObsolete, "NtDeviceIoControlFile");
	*(FARPROC *)&NtSetDebugFilterState	= GetProcAddress(hObsolete, "NtSetDebugFilterState");
	*(FARPROC *)&NtTerminateThread	= GetProcAddress(hObsolete, "NtTerminateThread");

	if(Nt_CurrentTeb && RtlFreeHeap && RtlAllocateHeap && NtQuerySystemInformation &&
		NtZeroMemory && RtlAdjustPrivilege && NtOpenProcess && 
		NtAllocateVirtualMemory && NtWriteVirtualMemory && RtlCreateUserThread &&
		NtClose && NtTerminateProcess && LdrUnloadDll && LdrGetDllHandle &&
		LdrLoadDll && RtlInitUnicodeString && NtDeleteFile && NtLoadDriver &&
		NtUnloadDriver && NtQueryDefaultLocale && ZwSetSystemInformation &&
		NtCreateFile && NtCreateKey && NtSetValueKey && NtDeleteKey && NtOpenFile &&
		NtCreateMutant && NtOpenMutant && NtOpenKey && DbgPrint && CsrClientCallServer &&
		RtlDosPathNameToNtPathName_U && RtlCreateUserProcess && 
		RtlCreateProcessParameters && NtResumeThread && NtWaitForSingleObject &&
		NtShutdownSystem && NtCreateSection && NtQuerySection &&
		NtProtectVirtualMemory && NtCreateThread && NtQueryInformationProcess &&
		NtDelayExecution && NtWriteFile && NtDeviceIoControlFile && 
		NtSetDebugFilterState && NtTerminateThread){
		__asm mov eax, 1;
	} else {
		__asm mov eax, 0;
	}
}

/*
if(NtSetDebugFilterState(0,0,TRUE) == STATUS_SUCCESS) => process debugged
*/

#define ULTIMA_LOADER_DATABASE_FILE		L"uload.db"
#define ULTIMA_LOADER_HOOK_DRIVER		L"uload.sys"
#define ULTIMA_LOADER_HOOK_DEVICE		L"\\DosDevices\\UltimaLoader"

#define IOCTL_DBGPRINT_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x01, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_DBGPRINTEX_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x02, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_VDBGPRINTEX_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x03, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
#define IOCTL_VDBGPRINTEXWITHPREFIX_HOOK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x04, METHOD_BUFFERED, FILE_READ_DATA|FILE_WRITE_DATA)
