#pragma once
#include <Windows.h>
#include <stdio.h>
#include "ntdll.h"
#pragma warning(disable: 4996)
#pragma comment(lib, "ntdll")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

NTSTATUS SelfNtCreateUserProcess(
	wchar_t* path,
	wchar_t* parameter,
	DWORD ppid,
	BOOL blockdll
) {
	
	UNICODE_STRING NtImagePath,CommandLine;
	DWORD listNum = 1;
	// concatenate path and parameter
	wchar_t* prefix = L"\\??\\";
	DWORD len = wcslen(path) + wcslen(parameter) + 2;
	wchar_t* commandline = (wchar_t*)malloc(sizeof(wchar_t) * len);
	
	printf("path:%ws\n", path);
	printf("paramter:%ws\n", parameter);

	wcscpy(commandline, path);
	wcscat(commandline, L" ");
	wcscat(commandline,parameter);
	wprintf(L"command line:%ls\n", commandline);
	RtlInitUnicodeString(&CommandLine, commandline);

	// Path to the image file from which the process will be created
	DWORD pathLen = wcslen(prefix) + wcslen(path) + 1;
	wchar_t* realPath = (wchar_t*)malloc(sizeof(wchar_t) * pathLen);
	wcscpy(realPath, prefix);
	wcscat(realPath, path);
	wprintf(L"realPath:%ls\n", realPath);
	RtlInitUnicodeString(&NtImagePath, (PWSTR)realPath);
	
	// Create the process parameters
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
	RtlCreateProcessParametersEx(
		&ProcessParameters,
		&NtImagePath, 
		NULL, 
		NULL, 
		&CommandLine,
		NULL, 
		NULL, 
		NULL, 
		NULL, 
		NULL, 
		RTL_USER_PROCESS_PARAMETERS_NORMALIZED
	);
	

	// Initialize the PS_CREATE_INFO structure
	PS_CREATE_INFO CreateInfo = { 0 };
	CreateInfo.Size = sizeof(CreateInfo);
	CreateInfo.State = PsCreateInitialState;

	// Initialize the PS_ATTRIBUTE_LIST structure
	if(blockdll)
	{
		listNum += 1;
	}
	if (ppid != 0)
	{
		listNum += 1;
	}
	PPS_ATTRIBUTE_LIST AttributeList = (PS_ATTRIBUTE_LIST*)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, listNum * sizeof(PS_ATTRIBUTE));
	
	DWORD index = 1;
	AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST) - ((3 - listNum) * sizeof(PS_ATTRIBUTE));
	AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	AttributeList->Attributes[0].Size = NtImagePath.Length;
	AttributeList->Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;

	OBJECT_ATTRIBUTES attr;
	InitializeObjectAttributes(&attr, 0, 0, 0, 0);
	CLIENT_ID cid = { (HANDLE)ppid, NULL };
	HANDLE hParent = NULL;
	if (ppid != 0)
	{
		printf("[+]PPID Spoofing\n");
		// obtain handle to parent
		NTSTATUS status = NtOpenProcess(&hParent, PROCESS_ALL_ACCESS, &attr, &cid);
		if (!NT_SUCCESS(status))
		{
			printf("[-]Failed, NtOpenProcess Error:%d\n", GetLastError());
			CloseHandle(hParent);
			exit(1);
		}
		// add parent process attribute
		AttributeList->Attributes[index].Attribute = PS_ATTRIBUTE_PARENT_PROCESS;
		AttributeList->Attributes[index].Size = sizeof(HANDLE);
		AttributeList->Attributes[index].ValuePtr = hParent;
		index++;
	}

	if (blockdll)
	{
		printf("[+]BlockDLL\n");
		// add process mitigation atribute
		AttributeList->Attributes[index].Attribute = PS_ATTRIBUTE_MITIGATION_OPTIONS_2;
		AttributeList->Attributes[index].Size = sizeof(DWORD64);
		AttributeList->Attributes[index].ValuePtr = &policy;
		index++;
	}

	// Create the process
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	// It didn't work
	ProcessParameters->ShowWindowFlags = SW_HIDE;
	NTSTATUS status = NtCreateUserProcess(
		&hProcess,
		&hThread,
		PROCESS_ALL_ACCESS,
		THREAD_ALL_ACCESS,
		NULL,
		NULL,
		NULL,
		NULL,
		ProcessParameters,
		&CreateInfo,
		AttributeList
	);
	

	// Clean up
	RtlFreeHeap(RtlProcessHeap(), 0, AttributeList);
	RtlDestroyProcessParameters(ProcessParameters);
	return status;
}