#include <stdio.h>
#include "NtCreateUserProcess.h"

int main()
{
	NTSTATUS status = SelfNtCreateUserProcess(L"C:\\Windows\\System32\\calc.exe\\npc.exe", L"12345", 0, TRUE);
	if (status != 0) {
		printf("[-]Failed, error:%x", status);
	}
	return 0;
}


