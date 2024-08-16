# Remote Process Injection Script

This script demonstrates how to perform a basic remote process injection using the Windows API. It creates a new process, allocates memory in the target process, writes shellcode to that memory, changes the memory protection, and executes the shellcode by creating a remote thread.

## Dependencies

- Python 3.x
- `ctypes` library (part of the standard library)

## Functionality

1. **Open Process**: Opens a target process for manipulation.
2. **Allocate Memory**: Allocates memory in the target process.
3. **Write Memory**: Writes shellcode to the allocated memory.
4. **Change Memory Protection**: Changes the protection of the memory to execute.
5. **Create Remote Thread**: Creates a thread in the target process to execute the shellcode.

## How It Works

- **Process Creation**: The script creates a suspended Notepad process using `CreateProcessA`.
- **Memory Allocation**: It allocates memory in the target process using `VirtualAllocEx`.
- **Memory Writing**: Writes a predefined shellcode to the allocated memory.
- **Memory Protection**: Changes the protection state of the memory to `PAGE_EXECUTE_READ`.
- **Thread Creation**: Creates a remote thread that begins execution of the shellcode in the target process.


## Script Details

- **OpenProcess**: Opens the target process.
- **VirtualAllocEx**: Allocates memory in the target process.
- **WriteProcessMemory**: Writes data to the allocated memory.
- **VirtualProtectEx**: Changes the protection of the memory.
- **CreateRemoteThread**: Creates a remote thread to execute the shellcode.

### Usage

Simply run the script as a Python script:

```bash
python script.py
