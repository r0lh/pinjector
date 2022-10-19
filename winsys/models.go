package pinjector

import "syscall"

type Inject struct {
	Pid              uint32
	DllPath          string
	DLLSize          uint32
	DLLBytes         uintptr
	Privilege        string
	RemoteProcHandle uintptr
	Lpaddr           uintptr
	LoadLibAddr      uintptr
	RThread          uintptr
	Token            TOKEN
}

type TOKEN struct {
	tokenhandle syscall.Token
}
