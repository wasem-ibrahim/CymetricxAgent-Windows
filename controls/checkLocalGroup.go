package controls

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// LOCALGROUP_INFO_0 represents the structure for local group information
type LOCALGROUP_INFO_0 struct {
	Lgrpi0Name *uint16
}

// NetLocalGroupEnum function signature
var (
	modNetapi32_4          = syscall.NewLazyDLL("netapi32.dll")
	procNetLocalGroupEnum  = modNetapi32_4.NewProc("NetLocalGroupEnum")
	procNetApiBufferFree_4 = modNetapi32_4.NewProc("NetApiBufferFree")
)

// NetLocalGroupEnum retrieves all local groups
func NetLocalGroupEnum(servername *uint16, level uint32, bufptr *uintptr, prefmaxlen uint32, entriesread *uint32, totalentries *uint32, resumehandle *uint32) (neterr error) {
	r0, _, _ := procNetLocalGroupEnum.Call(
		uintptr(unsafe.Pointer(servername)),
		uintptr(level),
		uintptr(unsafe.Pointer(bufptr)),
		uintptr(prefmaxlen),
		uintptr(unsafe.Pointer(entriesread)),
		uintptr(unsafe.Pointer(totalentries)),
		uintptr(unsafe.Pointer(resumehandle)),
		0,
		0,
	)
	if r0 != 0 {
		neterr = syscall.Errno(r0)
	}
	return
}

// NetApiBufferFree function signature
func NetApiBufferFree_4(buffer uintptr) (neterr error) {
	r0, _, _ := procNetApiBufferFree_4.Call(buffer)
	if r0 != 0 {
		neterr = syscall.Errno(r0)
	}
	return
}

// UTF16PtrToString converts a UTF16 pointer to a Go string
func UTF16PtrToString(ptr *uint16) string {
	return windows.UTF16PtrToString(ptr)
}

const MAX_PREFERRED_LENGTH2 = 0xFFFFFFFF

func Mainclg() {
	var (
		servername   *uint16
		level        uint32 = 0
		bufptr       uintptr
		prefmaxlen   uint32 = MAX_PREFERRED_LENGTH2
		entriesread  uint32
		totalentries uint32
		resumehandle uint32
	)

	err := NetLocalGroupEnum(servername, level, &bufptr, prefmaxlen, &entriesread, &totalentries, &resumehandle)
	if err != nil {
		fmt.Printf("NetLocalGroupEnum failed: %v\n", err)
		return
	}
	defer NetApiBufferFree_4(bufptr)

	// Convert the buffer to a slice of LOCALGROUP_INFO_0 structures
	groups := (*[1 << 20]LOCALGROUP_INFO_0)(unsafe.Pointer(bufptr))[:entriesread:entriesread]

	// Define the groups to check
	requiredGroups := map[string]bool{
		"Guests":         false,
		"Users":          false,
		"Administrators": false,
		// Add more groups as needed
	}

	// Check the presence of each required group
	for _, group := range groups {
		groupName := UTF16PtrToString(group.Lgrpi0Name)
		if _, exists := requiredGroups[groupName]; exists {
			requiredGroups[groupName] = true
		}
	}

	// Print the status of each required group
	for group, present := range requiredGroups {
		status := "enabled"
		if !present {
			status = "disabled"
		}
		fmt.Printf("Group: %s, Status: %s\n", group, status)
	}
}
