package controls

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	UF_ACCOUNTDISABLE = 0x00000002
	NERR_Success      = 0
)

type USER_INFO_1 struct {
	Usri1_name         *uint16
	Usri1_password     *uint16
	Usri1_password_age uint32
	Usri1_priv         uint32
	Usri1_home_dir     *uint16
	Usri1_comment      *uint16
	Usri1_flags        uint32
	Usri1_script_path  *uint16
}

func getAccountStatus(flags uint32) string {
	if flags&UF_ACCOUNTDISABLE != 0 {
		return "Disabled"
	}
	return "Enabled"
}

func getRenamedAccountName(oldName string) (string, error) {
	var sidSize uint32
	var domainSize uint32
	var sidUse uint32
	sidBuffer := make([]byte, 256)
	domainBuffer := make([]uint16, 256)

	// Convert oldName to UTF16
	oldNameUTF16, err := syscall.UTF16PtrFromString(oldName)
	if err != nil {
		return oldName, fmt.Errorf("UTF16PtrFromString for %s failed: %v", oldName, err)
	}

	// Lookup SID size
	err = windows.LookupAccountName(nil, oldNameUTF16, (*windows.SID)(unsafe.Pointer(&sidBuffer[0])), &sidSize, &domainBuffer[0], &domainSize, &sidUse)
	if err != nil {
		if err == syscall.ERROR_INSUFFICIENT_BUFFER {
			sidBuffer = make([]byte, sidSize)
			domainBuffer = make([]uint16, domainSize)
			err = windows.LookupAccountName(nil, oldNameUTF16, (*windows.SID)(unsafe.Pointer(&sidBuffer[0])), &sidSize, &domainBuffer[0], &domainSize, &sidUse)
			if err != nil {
				return oldName, fmt.Errorf("LookupAccountName for %s failed: %v", oldName, err)
			}
		} else {
			return oldName, fmt.Errorf("LookupAccountName for %s failed: %v", oldName, err)
		}
	}

	var newNameSize uint32 = 256
	newName := make([]uint16, newNameSize)
	domainSize = 256 // Reset domainSize to the size of the buffer
	err = windows.LookupAccountSid(nil, (*windows.SID)(unsafe.Pointer(&sidBuffer[0])), &newName[0], &newNameSize, &domainBuffer[0], &domainSize, &sidUse)
	if err != nil {
		if err == syscall.ERROR_INSUFFICIENT_BUFFER {
			domainBuffer = make([]uint16, domainSize)
			err = windows.LookupAccountSid(nil, (*windows.SID)(unsafe.Pointer(&sidBuffer[0])), &newName[0], &newNameSize, &domainBuffer[0], &domainSize, &sidUse)
			if err != nil {
				return oldName, fmt.Errorf("LookupAccountSid for %s failed: %v", oldName, err)
			}
		} else {
			return oldName, fmt.Errorf("LookupAccountSid for %s failed: %v", oldName, err)
		}
	}

	return syscall.UTF16ToString(newName), nil
}

func checkAccountStatus() (map[string]string, error) {
	results := make(map[string]string)

	// Check Administrator account status
	var adminInfo *USER_INFO_1
	nStatus, err := netUserGetInfo(nil, syscall.StringToUTF16Ptr("Administrator"), 1, (*byte)(unsafe.Pointer(&adminInfo)))
	if nStatus != NERR_Success {
		return nil, fmt.Errorf("NetUserGetInfo for Administrator failed: %d", nStatus)
	}
	results["Administrator account status"] = getAccountStatus(adminInfo.Usri1_flags)
	windows.NetApiBufferFree((*byte)(unsafe.Pointer(adminInfo)))

	// Check Guest account status
	var guestInfo *USER_INFO_1
	nStatus, err = netUserGetInfo(nil, syscall.StringToUTF16Ptr("Guest"), 1, (*byte)(unsafe.Pointer(&guestInfo)))
	if nStatus != NERR_Success {
		return nil, fmt.Errorf("NetUserGetInfo for Guest failed: %d", nStatus)
	}
	results["Guest account status"] = getAccountStatus(guestInfo.Usri1_flags)
	windows.NetApiBufferFree((*byte)(unsafe.Pointer(guestInfo)))

	// Check renamed accounts
	renamedAdmin, err := getRenamedAccountName("Administrator")
	if err != nil {
		return nil, err
	}
	results["Rename administrator account"] = renamedAdmin

	renamedGuest, err := getRenamedAccountName("Guest")
	if err != nil {
		return nil, err
	}
	results["Rename guest account"] = renamedGuest

	return results, nil
}

func netUserGetInfo(serverName *uint16, userName *uint16, level uint32, bufptr *byte) (netApiStatus uint32, err error) {
	r0, _, e1 := syscall.Syscall6(procNetUserGetInfo.Addr(), 4, uintptr(unsafe.Pointer(serverName)), uintptr(unsafe.Pointer(userName)), uintptr(level), uintptr(unsafe.Pointer(bufptr)), 0, 0)
	netApiStatus = uint32(r0)
	if netApiStatus != 0 {
		err = e1
	}
	return
}

var (
	modNetapi32_2      = windows.NewLazySystemDLL("netapi32.dll")
	procNetUserGetInfo = modNetapi32_2.NewProc("NetUserGetInfo")
)

func Mainca() {
	results, err := checkAccountStatus()
	if err != nil {
		fmt.Printf("Error checking account status: %v\n", err)
		return
	}

	for key, value := range results {
		fmt.Printf("%s: %s\n", key, value)
	}
}

func GetCheckAccount(obj map[string]string, variables map[string]string) (map[string]string, error) {

	valueType := obj["value_type"]
	valueData := obj["value_data"]
	accountType := obj["account_type"]

	var checkType string
	if _, ok := obj["check_type"]; ok {
		checkType = obj["check_type"]
	}

	resultMap := map[string]string{
		"type":               obj["type"],
		"control_key":        obj["control_key"],
		"Resulting Data":     valueData,
		"Audit Output":       "",
		"status":             "false",
		"Control Audit Type": checkType,
	}

	// Check if it is a variable and return it if so.
	if value, found := getValueFromVariables(valueData, variables); found {
		valueData = value
		resultMap["Resulting Data"] = valueData
	} else {
		return resultMap, fmt.Errorf("variable %s not found", valueData)
	}

	policies, err := checkAccountStatus()
	if err != nil {
		return resultMap, fmt.Errorf("error getting lockout policy: %w", err)
	}

	eventMapping := map[string]map[string]string{
		"POLICY_SET": {
			"ADMINISTRATOR_ACCOUNT": policies["Administrator account status"],
			"GUEST_ACCOUNT":         policies["Guest account status"],
		},
		"POLICY_TEXT": {
			"ADMINISTRATOR_ACCOUNT": policies["Rename administrator account"],
			"GUEST_ACCOUNT":         policies["Rename guest account"],
		},
	}
	resultMap["Audit Output"] = eventMapping[valueType][accountType]

	var result bool
	var status string

	if valueType == "POLICY_SET" {
		result = valueData == eventMapping[valueType][accountType]
	} else if valueType == "POLICY_TEXT" {

		result, err = checkTypeValidationValues(checkType, valueData, eventMapping[valueType][accountType])
		if err != nil {
			return resultMap, fmt.Errorf("error comparing values for input %s: %w", valueData, err)
		}

	}

	if result {
		status = "true"
	} else {
		status = "false"
	}

	resultMap["status"] = status

	return resultMap, nil
}
