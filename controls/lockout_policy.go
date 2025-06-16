package controls

import (
	"fmt"
	"strconv"
	"syscall"
	"unsafe"
)

// USER_MODALS_INFO_3 structure as per Windows API
type USER_MODALS_INFO_3 struct {
	LockoutDuration          uint32 // LOCKOUT_DURATION
	LockoutObservationWindow uint32 // LOCKOUT_RESET
	LockoutThreshold         uint32 // LOCKOUT_THRESHOLD
}

var (
	modNetapi32          = syscall.NewLazyDLL("Netapi32.dll")
	procNetUserModalsGet = modNetapi32.NewProc("NetUserModalsGet")
	procNetApiBufferFree = modNetapi32.NewProc("NetApiBufferFree")
)

const (
	USER_MODALS_INFO_3_LEVEL = 3
)

func getLockoutPolicies() (map[string]string, error) {
	var level uint32 = USER_MODALS_INFO_3_LEVEL
	var buf unsafe.Pointer

	// Call NetUserModalsGet
	ret, _, err := procNetUserModalsGet.Call(
		uintptr(0), // NULL, local computer
		uintptr(level),
		uintptr(unsafe.Pointer(&buf)),
	)

	if ret != 0 {
		return nil, fmt.Errorf("NetUserModalsGet failed with error: %v", err)
	}

	defer procNetApiBufferFree.Call(uintptr(buf))

	// Convert the result to USER_MODALS_INFO_3
	info := (*USER_MODALS_INFO_3)(buf)

	// Handle default or unset values
	// lockoutDuration := "Not Applicable"
	// if info.LockoutDuration != 1800 {
	lockoutDuration := strconv.Itoa(int(info.LockoutDuration / 60))
	// }

	// lockoutObservationWindow := "Not Applicable"
	// if info.LockoutObservationWindow != 1800 {
	lockoutObservationWindow := strconv.Itoa(int(info.LockoutObservationWindow / 60))
	// }

	lockoutThresholdString := strconv.Itoa(int(info.LockoutThreshold))

	// turn the struct into a map of string to string:
	returnedMap := map[string]string{
		"LOCKOUT_DURATION":  lockoutDuration,
		"LOCKOUT_THRESHOLD": lockoutThresholdString,
		"LOCKOUT_RESET":     lockoutObservationWindow,
	}

	return returnedMap, nil
}

func Mainlo() {
	info, err := getLockoutPolicies()
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(info)
}

// Handler functions for different types
func GetLockoutPolicy(obj map[string]string, variables map[string]string) (map[string]string, error) {
	valueType := obj["value_type"]
	valueData := obj["value_data"]
	lockoutPolicy := obj["lockout_policy"]

	// Constructing the result map
	resultMap := map[string]string{
		"type":           obj["type"],
		"control_key":    obj["control_key"],
		"Resulting Data": valueData,
		"Audit Output":   "",
		"status":         "false",
	}

	// Check if it is a variable and return it if so.
	if value, found := getValueFromVariables(valueData, variables); found {
		valueData = value
		resultMap["Resulting Data"] = valueData
	} else {
		return resultMap, fmt.Errorf("variable %s not found", valueData)
	}

	policies, err := getLockoutPolicies()
	if err != nil {
		return resultMap, fmt.Errorf("error getting lockout policies: %w", err)
	}
	resultMap["Audit Output"] = policies[lockoutPolicy]

	var result bool
	var status string

	if valueType == "POLICY_DWORD" || valueType == "TIME_MINUTE" {
		policyMin, policyMax, logicalValues := handleDwordOrRangeValue(valueData)
		result, err = compareValues(policyMin, policyMax, policies[lockoutPolicy], logicalValues)
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
