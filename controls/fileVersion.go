package controls

import (
	"fmt"
	"regexp"
	"syscall"
	"unsafe"
)

func getFileVersion(filePath string) (string, error) {
	// Expand environment variables
	expandedPath := expandEnvironmentVariables(filePath)

	// Load the DLL containing the required functions
	versionDLL := syscall.NewLazyDLL("version.dll")
	getFileVersionInfoSize := versionDLL.NewProc("GetFileVersionInfoSizeW")
	getFileVersionInfo := versionDLL.NewProc("GetFileVersionInfoW")
	verQueryValue := versionDLL.NewProc("VerQueryValueW")

	// Convert the file path to UTF-16
	pathPtr, err := syscall.UTF16PtrFromString(expandedPath)
	if err != nil {
		return "", err
	}

	// Get the size of the version info
	size, _, err := getFileVersionInfoSize.Call(uintptr(unsafe.Pointer(pathPtr)), uintptr(0))
	if size == 0 {
		return "", fmt.Errorf("failed to get version info size: %v", err)
	}

	// Allocate a buffer for the version info
	buffer := make([]byte, size)

	// Get the version info
	ret, _, err := getFileVersionInfo.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		uintptr(0),
		uintptr(size),
		uintptr(unsafe.Pointer(&buffer[0])),
	)
	if ret == 0 {
		return "", fmt.Errorf("failed to get version info: %v", err)
	}

	// Query the version value
	var block *uintptr
	var length uint
	ret, _, err = verQueryValue.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(`\StringFileInfo\040904B0\FileVersion`))),
		uintptr(unsafe.Pointer(&block)),
		uintptr(unsafe.Pointer(&length)),
	)
	if ret == 0 {
		return "", fmt.Errorf("failed to query version value: %v", err)
	}

	// Convert the version value to a Go string
	version := syscall.UTF16ToString((*[1 << 20]uint16)(unsafe.Pointer(block))[:length])

	// Extract the version number using a regular expression
	re := regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+`)
	match := re.FindString(version)
	if match == "" {
		return "", fmt.Errorf("failed to extract version number")
	}

	return match, nil
}

func mainfvv() {
	filePath := `%SystemRoot%\System32\calc.exe`
	exists := fileExists(filePath)
	if !exists {
		fmt.Printf("File %s does not exist\n", filePath)
		return
	}

	version, err := getFileVersion(filePath)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	fmt.Printf("File version of %s: %s\n", filePath, version)
}

// Handler functions for different types
func GetFileVersion(obj map[string]string, variables map[string]string) (map[string]string, error) {
	valueType := obj["value_type"]
	valueData := obj["value_data"]
	file := obj["file"]
	checkType := obj["check_type"]
	// fileOption := obj["file_option"] // there is not file option here in the examples

	// Check if it is a variable and return it if so.
	if value, found := getValueFromVariables(valueData, variables); found {
		valueData = value
	} else {
		return nil, fmt.Errorf("variable %s not found", valueData)
	}

	var result bool
	var status string
	var version string

	if valueType == "POLICY_FILE_VERSION" {
		exists := fileExists(file)
		if !exists {
			return nil, fmt.Errorf("File %s does not exist", file)
		}

		var err error
		version, err = getFileVersion(file)
		if err != nil {
			return nil, fmt.Errorf("Error: %v", err)
		}

		if checkType == "CHECK_LESS_THAN" {
			result = version < valueData
		} else if checkType == "CHECK_GREATER_THAN" {
			result = version > valueData
		} else if checkType == "CHECK_GREATER_THAN_OR_EQUAL" {
			result = version >= valueData
		} else if checkType == "CHECK_LESS_THAN_OR_EQUAL" {
			result = version <= valueData
		} else if checkType == "CHECK_EQUAL" {
			result = version == valueData
		} else {
			return nil, fmt.Errorf("Invalid check type: %s", checkType)
		}

	}

	if result {
		status = "true"
	} else {
		status = "false"
	}

	// Constructing the result map
	resultMap := map[string]string{
		"type":         obj["type"],
		"control_key":  obj["control_key"],
		"Resulting Data":   fmt.Sprintf("%v", valueData),
		"File":         file,
		"status":       status,
		"Returned Output": fmt.Sprintf("%v", version),
	}

	return resultMap, nil
}
