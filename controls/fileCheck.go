package controls

import (
	"fmt"
	"os"
	"strings"
)

// fileExists checks if a file exists at the given path
func expandEnvironmentVariables(path string) string {
	for _, env := range os.Environ() {
		pair := strings.SplitN(env, "=", 2)
		if len(pair) == 2 {
			path = strings.ReplaceAll(path, "%"+pair[0]+"%", pair[1])
		}
	}
	return path
}

func fileExists(filePath string) bool {
	expandedPath := expandEnvironmentVariables(filePath)

	_, err := os.Stat(expandedPath)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil
}

func Mainfc() {
	paths := []string{
		`%SystemRoot%\win.ini`,
		`%SystemDrive%\Windows\System32\drivers\etc\hosts`,
		`%ProgramFiles%\Internet Explorer\iexplore.exe`,
		`%USERPROFILE%\Desktop`,
		`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`,
		`%LOCALAPPDATA%\Temp`,
	}

	for _, path := range paths {
		exists := fileExists(path)
		fmt.Printf("File %s exists: %v\n", path, exists)
	}
}

// Handler functions for different types
func GetFileCheck(obj map[string]string, variables map[string]string) (map[string]string, error) {
	valueType := obj["value_type"]
	valueData := obj["value_data"]
	fileOption := obj["file_option"]

	// Constructing the result map
	resultMap := map[string]string{
		"type":            obj["type"],
		"control_key":     obj["control_key"],
		"Resulting Data":  valueData,
		"File Properties": fileOption,
		"status":          "false",
	}

	// Check if it is a variable and return it if so.
	if value, found := getValueFromVariables(valueData, variables); found {
		valueData = value
		resultMap["Resulting Data"] = valueData
	} else {
		return resultMap, fmt.Errorf("variable %s not found", valueData)
	}

	var result bool
	var status string

	if valueType == "POLICY_TEXT" {
		if fileOption == "MUST_EXIST" {
			result = fileExists(valueData)
		} else if fileOption == "MUST_NOT_EXIST" {
			result = !fileExists(valueData)
		} else {
			return nil, fmt.Errorf("Invalid file option: %s", fileOption)
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
