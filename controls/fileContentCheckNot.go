package controls

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
)

// the 2nd boolean is to tell us to return the error or not to the caller. if not return, then we
// return the map to the caller with no error
func fileContentCheckNot(filePath, presenceRegex, expectRegex string) (bool, bool, error) {

	expandedPath := expandEnvironmentVariables(filePath)

	file, err := os.Open(expandedPath)
	if err != nil {
		return false, false, err
	}
	defer file.Close()

	// Compile the regular expressions
	presenceRe, err := regexp.Compile(presenceRegex)
	if err != nil {
		return false, false, fmt.Errorf("invalid presence regex: %w", err)
	}

	expectRe, err := regexp.Compile(expectRegex)
	if err != nil {
		return false, false, fmt.Errorf("invalid expect regex: %w", err)
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if presenceRe.MatchString(line) {
			// If the presence regex matches, check the expect regex
			if expectRe.MatchString(line) {
				return true, true, nil
			}
			return false, true, fmt.Errorf("line matches presence regex but does not match expect regex")
		}
	}

	if err := scanner.Err(); err != nil {
		return false, true, err
	}

	return false, true, fmt.Errorf("presence regex not found in file")
}

// Handler functions for different types
func GetFileContentCheckNot(obj map[string]string, variables map[string]string) (map[string]string, error) {
	valueType := obj["value_type"]
	valueData := obj["value_data"]
	regex := obj["regex"]
	expectedRegex := obj["expect"]

	var fileOption string
	if field, ok := obj["file_option"]; ok {
		fileOption = field
	}

	resultMap := map[string]string{
		"type":               obj["type"],
		"control_key":        obj["control_key"],
		"Resulting Data":     valueData,
		"status":             "false",
		"Regular Expression": regex,
		"Audit Check":        expectedRegex,
		"File Properties":    fileOption,
	}

	// fileOption := obj["file_option"] // there is not file option here in the examples

	// Check if it is a variable and return it if so.
	if value, found := getValueFromVariables(valueData, variables); found {
		valueData = value
		resultMap["Resulting Data"] = valueData
	} else {
		return nil, fmt.Errorf("variable %s not found", valueData)
	}

	var result bool
	var status string

	if valueType == "POLICY_TEXT" {
		exists := fileExists(valueData)
		if !exists && fileOption == "CAN_BE_NULL" {
			resultMap["status"] = "true"
			return resultMap, nil
		}
		if !exists {
			return resultMap, fmt.Errorf("file %s does not exist", valueData)
		}

		var err error
		result, err = fileContentCheck(valueData, regex, expectedRegex)
		if err != nil {
			return resultMap, fmt.Errorf("error checking file content: %w", err)
		}
	}

	if !result {
		status = "true"
	} else {
		status = "false"
	}

	resultMap["status"] = status
	return resultMap, nil
}
