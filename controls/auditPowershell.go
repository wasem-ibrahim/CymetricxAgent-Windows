package controls

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os/exec"
	"strings"
)

func decodeBase64(encoded string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("error decoding base64: %w", err)
	}
	return string(decoded), nil
}

func GetAuditPowershell(obj map[string]string, variables map[string]string) (map[string]string, error) {
	valueType := obj["value_type"]
	valueData := obj["value_data"]
	checkType := obj["check_type"]
	powershellArgs := obj["powershell_args"]
	powershellPath := getPowerShellPath()

	// check if ps_encoded_args is a key in the variables map
	if val, ok := obj["ps_encoded_args"]; ok {
		// decode base64 encoded powershell_args
		decodedArgs, err := decodeBase64(val)
		if err != nil {
			return nil, fmt.Errorf("error decoding base64: %w", err)
		}
		powershellArgs = decodedArgs
	}

	// Constructing the result map
	resultMap := map[string]string{
		"type":                 obj["type"],
		"control_key":          obj["control_key"],
		"Resulting Data":       valueData,
		"Audit Output":         "",
		"status":               "false",
		"Powershell Arguments": powershellArgs,
		"Control Audit Type":   checkType,
	}

	// Check if it is a variable and return it if so.
	if value, found := getValueFromVariables(valueData, variables); found {
		valueData = value
		resultMap["Resulting Data"] = valueData
	} else {
		return resultMap, fmt.Errorf("variable %s not found", valueData)
	}

	returned_value, err := execCommandWithOutput2(powershellPath, powershellArgs)
	if err != nil {
		return resultMap, err
	}

	returned_value = strings.TrimSpace(returned_value)
	resultMap["Audit Output"] = returned_value

	var result bool
	var status string

	if valueType == "POLICY_TEXT" {
		// if checkType == "CHECK_REGEX" {
		// 	var error error
		// 	result, error = checkRegex(valueData, returned_value)
		// 	if error != nil {
		// 		return nil, fmt.Errorf("error checking regex: %w", error)
		// 	}
		// } else {
		// 	result = valueData == returned_value
		// }

		result, err = checkTypeValidationValues(checkType, valueData, returned_value)
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

// getPowerShellPath finds the path to powershell on the system.
//
// Returns:
//   - string: The path to powershell.
func getPowerShellPath() string {

	// Check if powershell.exe exists in the System32 directory. If it does, use that path. Otherwise, use "powershell"
	// which will use the powershell.exe in the PATH environment variable.
	powerShellFilePath, err := exec.LookPath("powershell")
	if err != nil {
		// Return the default location of powershell.exe
		return "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
	}

	return powerShellFilePath
}

// execCommandWithOutput runs the specified command along with its arguments and
// returns the output as a string. If the command execution fails, it captures
// the standard error output and includes it in the returned error.
func execCommandWithOutput2(command string, args ...string) (string, error) {
	// Create a buffer to store the error output of the command.
	var stderr bytes.Buffer

	// Create a new command with the specified command and args.
	cmd := exec.Command(command, args...)

	// Set the stderr of the command to the stderr buffer.
	// So, if there is an error, it will be stored in the stderr buffer.
	cmd.Stderr = &stderr

	// Execute the command and get the output.
	output, err := cmd.Output()
	if err != nil {
		// Using strings.Join for better formatting of args
		// Format and return the error with the command, arguments, and captured stderr.
		return "", fmt.Errorf("could not execute command: %s, args: %s, Stderr: %s, error: %w", command, strings.Join(args, " "), stderr.String(), err)
	}

	return string(output), nil
}
