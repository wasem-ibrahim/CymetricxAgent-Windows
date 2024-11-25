package controls

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// openRegistryKey opens the registry key based on the full path
func openRegistryKey2(fullPath string) (registry.Key, error) {
	var rootKey registry.Key
	var subPath string

	// Determine the root key and the subpath
	switch {
	case strings.HasPrefix(fullPath, "HKLM\\") || strings.HasPrefix(fullPath, "HKEY_LOCAL_MACHINE\\"):
		rootKey = registry.LOCAL_MACHINE
		subPath = strings.TrimPrefix(strings.TrimPrefix(fullPath, "HKLM\\"), "HKEY_LOCAL_MACHINE\\")
	case strings.HasPrefix(fullPath, "HKCU\\") || strings.HasPrefix(fullPath, "HKEY_CURRENT_USER\\"):
		rootKey = registry.CURRENT_USER
		subPath = strings.TrimPrefix(strings.TrimPrefix(fullPath, "HKCU\\"), "HKEY_CURRENT_USER\\")
	case strings.HasPrefix(fullPath, "HKCR\\") || strings.HasPrefix(fullPath, "HKEY_CLASSES_ROOT\\"):
		rootKey = registry.CLASSES_ROOT
		subPath = strings.TrimPrefix(strings.TrimPrefix(fullPath, "HKCR\\"), "HKEY_CLASSES_ROOT\\")
	case strings.HasPrefix(fullPath, "HKU\\") || strings.HasPrefix(fullPath, "HKEY_USERS\\"):
		rootKey = registry.USERS
		subPath = strings.TrimPrefix(strings.TrimPrefix(fullPath, "HKU\\"), "HKEY_USERS\\")
	case strings.HasPrefix(fullPath, "HKCC\\") || strings.HasPrefix(fullPath, "HKEY_CURRENT_CONFIG\\"):
		rootKey = registry.CURRENT_CONFIG
		subPath = strings.TrimPrefix(strings.TrimPrefix(fullPath, "HKCC\\"), "HKEY_CURRENT_CONFIG\\")
	default:
		return 0, fmt.Errorf("unsupported registry root abbreviation")
	}

	return registry.OpenKey(rootKey, subPath, registry.QUERY_VALUE)
}

// getRegistryValue retrieves the value of a specified registry item and returns it as a string
func getRegistryValue(registryPath, itemName string) (string, bool, error) {
	key, err := openRegistryKey2(registryPath)
	if err != nil {
		return "", false, fmt.Errorf("could not open registry key %s: %v", registryPath, err)
	}
	defer key.Close()

	if itemName == "" {
		value, _, err := key.GetStringValue("")
		if err == registry.ErrNotExist {
			// Default value exists but is not set
			return "(value not set)", true, nil
		} else if err != nil {
			return "", false, fmt.Errorf("could not get default value: %v", err)
		}
		return value, true, nil
	}

	// Try to get the value as a string
	value, _, err := key.GetStringValue(itemName)
	if err == nil {
		return value, true, nil
	}

	// Try to get the value as a uint32 (DWORD)
	dwordValue, _, err := key.GetIntegerValue(itemName)
	if err == nil {
		return fmt.Sprintf("%d", dwordValue), true, nil
	}

	// Try to get the value as binary
	binaryValue, _, err := key.GetBinaryValue(itemName)
	if err == nil {
		// Check if it's a QWORD
		if len(binaryValue) == 8 {
			qwordValue := binary.LittleEndian.Uint64(binaryValue)
			return fmt.Sprintf("%d", qwordValue), true, nil
		}
		return hex.EncodeToString(binaryValue), true, nil
	}

	// Try to get the value as a multi-string
	multiStringValue, _, err := key.GetStringsValue(itemName)
	if err == nil {
		return strings.Join(multiStringValue, ", "), true, nil
	}

	return "", false, fmt.Errorf("could not get value for item %s: %v", itemName, err)
}

func mainrgs() {
	registryPath := "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
	itemName := "ProgramFilesDir"

	value, _, err := getRegistryValue(registryPath, itemName)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("The value of %s in %s is: %s\n", itemName, registryPath, value)
	}
}

// matchPattern checks if a given string `sid` matches a specified pattern.
// The pattern can include wildcard characters '*' which represent any sequence of characters.
//
// The pattern matching works as follows:
// - If the `sid` ends with "_Class", the function immediately returns false.
// - If the pattern is a single "*", the function returns true for any input string.
// - The pattern is split by "*" and the function checks if:
//  1. The first part of the pattern (before the first "*") matches the start of the `sid` string.
//  2. The last part of the pattern (after the last "*") matches the end of the `sid` string.
//  3. All other parts of the pattern are present in the `sid` string, in order.
//
// Example:
//
//	matchPattern("abc123def", "abc*def")       // returns true
//	matchPattern("abc123def", "abc*xyz")       // returns false
//	matchPattern("abc123def", "*123*")         // returns true
//	matchPattern("abc123def", "*456*")         // returns false
//	matchPattern("abc123def", "*")             // returns true
//	matchPattern("example_Classes", "example*")  // returns false
func matchPattern(sid, pattern string) bool {
	if strings.HasSuffix(sid, "_Classes") {
		return false
	}

	if pattern == "*" {
		return true
	}

	parts := strings.Split(pattern, "*")
	for i, part := range parts {
		if i == 0 && !strings.HasPrefix(sid, part) {
			return false
		}

		if i == len(parts)-1 && !strings.HasSuffix(sid, part) {
			return false
		}

		if !strings.Contains(sid, part) {
			return false
		}
	}
	return true
}

func GetRegistrySetting(obj map[string]string, variables map[string]string) (map[string]string, error) {
	valueType := obj["value_type"]
	valueData := obj["value_data"]
	regKey := obj["reg_key"]
	regItem := obj["reg_item"]
	var regOption string
	var checkType string

	if _, ok := obj["reg_option"]; ok {
		regOption = obj["reg_option"]
	}

	if _, ok := obj["check_type"]; ok {
		checkType = obj["check_type"]
	}

	// Handle optional reg_include_hku_users and reg_ignore_hku_users
	var includeUsers, ignoreUsers []string
	if include, ok := obj["reg_include_hku_users"]; ok {
		includeUsers = strings.Split(include, ",")
	}
	if ignore, ok := obj["reg_ignore_hku_users"]; ok {
		ignoreUsers = strings.Split(ignore, ",")
	}

	resultMap := map[string]string{
		"type":                           obj["type"],
		"control_key":                    obj["control_key"],
		"Resulting Data":                 valueData,
		"Audit Output":                   "",
		"status":                         "false",
		"Registry Path":                  regKey,
		"Registry Item":                  regItem,
		"Registry Condition":             regOption,
		"Control Audit Type":             checkType,
		"Include User Registry Settings": strings.Join(includeUsers, ","),
		"Ignore User Registry Settings":  strings.Join(ignoreUsers, ","),
		"Entry Type":                     valueType,
		"Info":                           "",
	}

	// Check if it is a variable and return it if so.
	if value, found := getValueFromVariables(valueData, variables); found {
		valueData = value
		resultMap["Resulting Data"] = valueData
	} else {
		return resultMap, fmt.Errorf("variable %s not found", valueData)
	}

	// Iterate over user profiles if necessary
	if strings.HasPrefix(regKey, "HKU\\") {
		keys, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			return resultMap, fmt.Errorf("could not enumerate HKU subkeys: %v", err)
		}
		defer keys.Close()

		subKeys, err := keys.ReadSubKeyNames(-1)
		if err != nil {
			return resultMap, fmt.Errorf("could not read HKU subkeys: %v", err)
		}

		for _, subKey := range subKeys {
			// Check if the user profile should be included or ignored
			include := len(includeUsers) == 0
			for _, includePattern := range includeUsers {
				if matchPattern(subKey, includePattern) {
					include = true
					break
				}
			}
			for _, ignorePattern := range ignoreUsers {
				if matchPattern(subKey, ignorePattern) {
					include = false
					break
				}
			}
			if !include {
				continue
			}

			// Get the registry value for the user profile
			fullPath := strings.Replace(regKey, "HKU\\", "HKU\\"+subKey+"\\", 1)
			localPolicyValue, _, err := getRegistryValue(fullPath, regItem)
			if err != nil {
				if regOption == "MUST_EXIST" {
					resultMap["status"] = "false"
					return resultMap, fmt.Errorf("error getting registry value for key %s %s because of error: %w", fullPath, regItem, err)
				} else if regOption == "MUST_NOT_EXIST" {
					// If the value does not exist, and it must not exist, we can continue
					// to the next user profile
					continue
				} else if regOption == "CAN_BE_NULL" && strings.Contains(err.Error(), "The system cannot find the file specified.") {
					// If the regOption is set to "CAN_BE_NULL" and the registry key or path does not exist, then the control has passed for this path
					// `The system cannot find the file specified.` is returned only when `OpenKey`` function can't find the key
					continue
				}
				resultMap["status"] = "false"
				return resultMap, fmt.Errorf("error getting registry value for key %s %s because of error: %w", fullPath, regItem, err)
			}

			if localPolicyValue == "" && regOption == "CAN_BE_NULL" {
				continue
			} else if localPolicyValue == "" && regOption == "CAN_NOT_BE_NULL" {
				resultMap["status"] = "false"
				return resultMap, fmt.Errorf("registry value for key %s %s is empty when it must not be null", fullPath, regItem)
			}

			// resultMap["returned_value"] = localPolicyValue
			// localPolicyValues = append(localPolicyValues, localPolicyValue)
			// Apped the user profile and its local policy value to the result map key "returned_value"
			// for _, value := range localPolicyValues {
			resultMap["Audit Output"] += subKey + ": " + localPolicyValue + ", "
			// }

			var result bool
			var status string

			if valueType == "POLICY_DWORD" {
				policyMin, policyMax, logicalValues := handleDwordOrRangeValue(valueData)
				var err error
				result, err = compareValues(policyMin, policyMax, localPolicyValue, logicalValues)
				if err != nil {
					resultMap["status"] = "false"
					return resultMap, fmt.Errorf("error comparing values for local policy value %s against input %s: %w", localPolicyValue, valueData, err)
				}
			} else if valueType == "POLICY_SET" {
				result = valueData == localPolicyValue
			} else if valueType == "POLICY_TEXT" {
				result, err = checkTypeValidationValues(checkType, valueData, localPolicyValue)
				if err != nil {
					resultMap["status"] = "false"
					return resultMap, fmt.Errorf("error comparing values for local policy value %s against input %s: %w", localPolicyValue, valueData, err)
				}
			}

			if result {
				status = "true"
			} else {
				status = "false"
			}

			resultMap["status"] = status
			// break // Assuming we break on first match, remove this if you need to check all
		}
	} else {
		// Non-HKU registry key
		// Only one value is returned
		localPolicyValue, _, err := getRegistryValue(regKey, regItem)
		if err != nil {
			if regOption == "MUST_EXIST" {
				resultMap["status"] = "false"
				resultMap["Info"] = "The registry key or path does not exist while the regOption is set to MUST_EXIST, so the control has failed for this path"
				return resultMap, nil
			} else if regOption == "MUST_NOT_EXIST" {
				resultMap["status"] = "true"
				resultMap["Info"] = "The registry key or path does not exist while the regOption is set to MUST_NOT_EXIST, so the control has passed for this path"
				return resultMap, nil
			} else if regOption == "CAN_BE_NULL" && strings.Contains(err.Error(), "The system cannot find the file specified.") {
				// If the regOption is set to "CAN_BE_NULL" and the registry key or path does not exist, then the control has passed for this path
				// `The system cannot find the file specified.` is returned only when `OpenKey`` function can't find the key
				resultMap["status"] = "true"
				resultMap["Info"] = "The registry key or path does not exist while the regOption is set to CAN_BE_NULL, so the control has passed for this path"
				return resultMap, nil
			}
			return resultMap, fmt.Errorf("error getting registry value for key %s %s because of error: %w", regKey, regItem, err)
		}

		if localPolicyValue == "" && regOption == "CAN_BE_NULL" {
			resultMap["status"] = "true"
			return resultMap, nil
		} else if localPolicyValue == "" && regOption == "CAN_NOT_BE_NULL" {
			return resultMap, fmt.Errorf("registry value for key %s %s is empty when it must not be null", regKey, regItem)
		}

		resultMap["Audit Output"] = localPolicyValue
		var result bool
		var status string

		if valueType == "POLICY_DWORD" {
			policyMin, policyMax, logicalValues := handleDwordOrRangeValue(valueData)
			var err error
			result, err = compareValues(policyMin, policyMax, localPolicyValue, logicalValues)
			if err != nil {
				return resultMap, fmt.Errorf("error comparing values for input %s: %w", valueData, err)
			}
		} else if valueType == "POLICY_SET" {
			result = valueData == localPolicyValue
		} else if valueType == "POLICY_TEXT" {
			result, err = checkTypeValidationValues(checkType, valueData, localPolicyValue)
			if err != nil {
				return resultMap, fmt.Errorf("error comparing values for input %s: %w", valueData, err)
			}
		} else if valueType == "POLICY_MULTI_TEXT" {
			// Split the value data into a slice
			valueDataSlice := strings.Split(valueData, " && ")
			localPolicyValueSlice := strings.Split(localPolicyValue, ",")
			// clean up the local policy value slice
			for i, v := range localPolicyValueSlice {
				localPolicyValueSlice[i] = strings.TrimSpace(v)
			}

			// Check if the local policy value slice is a subset of the value data slice
			var missingKeys []string
			result, missingKeys = isSubset(localPolicyValueSlice, valueDataSlice)
			resultMap["Missing Keys"] = strings.Join(missingKeys, ", ")

			// fmt.Println("localPolicyValueSlice: ", localPolicyValueSlice)
			// fmt.Println("valueDataSlice: ", valueDataSlice)
		}

		if result {
			status = "true"
		} else {
			status = "false"
		}

		resultMap["status"] = status
	}

	return resultMap, nil
}

// isSubset checks if slice a is a subset of slice b
// ex: isSubset(["a", "b"], ["a", "b", "c"]) => true
// ex: isSubset(["a", "b"], ["a", "c", "d"]) => false
func isSubset(a, b []string) (bool, []string) {
	m := make(map[string]bool)
	for _, item := range b {
		m[item] = true
	}

	var missingKeys []string
	for _, item := range a {
		if !m[item] {
			missingKeys = append(missingKeys, item)
		}
	}
	return len(missingKeys) == 0, missingKeys
}
