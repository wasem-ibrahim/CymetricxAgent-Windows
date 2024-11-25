package controls

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Get the GUID from the guid_reg_key by checking all value names for a match containing regItem
func getGuidFromRegistry(guidRegKey, regItem string) (string, error) {
	key, err := openRegistryKey2(guidRegKey)
	if err != nil {
		return "", fmt.Errorf("could not open registry key %s: %v", guidRegKey, err)
	}
	defer key.Close()

	// Enumerate all value names in the registry key
	valueNames, err := key.ReadValueNames(-1)
	if err != nil {
		return "", fmt.Errorf("could not read value names for key %s: %v", guidRegKey, err)
	}

	// Check each value name to see if it contains the regItem
	for _, valueName := range valueNames {
		if strings.Contains(valueName, regItem) {
			// Retrieve the value associated with the matched value name
			guid, _, err := key.GetStringValue(valueName)
			if err == nil {
				return guid, nil
			}
		}
	}

	return "", fmt.Errorf("no matching value name containing %s found in key %s", regItem, guidRegKey)
}

func GetGuidRegistrySetting(obj map[string]string, variables map[string]string) (map[string]string, error) {
	valueType := obj["value_type"]
	valueData := obj["value_data"]
	regKey := obj["reg_key"]
	regItem := obj["reg_item"]
	guidRegKey := obj["guid_reg_key"]
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
		"guid_reg_key":                   guidRegKey,
		"Registry Condition":             regOption,
		"Control Audit Type":             checkType,
		"Include User Registry Settings": strings.Join(includeUsers, ","),
		"Ignore User Registry Settings":  strings.Join(ignoreUsers, ","),
	}

	// Check if it is a variable and return it if so.
	if value, found := getValueFromVariables(valueData, variables); found {
		valueData = value
		resultMap["Resulting Data"] = valueData
	} else {
		return resultMap, fmt.Errorf("variable %s not found", valueData)
	}

	// Get the GUID from the guid_reg_key
	// guid, _, err := getRegistryValue(guidRegKey, regItem)
	// if err != nil {
	// 	return resultMap, fmt.Errorf("error getting GUID from key %s: %v", guidRegKey, err)
	// }

	// Use the modified function to get the GUID
	// Since the item might have some other characters in the name, we need to check if the item is contained in the value name
	guid, err := getGuidFromRegistry(guidRegKey, regItem)
	if err != nil {
		return resultMap, fmt.Errorf("error getting GUID from key %s: %v", guidRegKey, err)
	}

	// Replace the {GUID} placeholder in regKey with the actual GUID
	regKey = strings.Replace(regKey, "{GUID}", guid, -1)

	// Iterate over user profiles if necessary
	if len(includeUsers) > 0 || len(ignoreUsers) > 0 {
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

			// Replace {USER_SID} placeholder in regKey with the actual user SID
			fullPath := strings.Replace(regKey, "{USER_SID}", subKey, -1)
			// localPolicyValue, _, err := getRegistryValue(fullPath, regItem)
			localPolicyValue, _, err := getRegistryValue(fullPath, "")
			if err != nil {
				if regOption == "MUST_EXIST" {
					resultMap["status"] = "false"
					// The regItem shouldn't exist, but im
					// return resultMap, fmt.Errorf("error getting registry value for key %s %s because of error: %w", fullPath, regItem, err)
					return resultMap, fmt.Errorf("error getting registry value for key %s because of error: %w", fullPath, err)
				} else if regOption == "MUST_NOT_EXIST" {
					continue
				}
				resultMap["status"] = "false"
				// return resultMap, fmt.Errorf("error getting registry value for key %s %s because of error: %w", fullPath, regItem, err)
				return resultMap, fmt.Errorf("error getting registry value for key %s because of error: %w", fullPath, err)
			}

			if localPolicyValue == "" && regOption == "CAN_BE_NULL" {
				continue
			} else if localPolicyValue == "" && regOption == "CAN_NOT_BE_NULL" {
				resultMap["status"] = "false"
				// return resultMap, fmt.Errorf("registry value for key %s %s is empty when it must not be null", fullPath, regItem)
				return resultMap, fmt.Errorf("registry value for key %s is empty when it must not be null", fullPath)
			}

			resultMap["Audit Output"] += subKey + ": " + localPolicyValue + ", "

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
		}
	} else {
		// Non-HKU registry key
		// localPolicyValue, _, err := getRegistryValue(regKey, regItem)
		localPolicyValue, _, err := getRegistryValue(regKey, "")
		if err != nil {
			if regOption == "MUST_EXIST" {
				resultMap["status"] = "false"
				return resultMap, nil
			} else if regOption == "MUST_NOT_EXIST" {
				resultMap["status"] = "true"
				return resultMap, nil
			}
			// return resultMap, fmt.Errorf("error getting registry value for key %s %s because of error: %w", regKey, regItem, err)
			return resultMap, fmt.Errorf("error getting registry value for key %s because of error: %w", regKey, err)
		}

		if localPolicyValue == "" && regOption == "CAN_BE_NULL" {
			resultMap["status"] = "true"
			return resultMap, nil
		} else if localPolicyValue == "" && regOption == "CAN_NOT_BE_NULL" {
			// return resultMap, fmt.Errorf("registry value for key %s %s is empty when it must not be null", regKey, regItem)
			return resultMap, fmt.Errorf("registry value for key %s is empty when it must not be null", regKey)
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
