package controls

import (
	"fmt"
	"strings"
)

func GetBannerCheck(obj map[string]string, variables map[string]string) (map[string]string, error) {
	valueType := obj["value_type"]
	valueData := obj["value_data"]
	registryPath := obj["reg_key"]
	regItem := obj["reg_item"]

	// if is_substring key is present, then retrieve it
	var isSubstring string
	if val, ok := obj["is_substring"]; ok {
		isSubstring = val
	}

	// Constructing the result map
	resultMap := map[string]string{
		"type":           obj["type"],
		"control_key":    obj["control_key"],
		"Resulting Data": valueData,
		"Audit Output":   "",
		"status":         "false",
		"Registry Path":  registryPath,
		"Registry Item":  regItem,
	}

	// Check if it is a variable and return it if so.
	if value, found := getValueFromVariables(valueData, variables); found {
		valueData = value
		resultMap["Resulting Data"] = valueData
	} else {
		return resultMap, fmt.Errorf("variable %s not found", valueData)
	}

	value, _, err := getRegistryValue(registryPath, regItem)
	if err != nil {
		return resultMap, fmt.Errorf("error getting registry value: %w", err)
	}
	resultMap["Audit Output"] = value

	var result bool
	var status string

	if valueType == "POLICY_TEXT" {
		if isSubstring == "YES" {
			result = strings.Contains(value, valueData)
		} else {
			result = value == valueData
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
