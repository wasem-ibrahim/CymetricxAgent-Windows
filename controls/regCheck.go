package controls

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// openRegistryKey opens the registry key based on the full path
func openRegistryKey(fullPath string) (registry.Key, error) {
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

// KeyOrItemExists checks if a registry key or a key item exists at the given path
func KeyOrItemExists(registryPath, keyItem string) bool {
	key, err := openRegistryKey(registryPath)
	if err != nil {
		if err == registry.ErrNotExist {
			return false
		}
		return false
	}
	defer key.Close()

	if keyItem == "" {
		// If key item is not provided, check if the key exists
		return true
	}

	// If key item is provided, check if the value exists in the key
	_, _, err = key.GetValue(keyItem, nil)
	if err != nil {
		if err == registry.ErrNotExist {
			return false
		}
		return false
	}

	return true
}

func Mainrc() {
	registryChecks := []struct {
		Path string
		Item string
	}{
		{"HKLM\\SOFTWARE\\Adobe\\Acrobat Reader\\7.0\\AdobeViewer", "EULA"},
		{"HKLM\\SOFTWARE\\Adobe\\Acrobat Reader\\7.0\\AdobeViewer", ""},
		{"HKLM\\SOFTWARE\\NonExistentKey", ""},
		{"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer", ""},
		{"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer", "StartPage"},
		{"HKEY_CLASSES_ROOT\\.txt", ""},
	}

	for _, check := range registryChecks {
		if KeyOrItemExists(check.Path, check.Item) {
			if check.Item != "" {
				fmt.Printf("Registry key %s and item %s exist.\n", check.Path, check.Item)
			} else {
				fmt.Printf("Registry key %s exists.\n", check.Path)
			}
		} else {
			if check.Item != "" {
				fmt.Printf("Registry key %s or item %s does not exist.\n", check.Path, check.Item)
			} else {
				fmt.Printf("Registry key %s does not exist.\n", check.Path)
			}
		}
	}
}

// Handler functions for different types
func GetRegCheck(obj map[string]string, variables map[string]string) (map[string]string, error) {
	valueType := obj["value_type"]
	valueData := obj["value_data"] // Registry key
	regOption := obj["reg_option"]

	var keyItem string
	if field, ok := obj["key_item"]; ok {
		keyItem = field
	}

	resultMap := map[string]string{
		"type":               obj["type"],
		"control_key":        obj["control_key"],
		"Resulting Data":     valueData,
		"status":             "false",
		"Registry Condition": regOption,
		"Registry Key":       keyItem, // might be empty
		"Returned Result":    "",
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
		keyOrValueExists := KeyOrItemExists(valueData, keyItem)
		if !keyOrValueExists && regOption == "MUST_EXIST" {
			return resultMap, fmt.Errorf("registry key %s does not exist", valueData)
		}

		if !keyOrValueExists && regOption == "MUST_NOT_EXIST" {
			resultMap["status"] = "true"
			return resultMap, nil
		}

		if !keyOrValueExists {
			return resultMap, fmt.Errorf("registry key %s does not exist", valueData)
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
