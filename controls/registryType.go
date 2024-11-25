package controls

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// openRegistryKey opens the registry key based on the full path
func openRegistryKey3(fullPath string) (registry.Key, error) {
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

// getRegistryValueType retrieves the type of a specified registry item and returns it as a string
func getRegistryValueType(registryPath, itemName string) (string, error) {
	key, err := openRegistryKey3(registryPath)
	if err != nil {
		return "", fmt.Errorf("could not open registry key %s: %v", registryPath, err)
	}
	defer key.Close()

	// Query the value to get its type
	_, valType, err := key.GetValue(itemName, nil)
	if err != nil {
		return "", fmt.Errorf("could not get value for item %s: %v", itemName, err)
	}

	// Map the registry type to a human-readable string
	var typeString string
	switch valType {
	case registry.SZ:
		typeString = "REG_SZ"
	case registry.EXPAND_SZ:
		typeString = "REG_EXPAND_SZ"
	case registry.BINARY:
		typeString = "REG_BINARY"
	case registry.DWORD:
		typeString = "REG_DWORD"
	case registry.DWORD_BIG_ENDIAN:
		typeString = "REG_DWORD_BIG_ENDIAN"
	case registry.LINK:
		typeString = "REG_LINK"
	case registry.MULTI_SZ:
		typeString = "REG_MULTI_SZ"
	case registry.RESOURCE_LIST:
		typeString = "REG_RESOURCE_LIST"
	case registry.FULL_RESOURCE_DESCRIPTOR:
		typeString = "REG_FULL_RESOURCE_DESCRIPTOR"
	case registry.RESOURCE_REQUIREMENTS_LIST:
		typeString = "REG_RESOURCE_REQUIREMENTS_LIST"
	case registry.QWORD:
		typeString = "REG_QWORD"
	default:
		typeString = "UNKNOWN"
	}

	return typeString, nil
}

func mainrt() {
	registryPath := `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`
	itemName := "scremoveoption"

	valueType, err := getRegistryValueType(registryPath, itemName)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	} else {
		fmt.Printf("The type of %s in %s is: %s\n", itemName, registryPath, valueType)
	}
}
