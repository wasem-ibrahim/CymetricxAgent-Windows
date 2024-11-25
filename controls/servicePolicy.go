package controls

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

func checkServiceStartup(serviceName string) (string, error) {
	keyPath := fmt.Sprintf(`SYSTEM\CurrentControlSet\Services\%s`, serviceName)
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return "", fmt.Errorf("could not open registry key: %v", err)
	}
	defer key.Close()

	value, _, err := key.GetIntegerValue("Start")
	if err != nil {
		return "", fmt.Errorf("could not get registry value: %v", err)
	}

	return translateStartupType(value), nil
}

func translateStartupType(value uint64) string {
	switch value {
	case 2:
		return "Automatic"
	case 3:
		return "Manual"
	case 4:
		return "Disabled"
	default:
		return "Unknown"
	}
}

func mainspo() {
	serviceName := "AppReadiness"
	value, err := checkServiceStartup(serviceName)
	if err != nil {
		fmt.Println("Error:", err)
	} else {
		fmt.Printf("Service %s startup type: %s\n", serviceName, value)
	}
}

func GetServicePolicy(obj map[string]string, variables map[string]string) (map[string]string, error) {
	valueType := obj["value_type"]
	valueData := obj["value_data"]
	serviceName := obj["service_name"]

	// if is_substring key is present, then retrieve it
	var svcOption string
	if val, ok := obj["svc_option"]; ok {
		svcOption = val
	}

	value, err := checkServiceStartup(serviceName)
	if err != nil {
		return nil, fmt.Errorf("error getting service startup type: %w", err)
	}

	var result bool
	var status string

	if valueType == "SERVICE_SET" {
		if svcOption == "CAN_NOT_BE_NULL" && value == "Unknown" {
			result = false
		} else {
			result = value == valueData
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
		"Resulting Data":   valueData,
		"Audit Output": value,
		"status":       status,
		"Service Name": serviceName,
		"Service Option":   svcOption,
	}

	return resultMap, nil
}
