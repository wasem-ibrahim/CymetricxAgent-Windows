package controls

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// getAuditPolicyValueForKey now returns an error as well
func getAuditPolicyValueForKey(key string) (string, bool, error) {
	cmd := exec.Command("cmd", "/C", "auditpol /get /category:*")
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", false, fmt.Errorf("failed to execute command: %w", err)
	}

	keys := []string{
		"Security State Change",
		"Security System Extension",
		"System Integrity",
		"IPsec Driver",
		"Other System Events",
		"Logon",
		"Logoff",
		"Account Lockout",
		"IPsec Main Mode",
		"IPsec Quick Mode",
		"IPsec Extended Mode",
		"Special Logon",
		"Other Logon/Logoff Events",
		"Network Policy Server",
		"File System",
		"Registry",
		"Kernel Object",
		"SAM",
		"Certification Services",
		"Application Generated",
		"Handle Manipulation",
		"File Share",
		"Filtering Platform Packet Drop",
		"Filtering Platform Connection",
		"Other Object Access Events",
		"Sensitive Privilege Use",
		"Non Sensitive Privilege Use",
		"Other Privilege Use Events",
		"Process Creation",
		"Process Termination",
		"DPAPI Activity",
		"RPC Events",
		"Audit Policy Change",
		"Authentication Policy Change",
		"Authorization Policy Change",
		"MPSSVC Rule-Level Policy Change",
		"Filtering Platform Policy Change",
		"Other Policy Change Events",
		"User Account Management",
		"Computer Account Management",
		"Security Group Management",
		"Distribution Group Management",
		"Application Group Management",
		"Other Account Management Events",
		"Directory Service Access",
		"Directory Service Changes",
		"Directory Service Replication",
		"Detailed Directory Service Replication",
		"Credential Validation",
		"Kerberos Service Ticket Operations",
		"Other Account Logon Events",
		"Removable Storage",
		"Detailed File Share",
		"Group Membership",
		"Plug and Play Events",
		"Central Policy Staging",
		"Kerberos Authentication Service",
		"Token Right Adjusted Events",
	}

	auditPolicies, err := parseAuditPolicies(out.String(), keys)
	if err != nil {
		return "", false, err
	}

	value, found := getPolicyValue(auditPolicies, key)
	if !found {
		return "", false, errors.New("key not found")
	}
	return value, found, nil
}

func Mainaps() {
	key := "Credential Validation"
	value, found, err := getAuditPolicyValueForKey(key)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	if found {
		fmt.Printf("Policy for '%s': %s\n", key, value)
	} else {
		fmt.Printf("Policy for '%s' not found.\n", key)
	}
}

// parseAuditPolicies now returns an error as well
func parseAuditPolicies(output string, keys []string) (map[string]string, error) {
	lines := strings.Split(output, "\n")
	auditPolicies := make(map[string]string)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		for _, key := range keys {
			if strings.HasPrefix(line, key) {
				parts := strings.Split(line, key)
				if len(parts) < 2 {
					continue
				}
				auditPolicies[key] = strings.TrimSpace(parts[1])
				break
			}
		}
	}

	return auditPolicies, nil
}

// getPolicyValue remains unchanged as it does not generate errors
func getPolicyValue(auditPolicies map[string]string, key string) (string, bool) {
	value, found := auditPolicies[key]
	return value, found
}

func GetAuditPolicySubcategory(obj map[string]string, variables map[string]string) (map[string]string, error) {
	valueType := obj["value_type"]
	valueData := obj["value_data"]
	auditPolicySubcategory := obj["audit_policy_subcategory"]

	resultMap := map[string]string{
		"type":                     obj["type"],
		"control_key":              obj["control_key"],
		"Resulting Data":           valueData,
		"Audit Output":             "",
		"status":                   "false",
		"Audit Policy Subcategory": auditPolicySubcategory,
	}

	// Check if it is a variable and return it if so.
	if value, found := getValueFromVariables(valueData, variables); found {
		valueData = value
		resultMap["Resulting Data"] = valueData
	} else {
		return resultMap, fmt.Errorf("variable %s not found", valueData)
	}

	returned_value, _, err := getAuditPolicyValueForKey(auditPolicySubcategory)
	if err != nil {
		return resultMap, fmt.Errorf("error getting audit policy value for key '%s': %w", auditPolicySubcategory, err)
	}
	// Repalce " and " with ", " in returned_value to match the format of valueData
	returned_value = strings.ReplaceAll(returned_value, " and ", ", ")
	resultMap["Audit Output"] = returned_value

	var result bool
	var status string

	var valueDataList []string

	// Split on "||" and then trim the spaces
	if strings.Contains(valueData, "||") {
		parts := strings.Split(valueData, "||")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			valueDataList = append(valueDataList, part)
		}
	} else {
		valueDataList = append(valueDataList, valueData)
	}

	if valueType == "AUDIT_SET" {
		// result = valueData == returned_value
		for _, value := range valueDataList {
			if value == returned_value {
				result = true
				break
			}
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
