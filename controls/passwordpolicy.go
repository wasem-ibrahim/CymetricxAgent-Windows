package controls

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

type USER_MODALS_INFO_0 struct {
	MinPasswdLen    uint32
	MaxPasswdAge    uint32
	MinPasswdAge    uint32
	ForceLogoff     int32 // -1 disabled. 0 enabled
	PasswordHistLen uint32
}

const (
	NET_API_STATUS_NERR_Success = 0
)

// Function to get user modals info using Netapi32.dll
func getUserModalsInfo() (map[string]string, error) {
	modNetapi32 := windows.NewLazySystemDLL("Netapi32.dll")
	procNetUserModalsGet := modNetapi32.NewProc("NetUserModalsGet")
	procNetApiBufferFree := modNetapi32.NewProc("NetApiBufferFree")

	var serverName *uint16 = nil // Use nil for local computer
	var bufptr uintptr

	ret, _, _ := procNetUserModalsGet.Call(
		uintptr(unsafe.Pointer(serverName)),
		0,
		uintptr(unsafe.Pointer(&bufptr)),
	)
	status := uint32(ret)

	if status != NET_API_STATUS_NERR_Success {
		return nil, fmt.Errorf("NetUserModalsGet failed with status: %d", status)
	}
	defer procNetApiBufferFree.Call(bufptr)

	userModalsInfo := (*USER_MODALS_INFO_0)(unsafe.Pointer(bufptr))

	// Convert MaxPasswdAge and MinPasswdAge from seconds to days for readability
	maxPasswdAgeDays := userModalsInfo.MaxPasswdAge / (24 * 3600)
	minPasswdAgeDays := userModalsInfo.MinPasswdAge / (24 * 3600)

	forceLogoffValue := "Disabled"
	if userModalsInfo.ForceLogoff == 0 {
		forceLogoffValue = "Enabled"
	}

	// Store the user modals info in a map with updated key names
	passwordPolicies := map[string]string{
		"MAXIMUM_PASSWORD_AGE":    strconv.Itoa(int(maxPasswdAgeDays)),
		"MINIMUM_PASSWORD_AGE":    strconv.Itoa(int(minPasswdAgeDays)),
		"FORCE_LOGOFF":            forceLogoffValue,
		"MINIMUM_PASSWORD_LENGTH": strconv.Itoa(int(userModalsInfo.MinPasswdLen)),
		"PasswordHistLen":         strconv.Itoa(int(userModalsInfo.PasswordHistLen)),
	}

	return passwordPolicies, nil
}

// Function to get security policy settings using PowerShell
func getSecurityPolicies() (map[string]string, error) {
	psScript := `
		$ErrorActionPreference = 'Stop'
		$tempFile = [System.IO.Path]::GetTempFileName()
		secedit /export /cfg $tempFile /areas SECURITYPOLICY | Out-Null
		$content = Get-Content $tempFile

		$passwordPolicies = @{
			"MinimumPasswordLengthAudit" = "Not Defined"
			"PasswordMustMeetComplexityRequirements" = "Not Defined"
			"RelaxMinimumPasswordLengthLimits" = "Not Defined"
			"StorePasswordsUsingReversibleEncryption" = "Not Defined"
			"EnforcePasswordHistory" = "Not Defined"
			"AllowAdministratorAccountLockout" = "Not Defined"
		}

		foreach ($line in $content) {
			if ($line -match "MinimumPasswordLengthAudit\s*=\s*(\d+)") {
				$passwordPolicies["MinimumPasswordLengthAudit"] = $matches[1]
			}
			if ($line -match "PasswordComplexity\s*=\s*(\d)") {
				$passwordPolicies["PasswordMustMeetComplexityRequirements"] = if ($matches[1] -eq 1) { "Enabled" } else { "Disabled" }
			}
			if ($line -match "RelaxMinimumPasswordLengthLimits\s*=\s*(\d)") {
				$passwordPolicies["RelaxMinimumPasswordLengthLimits"] = if ($matches[1] -eq 1) { "Enabled" } else { "Disabled" }
			}
			if ($line -match "ClearTextPassword\s*=\s*(\d)") {
				$passwordPolicies["StorePasswordsUsingReversibleEncryption"] = if ($matches[1] -eq 1) { "Enabled" } else { "Disabled" }
			}
			if ($line -match "PasswordHistorySize\s*=\s*(\d+)") {
				$passwordPolicies["EnforcePasswordHistory"] = "$($matches[1])"
			}
			if ($line -match "LockoutBadCount\s*=\s*(\d+)") {
				$passwordPolicies["AllowAdministratorAccountLockout"] = if ($matches[1] -gt 0) { "Enabled" } else { "Disabled" }
			}
		}

		# Check if LockoutBadCount is not defined, it means 'Not Applicable'
		if ($passwordPolicies["AllowAdministratorAccountLockout"] -eq "Not Defined") {
			$passwordPolicies["AllowAdministratorAccountLockout"] = "Not Applicable"
		}

		Remove-Item $tempFile

		$passwordPolicies | ConvertTo-Json
	`

	// Execute the PowerShell script
	cmd := exec.Command("powershell", "-Command", psScript)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("error executing PowerShell script: %w", err)
	}

	// Parse the JSON output into a map
	var securityPolicies map[string]string
	err = json.Unmarshal(output, &securityPolicies)
	if err != nil {
		return nil, fmt.Errorf("error parsing JSON output: %w", err)
	}

	// Map PowerShell policy keys to the required static key names
	mappedSecurityPolicies := map[string]string{
		"MinimumPasswordLengthAudit":       securityPolicies["MinimumPasswordLengthAudit"],
		"COMPLEXITY_REQUIREMENTS":          securityPolicies["PasswordMustMeetComplexityRequirements"],
		"RelaxMinimumPasswordLengthLimits": securityPolicies["RelaxMinimumPasswordLengthLimits"],
		"REVERSIBLE_ENCRYPTION":            securityPolicies["StorePasswordsUsingReversibleEncryption"],
		"ENFORCE_PASSWORD_HISTORY":         securityPolicies["EnforcePasswordHistory"],
		"LOCKOUT_ADMINS":                   securityPolicies["AllowAdministratorAccountLockout"],
	}

	return mappedSecurityPolicies, nil
}

// Function to combine the results from both sources
func getPasswordPolicies() (map[string]string, error) {
	// Get user modals info
	userModalsInfo, err := getUserModalsInfo()
	if err != nil {
		return nil, err
	}

	// Get security policy settings
	securityPolicies, err := getSecurityPolicies()
	if err != nil {
		return nil, err
	}

	// Merge security policies into the main map
	for k, v := range securityPolicies {
		userModalsInfo[k] = v
	}

	return userModalsInfo, nil
}

func Mainppp() {
	// Get the password policies
	policies, err := getPasswordPolicies()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Print all policies
	for key, value := range policies {
		fmt.Printf("%s: %s\n", key, value)
	}
}

// Handler functions for different types
func GetPasswordPolicy(obj map[string]string, variables map[string]string) (map[string]string, error) {
	valueType := obj["value_type"]
	valueData := obj["value_data"]
	passwordPolicy := obj["password_policy"]

	resultMap := map[string]string{
		"type":           obj["type"],
		"control_key":    obj["control_key"],
		"Resulting Data": valueData,
		"Audit Output":   "",
		"status":         "false",
	}

	// Check if it is a variable and return it if so.
	if value, found := getValueFromVariables(valueData, variables); found {
		valueData = value
		resultMap["Resulting Data"] = valueData
	} else {
		return resultMap, fmt.Errorf("variable %s not found", valueData)
	}

	policies, err := getPasswordPolicies()
	if err != nil {
		return resultMap, fmt.Errorf("error getting password policies: %w", err)
	}

	var result bool
	var status string

	if valueType == "POLICY_DWORD" || valueType == "TIME_DAY" {
		policyMin, policyMax, logicalValues := handleDwordOrRangeValue(valueData)
		result, err = compareValues(policyMin, policyMax, policies[passwordPolicy], logicalValues)
		if err != nil {
			return resultMap, fmt.Errorf("error comparing values for input %s: %w", valueData, err)
		}
	} else if valueType == "POLICY_SET" {
		result = valueData == policies[passwordPolicy]
	}

	if result {
		status = "true"
	} else {
		status = "false"
	}

	resultMap["Audit Output"] = policies[passwordPolicy]
	resultMap["status"] = status

	return resultMap, nil
}
