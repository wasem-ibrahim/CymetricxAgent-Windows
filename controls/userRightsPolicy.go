package controls

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

const (
	STATUS_SUCCESS                = 0x00000000
	POLICY_LOOKUP_NAMES           = 0x00000800
	POLICY_VIEW_LOCAL_INFORMATION = 0x00000001
	STATUS_NO_MORE_ENTRIES        = 0x8000001A
)

type LSA_UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type LSA_OBJECT_ATTRIBUTES struct {
	Length                   uint32
	RootDirectory            syscall.Handle
	ObjectName               *LSA_UNICODE_STRING
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type LSA_ENUMERATION_INFORMATION struct {
	Sid *syscall.SID
}

var (
	modAdvapi32                           = syscall.NewLazyDLL("advapi32.dll")
	procLsaEnumerateAccountsWithUserRight = modAdvapi32.NewProc("LsaEnumerateAccountsWithUserRight")
	procLsaOpenPolicy                     = modAdvapi32.NewProc("LsaOpenPolicy")
	procLsaNtStatusToWinError             = modAdvapi32.NewProc("LsaNtStatusToWinError")
	procLsaFreeMemory                     = modAdvapi32.NewProc("LsaFreeMemory")
	procLsaClose                          = modAdvapi32.NewProc("LsaClose")
)

func getUsersRightsPolicyForPrivilege(privilege string, includeDomain bool) ([]string, error) {
	// Open LSA Policy
	policyHandle, err := LsaOpenPolicy(nil, POLICY_LOOKUP_NAMES|POLICY_VIEW_LOCAL_INFORMATION)
	if err != nil {
		return nil, fmt.Errorf("error opening policy: %w", err)
	}
	defer LsaClose(policyHandle)

	// Convert privilege string to LSA_UNICODE_STRING
	userRight := stringToLSAUnicodeString(privilege)

	// Enumerate accounts with the specified user right
	accounts, err := LsaEnumerateAccountsWithUserRight(policyHandle, userRight)
	if err != nil {
		return nil, fmt.Errorf("error enumerating accounts with user right %s: %w", privilege, err)
	}

	if len(accounts) == 0 {
		return nil, fmt.Errorf("no accounts found with the user right: %s", privilege)
	}

	// Inner function to convert SIDs to strings
	convertSidsToStrings := func(accounts []LSA_ENUMERATION_INFORMATION) ([]string, error) {
		var sidList []string
		for _, account := range accounts {
			if account.Sid == nil {
				return nil, fmt.Errorf("retrieved a nil SID")
			}
			sidString, err := convertSidToString1(account.Sid)
			if err != nil {
				return nil, fmt.Errorf("error converting SID for account %s with privilege %s to string: %w", account.Sid, privilege, err)
			}
			sidList = append(sidList, sidString)
		}
		return sidList, nil
	}

	// Inner function to lookup account names
	lookupAccountNames := func(sidList []string) ([]string, error) {
		var accountNames []string
		for _, sid := range sidList {
			accountName, err := lookupAccountName(sid, includeDomain)
			if err != nil {
				return nil, fmt.Errorf("error looking up SID %s: %w", sid, err)
			}
			accountNames = append(accountNames, accountName)
		}
		return accountNames, nil
	}

	sidList, err := convertSidsToStrings(accounts)
	if err != nil {
		return nil, err
	}

	return lookupAccountNames(sidList)
}

func LsaOpenPolicy(systemName *uint16, desiredAccess uint32) (policyHandle syscall.Handle, err error) {
	var objectAttributes LSA_OBJECT_ATTRIBUTES
	objectAttributes.Length = uint32(unsafe.Sizeof(objectAttributes))
	r1, _, _ := procLsaOpenPolicy.Call(
		uintptr(unsafe.Pointer(systemName)),
		uintptr(unsafe.Pointer(&objectAttributes)),
		uintptr(desiredAccess),
		uintptr(unsafe.Pointer(&policyHandle)),
	)
	if r1 != STATUS_SUCCESS {
		err = syscall.Errno(LsaNtStatusToWinError(r1))
	}
	return
}

func LsaEnumerateAccountsWithUserRight(policyHandle syscall.Handle, userRight *LSA_UNICODE_STRING) ([]LSA_ENUMERATION_INFORMATION, error) {
	var buffer *LSA_ENUMERATION_INFORMATION
	var countReturned uint32

	r1, _, _ := procLsaEnumerateAccountsWithUserRight.Call(
		uintptr(policyHandle),
		uintptr(unsafe.Pointer(userRight)),
		uintptr(unsafe.Pointer(&buffer)),
		uintptr(unsafe.Pointer(&countReturned)),
	)
	if r1 != STATUS_SUCCESS {
		// Check for STATUS_NO_MORE_ENTRIES and treat it as no accounts found
		if r1 == STATUS_NO_MORE_ENTRIES {
			return nil, nil
		}
		err := syscall.Errno(LsaNtStatusToWinError(r1))
		return nil, err
	}

	defer procLsaFreeMemory.Call(uintptr(unsafe.Pointer(buffer)))

	if countReturned == 0 {
		return nil, nil
	}

	accounts := make([]LSA_ENUMERATION_INFORMATION, countReturned)
	for i := 0; i < int(countReturned); i++ {
		accounts[i] = *(*LSA_ENUMERATION_INFORMATION)(unsafe.Pointer(uintptr(unsafe.Pointer(buffer)) + uintptr(i)*unsafe.Sizeof(*buffer)))
	}

	return accounts, nil
}

func LsaClose(policyHandle syscall.Handle) error {
	r1, _, _ := procLsaClose.Call(uintptr(policyHandle))
	if r1 != STATUS_SUCCESS {
		return syscall.Errno(LsaNtStatusToWinError(r1))
	}
	return nil
}

func stringToLSAUnicodeString(s string) *LSA_UNICODE_STRING {
	us := syscall.StringToUTF16(s)
	return &LSA_UNICODE_STRING{
		Length:        uint16((len(us) - 1) * 2),
		MaximumLength: uint16(len(us) * 2),
		Buffer:        &us[0],
	}
}

func convertSidToString1(sid *syscall.SID) (string, error) {
	var stringSid *uint16
	err := syscall.ConvertSidToStringSid(sid, &stringSid)
	if err != nil {
		return "", err
	}
	defer syscall.LocalFree((syscall.Handle)(unsafe.Pointer(stringSid)))
	return syscall.UTF16ToString((*[256]uint16)(unsafe.Pointer(stringSid))[:]), nil
}

func LsaNtStatusToWinError(status uintptr) syscall.Errno {
	r1, _, _ := procLsaNtStatusToWinError.Call(status)
	return syscall.Errno(r1)
}

func lookupAccountName(sidStr string, includeDomain bool) (string, error) {
	// Convert SID string to SID
	sid, err := StringToSid(sidStr)
	if err != nil {
		return "", err
	}

	// Lookup account name
	var accountName [256]uint16
	var domainName [256]uint16
	accountNameLen := uint32(len(accountName))
	domainNameLen := uint32(len(domainName))
	var sidType uint32

	err = syscall.LookupAccountSid(nil, sid, &accountName[0], &accountNameLen, &domainName[0], &domainNameLen, &sidType)
	if err != nil {
		return "", err
	}

	if includeDomain {
		return fmt.Sprintf("%s\\%s", syscall.UTF16ToString(domainName[:]), syscall.UTF16ToString(accountName[:])), nil
	}

	return syscall.UTF16ToString(accountName[:]), nil
}

// StringToSid converts a string representation of a SID to a SID.
func StringToSid(s string) (*syscall.SID, error) {
	var sid *syscall.SID
	err := ConvertStringSidToSid(s, &sid)
	if err != nil {
		return nil, err
	}
	return sid, nil
}

// ConvertStringSidToSid is a wrapper for the Windows API function ConvertStringSidToSidW.
func ConvertStringSidToSid(stringSid string, sid **syscall.SID) error {
	psid, err := syscall.UTF16PtrFromString(stringSid)
	if err != nil {
		return err
	}
	r1, _, e1 := syscall.NewLazyDLL("advapi32.dll").NewProc("ConvertStringSidToSidW").Call(
		uintptr(unsafe.Pointer(psid)),
		uintptr(unsafe.Pointer(sid)),
	)
	if r1 == 0 {
		return e1
	}
	return nil
}
func Mainu() {
	privilege := "SeBatchLogonRight"
	includeDomain := true // Set this to true or false as needed

	var privileges = []string{
		"SeAssignPrimaryTokenPrivilege",
		"SeAuditPrivilege",
		"SeBackupPrivilege",
		"SeBatchLogonRight",
		"SeChangeNotifyPrivilege",
		"SeCreateGlobalPrivilege",
		"SeCreatePagefilePrivilege",
		"SeCreatePermanentPrivilege",
		"SeCreateTokenPrivilege",
		"SeDenyBatchLogonRight",
		"SeDenyInteractiveLogonRight",
		"SeDenyNetworkLogonRight",
		"SeDenyRemoteInteractiveLogonRight",
		"SeDenyServiceLogonRight",
		"SeDebugPrivilege",
		"SeEnableDelegationPrivilege",
		"SeImpersonatePrivilege",
		"SeIncreaseBasePriorityPrivilege",
		"SeIncreaseWorkingSetPrivilege",
		"SeIncreaseQuotaPrivilege",
		"SeInteractiveLogonRight",
		"SeLoadDriverPrivilege",
		"SeLockMemoryPrivilege",
		"SeMachineAccountPrivilege",
		"SeManageVolumePrivilege",
		"SeNetworkLogonRight",
		"SeProfileSingleProcessPrivilege",
		"SeRemoteShutdownPrivilege",
		"SeRemoteInteractiveLogonRight",
		"SeRelabelPrivilege",
		"SeRestorePrivilege",
		"SeSecurityPrivilege",
		"SeServiceLogonRight",
		"SeShutdownPrivilege",
		"SeSyncAgentPrivilege",
		"SeSystemEnvironmentPrivilege",
		"SeSystemProfilePrivilege",
		"SeSystemTimePrivilege",
		"SeTakeOwnershipPrivilege",
		"SeTcbPrivilege",
		"SeTimeZonePrivilege",
		"SeUndockPrivilege",
	}

	for _, privilege1 := range privileges {
		x, err := getUsersRightsPolicyForPrivilege(privilege1, includeDomain)
		if err != nil {
			fmt.Println("Error:", err)
			continue
		}
		fmt.Println("Privilege:", privilege1)
		fmt.Println("Account names:", x)
	}
	return

	accountNames, err := getUsersRightsPolicyForPrivilege(privilege, includeDomain)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// accountNames = []string{"Administrators", "WdiServiceHost"}

	// Sample control data
	control := struct {
		Type        string
		ControlKey  string
		Description string
		ValueType   string
		ValueData   string
		RightType   string
	}{
		Type:        "USER_RIGHTS_POLICY",
		ControlKey:  "2.2.44",
		Description: "2.2.44 (L1) Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\\WdiServiceHost'",
		ValueType:   "USER_RIGHT",
		ValueData:   "Administrators && (NT SERVICE\\WdiServiceHost || WdiServiceHost)",
		RightType:   "SeSystemProfilePrivilege",
	}

	fmt.Println("Checking control:", control.ValueData)
	fmt.Println("Account names:", accountNames)

	result := EvaluateLogicalExpression(control.ValueData, accountNames)
	fmt.Printf("Control Check for '%s': %v\n", control.Description, result)
}

// Helper function to evaluate logical expression
func EvaluateLogicalExpression(expression string, accountNames []string) bool {
	if strings.TrimSpace(expression) == "" {
		// Handle empty expression case
		return false
	}

	expression = prepareExpression(expression, accountNames)
	expr, err := parser.ParseExpr(expression)
	if err != nil {
		return false
	}
	return eval(expr)
}

// Helper function to replace account names with true/false in the expression
func prepareExpression(expression string, accountNames []string) string {
	// Convert the expression to lowercase for uniform matching
	expression = strings.ToLower(expression)

	// Convert all account names to lowercase for uniform matching
	lowerAccountNames := make([]string, len(accountNames))
	for i, name := range accountNames {
		lowerAccountNames[i] = strings.ToLower(name)
	}

	// Sort accountNames by length in descending order to avoid partial replacements
	sort.Slice(lowerAccountNames, func(i, j int) bool {
		return len(lowerAccountNames[i]) > len(lowerAccountNames[j])
	})

	// Replace account names with 'true'
	for _, name := range lowerAccountNames {
		escapedName := regexp.QuoteMeta(name)
		// Replace exact occurrences of the account name
		re := regexp.MustCompile(`\b` + escapedName + `\b`)
		expression = re.ReplaceAllString(expression, "true")
	}

	// Replace remaining names (non-matched) with 'false'
	// Match sequences of letters, digits, underscores, and spaces
	re := regexp.MustCompile(`\b[a-z0-9_\\ ]+\b`)
	expression = re.ReplaceAllStringFunc(expression, func(name string) string {
		trimmedName := strings.TrimSpace(name)
		if trimmedName != "true" && trimmedName != "false" && !isLogicalOperator(trimmedName) {
			return "false"
		}
		return name
	})

	return expression
}

// Check if the token is a logical operator
func isLogicalOperator(token string) bool {
	return token == "&&" || token == "||" || token == "(" || token == ")"
}

// Helper function to evaluate parsed boolean expression
func eval(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.ParenExpr:
		return eval(e.X)
	case *ast.BinaryExpr:
		switch e.Op {
		case token.LAND:
			return eval(e.X) && eval(e.Y)
		case token.LOR:
			return eval(e.X) || eval(e.Y)
		}
	case *ast.Ident:
		return e.Name == "true"
	}
	return false
}

// Handler functions for different types
func GetUserRightsPolicy(obj map[string]string, variables map[string]string) (map[string]string, error) {
	valueType := obj["value_type"]
	valueData := obj["value_data"] // Expression of users and groups
	rightType := obj["right_type"]

	includeDomain := false // Set this to true or false as needed

	if useDomain, ok := obj["use_domain"]; ok {
		includeDomain = useDomain == "YES"
	}

	// Constructing the result map
	resultMap := map[string]string{
		"type":                  obj["type"],
		"control_key":           obj["control_key"],
		"Resulting Data":        valueData,
		"Audit Output":          "",
		"status":                "false",
		"Rights Classification": rightType,
	}

	//Capatilize the word "builtin" in the valueData if it is present
	// This is done to match the format of the builtin accounts in the system
	// where the valueData is compared against the returned value from the system
	valueData = strings.Replace(valueData, "builtin", "BUILTIN", -1)

	// Check if it is a variable and return it if so.
	if value, found := getValueFromVariables(valueData, variables); found {
		valueData = value
		resultMap["Resulting Data"] = valueData
	} else {
		return resultMap, fmt.Errorf("variable %s not found", valueData)
	}

	accountNames, err := getUsersRightsPolicyForPrivilege(rightType, includeDomain)
	if err != nil {
		if strings.Contains(err.Error(), "no accounts found") && valueData == "" {
			resultMap["status"] = "true"
			return resultMap, nil
		} else if strings.Contains(err.Error(), "error converting SID") {
			// Use backup method to get the denied rights using secedit
			var err error
			accountNames, err = getSeceditAccountNames(rightType)
			fmt.Println("Account names:", accountNames)
			if err != nil {
				return resultMap, fmt.Errorf("failed to get user rights policy using secedit: %w", err)
			}
		} else {
			return resultMap, fmt.Errorf("failed to get user rights policy: %w", err)
		}
	}

	resultMap["Audit Output"] = strings.Join(accountNames, ", ")

	var result bool
	var status string

	if valueType == "USER_RIGHT" {
		if strings.Contains(valueData, "&&") || strings.Contains(valueData, "||") {
			// If the valueData contains logical operators, then evaluate the logical expression
			result = EvaluateLogicalExpression(valueData, accountNames)
		} else {
			// Here we would have only one value in the valueData so in this case i need to exactly match the valueData with the accountNames
			// If accountNames contains anything more than what's mentioned in valueData, then it should return false
			// If accountNames contains exactly what's mentioned in valueData, then it should return true

			if len(accountNames) > 1 {
				// If there are more than one account names, then it should return false
				// Because the valueData is a single account name
				result = false
			} else if len(accountNames) == 1 {
				if strings.EqualFold(accountNames[0], valueData) {
					// If there is only one account name and it matches the valueData, then it should return true
					result = true
				} else {
					// If there is only one account name and it doesn't match the valueData, then it should return false
					result = false
				}
			} else if len(accountNames) == 0 && valueData == "" {
				// Set to no one case, which should return true
				result = true
			} else {
				// If there are no account names, then it should return false
				result = false
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

// Helper function to read UTF-16 encoded file
func readUTF16File(path string) (string, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}

	// Check for BOM and strip it
	if len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE {
		data = data[2:]
	}

	// Convert UTF-16 (little-endian) bytes to string
	u16s := make([]uint16, len(data)/2)
	for i := 0; i < len(u16s); i++ {
		u16s[i] = uint16(data[2*i]) + uint16(data[2*i+1])<<8
	}
	return string(utf16.Decode(u16s)), nil
}

// Placeholder implementation for secedit usage in PowerShell
func getSeceditAccountNames(rightType string) ([]string, error) {
	tempFile := "securitypolicy.txt"
	cmd := exec.Command("powershell", "-Command", fmt.Sprintf("secedit /export /cfg %s", tempFile))
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to export security policy: %w", err)
	}
	defer os.Remove(tempFile)

	content, err := readUTF16File(tempFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read security policy file: %w", err)
	}

	lines := strings.Split(content, "\r\n")
	var values []string
	for _, line := range lines {
		if strings.HasPrefix(line, rightType) {
			parts := strings.Split(line, "=")
			if len(parts) > 1 {
				values = strings.Split(parts[1], ",")
				break
			}
		}
	}

	var accountNames []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if strings.HasPrefix(value, "*S") {
			value = value[1:]
			accountName, err := lookupAccountName(value, false)
			if err != nil {
				return nil, fmt.Errorf("failed to look up SID: %w", err)
			}
			accountNames = append(accountNames, accountName)
		} else {
			accountNames = append(accountNames, value)
		}
	}

	return accountNames, nil
}
