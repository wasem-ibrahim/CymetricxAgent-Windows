package controls

/*
#include <windows.h>
#include <ntsecapi.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct {
    char auditEventNames[9][50];
    char auditEventOptions[9][50];
} AuditPolicy;

AuditPolicy* GetAuditPolicy()
{
    AuditPolicy* policy = (AuditPolicy*)malloc(sizeof(AuditPolicy));
    if (policy == NULL) {
        return NULL;
    }

    LSA_HANDLE policyHandle;
    LSA_OBJECT_ATTRIBUTES objectAttributes;
    ZeroMemory(&objectAttributes, sizeof(objectAttributes));

    NTSTATUS status = LsaOpenPolicy(NULL, &objectAttributes, POLICY_VIEW_AUDIT_INFORMATION, &policyHandle);
    if (!NT_SUCCESS(status)) {
        free(policy);
        return NULL;
    }

    POLICY_AUDIT_EVENTS_INFO* auditInfo;
    status = LsaQueryInformationPolicy(policyHandle, PolicyAuditEventsInformation, (void**)&auditInfo);
    if (!NT_SUCCESS(status)) {
        LsaClose(policyHandle);
        free(policy);
        return NULL;
    }

    const char* auditEventNames[] = {
        "AuditCategorySystem",
        "AuditCategoryLogon",
        "AuditCategoryObjectAccess",
        "AuditCategoryPrivilegeUse",
        "AuditCategoryDetailedTracking",
        "AuditCategoryPolicyChange",
        "AuditCategoryAccountManagement",
        "AuditCategoryDirectoryServiceAccess",
        "AuditCategoryAccountLogon"
    };

    for (ULONG i = 0; i < auditInfo->MaximumAuditEventCount; i++) {
        strcpy(policy->auditEventNames[i], auditEventNames[i]);
        ULONG options = auditInfo->EventAuditingOptions[i];
        if (options == POLICY_AUDIT_EVENT_NONE) {
            strcpy(policy->auditEventOptions[i], "No auditing");
        } else {
            bool success = (options & POLICY_AUDIT_EVENT_SUCCESS) != 0;
            bool failure = (options & POLICY_AUDIT_EVENT_FAILURE) != 0;

            if (success && failure) {
                strcpy(policy->auditEventOptions[i], "Success, Failure");
            } else if (success) {
                strcpy(policy->auditEventOptions[i], "Success");
            } else if (failure) {
                strcpy(policy->auditEventOptions[i], "Failure");
            } else {
                strcpy(policy->auditEventOptions[i], "No auditing");
            }
        }
    }

    LsaFreeMemory(auditInfo);
    LsaClose(policyHandle);
    return policy;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// getAuditPolicies retrieves the audit policy and converts it to a map of string to string.
func getAuditPolicies() (map[string]string, error) {
	auditPolicy := C.GetAuditPolicy()
	if auditPolicy == nil {
		return nil, fmt.Errorf("failed to get audit policy")
	}
	defer C.free(unsafe.Pointer(auditPolicy))

	eventMapping := map[string]string{
		"AUDIT_ACCOUNT_LOGON":            "AuditCategoryAccountLogon",
		"AUDIT_ACCOUNT_MANAGER":          "AuditCategoryAccountManagement",
		"AUDIT_DIRECTORY_SERVICE_ACCESS": "AuditCategoryDirectoryServiceAccess",
		"AUDIT_LOGON":                    "AuditCategoryLogon",
		"AUDIT_OBJECT_ACCESS":            "AuditCategoryObjectAccess",
		"AUDIT_POLICY_CHANGE":            "AuditCategoryPolicyChange",
		"AUDIT_PRIVILEGE_USE":            "AuditCategoryPrivilegeUse",
		"AUDIT_DETAILED_TRACKING":        "AuditCategoryDetailedTracking",
		"AUDIT_SYSTEM":                   "AuditCategorySystem",
	}

	auditMap := make(map[string]string)

	for key, value := range eventMapping {
		for i := 0; i < 9; i++ {
			eventName := C.GoString(&auditPolicy.auditEventNames[i][0])
			if eventName == value {
				eventOption := C.GoString(&auditPolicy.auditEventOptions[i][0])
				auditMap[key] = eventOption
			}
		}
	}

	return auditMap, nil
}

// Maina is the caller function that calls getAuditPolicies and handles the result.
func Maina() {
	auditMap, err := getAuditPolicies()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	for k, v := range auditMap {
		fmt.Printf("%s: %s\n", k, v)
	}
}

func GetAuditPolicy(obj map[string]string, variables map[string]string) (map[string]string, error) {
	policies, err := getAuditPolicies()
	if err != nil {
		return nil, fmt.Errorf("error getting lockout policy: %w", err)
	}

	valueType := obj["value_type"]
	valueData := obj["value_data"]
	auditPolicy := obj["audit_policy"]

	// Check if it is a variable and return it if so.
	if value, found := getValueFromVariables(valueData, variables); found {
		valueData = value
	} else {
		return nil, fmt.Errorf("variable %s not found", valueData)
	}

	var result bool
	var status string

	if valueType == "AUDIT_SET" {
		result = valueData == policies[auditPolicy]
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
		"Description":  obj["description"],
		"Resulting Data":   valueData,
		"Audit Output": policies[auditPolicy],
		"status":       status,
	}

	return resultMap, nil
}
