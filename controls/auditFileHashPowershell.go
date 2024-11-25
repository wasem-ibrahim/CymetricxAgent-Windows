package controls

import (
	"fmt"
	"strings"
)

func GetAuditFIleHashPowershell(obj map[string]string, variables map[string]string) (map[string]string, error) {
	valueType := obj["value_type"]
	valueData := obj["value_data"]
	filePath := obj["file"]
	hashAlgorithm := "MD5" // default hash algorithm
	powershellPath := getPowerShellPath()

	// check if ps_encoded_args is a key in the variables map
	if val, ok := variables["hash_algorithm"]; ok {
		// decode base64 encoded powershell_args
		hashAlgorithm = val
	}

	psCommand := fmt.Sprintf("Get-FileHash -Path \"%s\" -Algorithm %s | Select-Object -ExpandProperty Hash", filePath, hashAlgorithm)

	returned_value, err := execCommandWithOutput2(powershellPath, psCommand)
	if err != nil {
		return map[string]string{
			"type":           obj["type"],
			"control_key":    obj["control_key"],
			"value_date":     valueData,
			"Audit Output":   err.Error(),
			"status":         "false",
			"hash_algorithm": hashAlgorithm,
			"file":           filePath,
		}, fmt.Errorf("error executing powershell command: %w", err)
	}

	var result bool
	var status string
	returned_value = strings.TrimSpace(returned_value)

	if valueType == "POLICY_TEXT" {
		result = valueData == returned_value
	}

	if result {
		status = "true"
	} else {
		status = "false"
	}

	// Constructing the result map
	resultMap := map[string]string{
		"type":           obj["type"],
		"control_key":    obj["control_key"],
		"Description":    obj["description"],
		"Resulting Data":     valueData,
		"Audit Output":   returned_value,
		"status":         status,
		"Hash Algorithm": hashAlgorithm,
		"File":           filePath,
	}

	return resultMap, nil
}
