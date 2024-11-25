package controls

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

func checkTypeValidationValues(checkType, valueData, localPolicyValue string) (bool, error) {
	valueDataList := strings.Split(valueData, "||")

	switch checkType {
	// Default case is for empty checkType which means "CHECK_EQUAL"
	case "":
		for _, val := range valueDataList {
			if strings.TrimSpace(val) == strings.TrimSpace(localPolicyValue) {
				return true, nil
			}
		}
		return false, nil
	case "CHECK_EQUAL":
		for _, val := range valueDataList {
			if strings.TrimSpace(val) == strings.TrimSpace(localPolicyValue) {
				return true, nil
			}
		}
		return false, nil
	case "CHECK_EQUAL_ANY":
		for _, v := range valueDataList {
			if strings.TrimSpace(v) == strings.TrimSpace(localPolicyValue) {
				return true, nil
			}
		}
		return false, nil
	case "CHECK_NOT_EQUAL":
		for _, val := range valueDataList {
			if strings.TrimSpace(val) != localPolicyValue {
				return true, nil
			}
		}
		return false, nil
	case "CHECK_NOT_REGEX":
		for _, val := range valueDataList {
			matched, err := regexp.MatchString(val, strings.TrimSpace(localPolicyValue))
			if err != nil {
				return false, err
			}
			if !matched {
				return true, nil
			}
		}
		return false, nil
	case "CHECK_GREATER_THAN":
		val2, err := strconv.ParseFloat(localPolicyValue, 64)
		if err != nil {
			return false, err
		}
		for _, val := range valueDataList {
			val1, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
			if err != nil {
				return false, err
			}
			if val2 > val1 {
				return true, nil
			}
		}
		return false, nil
	case "CHECK_GREATER_THAN_OR_EQUAL":
		val2, err := strconv.ParseFloat(localPolicyValue, 64)
		if err != nil {
			return false, err
		}
		for _, val := range valueDataList {
			val1, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
			if err != nil {
				return false, err
			}
			if val2 >= val1 {
				return true, nil
			}
		}
		return false, nil
	case "CHECK_LESS_THAN":
		val2, err := strconv.ParseFloat(localPolicyValue, 64)
		if err != nil {
			return false, err
		}
		for _, val := range valueDataList {
			val1, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
			if err != nil {
				return false, err
			}
			if val2 < val1 {
				return true, nil
			}
		}
		return false, nil
	case "CHECK_LESS_THAN_OR_EQUAL":
		val2, err := strconv.ParseFloat(localPolicyValue, 64)
		if err != nil {
			return false, err
		}
		for _, val := range valueDataList {
			val1, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
			if err != nil {
				return false, err
			}
			if val2 <= val1 {
				return true, nil
			}
		}
		return false, nil
	case "CHECK_REGEX":
		for _, val := range valueDataList {
			matched, err := regexp.MatchString(val, strings.TrimSpace(localPolicyValue))
			if err != nil {
				return false, err
			}
			if matched {
				return true, nil
			}
		}
		return false, nil
	default:
		return false, fmt.Errorf("unsupported check type: %s", checkType)
	}
}

func getValueFromVariables(valueData string, variables map[string]string) (string, bool) {
	if len(valueData) > 0 && valueData[0] == '@' && valueData[len(valueData)-1] == '@' {
		varName := valueData[1 : len(valueData)-1]
		if value, exists := variables[varName]; exists {
			return value, true
		}
	}

	// if it still starts with @ and ends with @ and not found previously, return empty string and false
	if len(valueData) > 0 && valueData[0] == '@' && valueData[len(valueData)-1] == '@' {
		return "", false
	}

	// if it does not start with @ and end with @, return the value itself.
	return valueData, true
}

// handleDwordOrRangeValue parses the input string and returns appropriate values as strings
func handleDwordOrRangeValue(value string) (string, string, []string) {
	value = strings.TrimSpace(value)

	// Handle logical expressions like "1 || 11"
	if strings.Contains(value, "||") {
		parts := strings.Split(value, "||")
		var values []string
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if val, err := parseValue(part); err == nil {
				values = append(values, val)
			}
		}
		return "", "", values
	}

	// Handle ranges like "[7..11]"
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = strings.Trim(value, "[]")
		parts := strings.Split(value, "..")
		if len(parts) == 2 {
			min, err1 := parseValue(parts[0])
			max, err2 := parseValue(parts[1])
			if err1 == nil && err2 == nil {
				return min, max, nil
			}
		}
	}

	// Handle individual values like "7" or hex values
	min, err := parseValue(value)
	if err == nil {
		return min, "", nil
	}

	return "", "", nil
}

// checkRegex takes a regex pattern and an input string, applies the regex, and returns the found value or "None" if nothing is found.
// checkRegex takes a regex pattern and an input string, applies the regex, and returns true if a match is found, otherwise false.
func checkRegex(pattern string, input string) (bool, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false, fmt.Errorf("invalid regex pattern: %w", err)
	}

	match := re.MatchString(input)
	return match, nil
}

// parseValue parses a string into an appropriate number value and returns it as a string
func parseValue(value string) (string, error) {
	value = strings.TrimSpace(value)

	// Handle infinity cases
	if value == "MIN" {
		return "-inf", nil
	}
	if value == "MAX" {
		return "+inf", nil
	}

	// Handle signed hex
	if strings.HasPrefix(value, "-0x") || strings.HasPrefix(value, "+0x") || strings.HasPrefix(value, "0x") {
		return value, nil
	}

	// Handle decimal values
	if _, err := strconv.ParseInt(value, 10, 64); err == nil {
		return value, nil
	}

	return "", fmt.Errorf("invalid value format")
}

// convertToNumber converts a string to an integer or float for comparison
func convertToNumber(value string) (float64, error) {
	switch value {
	case "-inf":
		return math.Inf(-1), nil
	case "+inf":
		return math.Inf(1), nil
	}

	// Handle signed hex
	if strings.HasPrefix(value, "-0x") || strings.HasPrefix(value, "+0x") || strings.HasPrefix(value, "0x") {
		num, err := strconv.ParseInt(value, 0, 64)
		return float64(num), err
	}

	// Handle decimal values
	num, err := strconv.ParseInt(value, 10, 64)
	return float64(num), err
}

// compareValues compares a given value with the parsed policy values
func compareValues(policyMin, policyMax, givenValue string, logicalValues []string) (bool, error) {
	// Convert givenValue to an integer or float
	givenNum, err := convertToNumber(givenValue)
	if err != nil {
		return false, err
	}

	// If logicalValues is not empty, check if givenValue matches any of them
	if len(logicalValues) > 0 {
		for _, logicalValue := range logicalValues {
			logicalNum, err := convertToNumber(logicalValue)
			if err != nil {
				return false, err
			}
			if givenNum == logicalNum {
				return true, nil
			}
		}
		return false, nil
	}

	// If policyMax is empty, we only compare with policyMin
	if policyMax == "" {
		policyMinNum, err := convertToNumber(policyMin)
		if err != nil {
			return false, err
		}
		return givenNum == policyMinNum, nil
	}

	// Convert policyMin and policyMax to numbers
	policyMinNum, err := convertToNumber(policyMin)
	if err != nil {
		return false, err
	}
	policyMaxNum, err := convertToNumber(policyMax)
	if err != nil {
		return false, err
	}

	// Check if givenValue falls within the range [policyMin, policyMax]
	return policyMinNum <= givenNum && givenNum <= policyMaxNum, nil
}
