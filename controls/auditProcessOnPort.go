package controls

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

func GetAuditProcessOnPort(obj map[string]string, variables map[string]string) (map[string]string, error) {

	valueType := obj["value_type"]
	valueData := obj["value_data"]
	portType := obj["port_type"]
	portNumber := obj["port_no"]
	// portOption := obj["port_option"]
	// checkType := obj["check_type"]

	sockets, err := getOpenSockets(portType)
	if err != nil {
		return nil, fmt.Errorf("error getting open ports: %w", err)
	}

	var ports []uint16
	uniquePorts := make(map[uint16]bool)

	for _, socket := range sockets {
		// Check if the port is already in the uniquePorts map
		if _, exists := uniquePorts[socket.LocalAddr.Port]; !exists {
			uniquePorts[socket.LocalAddr.Port] = true
			ports = append(ports, socket.LocalAddr.Port)
		}
	}

	// Build a process map where the key is the port number and the value is a list of string of the processes that are using the port
	processMap := make(map[string][]string)
	for _, socket := range sockets {
		portStr := strconv.Itoa(int(socket.LocalAddr.Port))
		if _, exists := processMap[portStr]; !exists {
			processMap[portStr] = []string{socket.Process.Name}
		}
	}

	var result bool
	var status string

	if valueType == "POLICY_TEXT" {
		// Check open ports and process conditions
		matchingPorts, err := checkOpenPortsAndProcesses(ports, portNumber, processMap, valueData)
		if err != nil {
			return nil, fmt.Errorf("error checking open ports and processes: %w", err)
		}

		// Print the open ports
		if len(matchingPorts) > 0 {
			result = true
		} else {
			result = false
		}
	}

	if result {
		status = "true"
	} else {
		status = "false"
	}

	// Constructing the result map
	resultMap := map[string]string{
		"type":        obj["type"],
		"control_key": obj["control_key"],
		"Resulting Data":  valueData,
		// add the list of ports we got as a value  to the returned_value key
		"Audit Output": fmt.Sprintf("%v", processMap),
		"status":       status,
	}

	return resultMap, nil
}

// Function to check open ports and process conditions
func checkOpenPortsAndProcesses(ports []uint16, portNumber string, processMap map[string][]string, valueData string) ([]uint16, error) {
	// Get the list of open ports
	openPorts, err := checkOpenPorts(ports, portNumber)
	if err != nil {
		return nil, err
	}

	// List to hold the matching ports
	matchingPorts := []uint16{}

	// Check open ports and process conditions
	for _, port := range openPorts {
		portStr := strconv.Itoa(int(port))
		processes, exists := processMap[portStr]
		if !exists {
			continue
		}

		match, err := evaluateProcessCondition(processes, valueData)
		if err != nil {
			return nil, err
		}

		if match {
			matchingPorts = append(matchingPorts, port)
		}
	}

	return matchingPorts, nil
}

// Function to evaluate process conditions
func evaluateProcessCondition(processList []string, valueData string) (bool, error) {
	// Split the condition by logical operators
	orConditions := strings.Split(valueData, "||")
	for _, orCondition := range orConditions {
		andConditions := strings.Split(strings.TrimSpace(orCondition), "&&")
		matchAll := true

		for _, andCondition := range andConditions {
			andCondition = strings.TrimSpace(andCondition)
			regex, err := regexp.Compile(andCondition)
			if err != nil {
				return false, fmt.Errorf("invalid regex pattern: %s", andCondition)
			}

			matched := false
			for _, process := range processList {
				if regex.MatchString(process) {
					matched = true
					break
				}
			}

			if !matched {
				matchAll = false
				break
			}
		}

		if matchAll {
			return true, nil
		}
	}

	return false, nil
}
