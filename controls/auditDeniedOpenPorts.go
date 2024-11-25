package controls

import "fmt"

func GetAuditDeniedOpenPorts(obj map[string]string, variables map[string]string) (map[string]string, error) {

	valueType := obj["value_type"]
	valueData := obj["value_data"]
	portType := obj["port_type"]

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

	var result bool
	var status string

	if valueType == "POLICY_PORTS" {
		// Get the list of open ports
		openPorts, err := checkOpenPorts(ports, valueData)
		if err != nil {
			return nil, fmt.Errorf("error checking open ports: %w", err)
		}

		// Print the open ports
		if len(openPorts) > 0 {
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
		"Description": obj["description"],
		"Resulting Data":  valueData,
		// add the list of ports we got as a value  to the returned_value key
		"Audit Output": fmt.Sprintf("%v", ports),
		"status":       status,
	}

	return resultMap, nil
}
