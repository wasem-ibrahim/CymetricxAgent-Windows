package controls

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/cakturk/go-netstat/netstat"
)

func getOpenSockets(portType string) ([]netstat.SockTabEntry, error) {
	var sockets []netstat.SockTabEntry
	var sockets6 []netstat.SockTabEntry
	var err error

	switch portType {
	case "TCP":
		sockets, sockets6, err = getTCPAndTCP56ListeningServices2()
	case "UDP":
		sockets, sockets6, err = getUDPAndUDP6ListeningServices2()
	}

	if err != nil {
		return nil, fmt.Errorf("error getting %s sockets: %s", portType, err)
	}

	// Combine sockets and sockets6 into one list
	combinedSockets := append(sockets, sockets6...)

	return combinedSockets, nil
}

func getTCPAndTCP56ListeningServices2() ([]netstat.SockTabEntry, []netstat.SockTabEntry, error) {

	// get only listening TCP sockets
	sockets, err := netstat.TCPSocks(func(s *netstat.SockTabEntry) bool {
		return s.State == netstat.Listen
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error getting TCP sockets: %s", err)
	}

	// get only listening TCP6 sockets
	sockets6, err := netstat.TCP6Socks(func(s *netstat.SockTabEntry) bool {
		return s.State == netstat.Listen
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error getting TCP6 sockets: %s", err)
	}

	return sockets, sockets6, nil
}

func getUDPAndUDP6ListeningServices2() ([]netstat.SockTabEntry, []netstat.SockTabEntry, error) {

	// get only listening UDP sockets
	sockets, err := netstat.UDPSocks(func(s *netstat.SockTabEntry) bool {
		return s.State == netstat.Listen
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error getting UDP sockets: %s", err)
	}

	// get only listening UDP6 sockets
	sockets6, err := netstat.UDP6Socks(func(s *netstat.SockTabEntry) bool {
		return s.State == netstat.Listen
	})
	if err != nil {
		return nil, nil, fmt.Errorf("error getting UDP6 sockets: %s", err)
	}

	return sockets, sockets6, nil
}

// Function to check if a port is open and return a list of open ports
func checkOpenPorts(ports []uint16, portNumber string) ([]uint16, error) {
	// Split the valueData string by commas
	portStrings := strings.Split(portNumber, ",")

	// Convert the ports list to a map for quick lookup
	portMap := make(map[uint16]bool)
	for _, port := range ports {
		portMap[port] = true
	}

	// List to hold the open ports
	openPorts := []uint16{}

	// Iterate over the portStrings
	for _, portStr := range portStrings {
		portStr = strings.TrimSpace(portStr)
		if portStr == "" {
			continue
		}

		// Check if the portStr is a regex pattern
		if strings.ContainsAny(portStr, "[]+") {
			// Compile the regex pattern
			regex, err := regexp.Compile(portStr)
			if err != nil {
				fmt.Printf("Invalid regex pattern: %s\n", portStr)
				continue
			}

			// Check if any of the ports match the regex pattern
			for port := range portMap {
				if regex.MatchString(strconv.Itoa(int(port))) {
					openPorts = append(openPorts, port)
				}
			}
		} else {
			// Convert portStr to an integer
			portNum, err := strconv.Atoi(portStr)
			if err != nil {
				fmt.Printf("Invalid port number: %s\n", portStr)
				continue
			}
			port := uint16(portNum)

			// Check if the port is in the portMap
			if portMap[port] {
				openPorts = append(openPorts, port)
			}
		}
	}

	// Return the list of open ports
	return openPorts, nil
}

func GetAuditAllowedOpenPorts(obj map[string]string, variables map[string]string) (map[string]string, error) {

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
		"Resulting Data":  valueData,
		// add the list of ports we got as a value  to the returned_value key
		"Audit Output": fmt.Sprintf("%v", ports),
		"status":       status,
	}

	return resultMap, nil
}
