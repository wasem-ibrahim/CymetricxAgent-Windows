package main

import (
	"fmt"
)

func main3() {

	// Simulate getting JSON data from server
	jsonData := getJSONData()

	// Process the JSON data
	jsonDataOutput := processControlsData(jsonData)

	// Export it to a file
	// err := os.WriteFile("output.json", jsonDataOutput, 0644)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	jsonDataOutputString := string(jsonDataOutput)
	fmt.Println(jsonDataOutputString)
}

// Function to get JSON data (simulate server response for testing purposes)
func getJSONData() string {
	jsonData := `[
		{
			"level": 1,
			"variables": {
				"PASSWORD_HISTORY": {
					"name": "PASSWORD_HISTORY",
					"default": "[24..MAX]",
					"description": "Password history value",
					"info": "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Password Policy\\Enforce password history",
					"value_type": "STRING"
				},
				"LEGAL_NOTICE_TEXT": {
					"name": "LEGAL_NOTICE_TEXT",
					"default": "All activities performed on this system will be monitored.",
					"description": "Logon Window Text",
					"info": "This is the window text for the login warning a user receives when logging onto the system.",
					"value_type": "STRING"
				},
				"LOCKOUT_DURATION": {
					"name": "LOCKOUT_DURATION",
					"default": "[15..MAX]",
					"description": "Account lockout duration",
					"info": "Computer Configuration\\Policies\\Windows Settings\\Security Settings\\Account Policies\\Account Lockout Policy\\Account lockout duration",
					"value_type": "STRING"
				}
			},
			"controls": [
				{
				"type": "REGISTRY_SETTING",
				"control_key": "5.10",
				"description": "5.10 (L1) Ensure 'LxssManager (LxssManager)' is set to 'Disabled' or 'Not Installed'",
				"value_type": "POLICY_DWORD",
				"value_data": "4",
				"reg_key": "HKLM\\System\\CurrentControlSet\\Services\\LxssManager",
				"reg_item": "Start",
				"reg_option": "CAN_BE_NULL"
			}
			]
		}
	]`

	// get jsonDat from a json file instead. Open a file called txt.json and get the data from it
	// jsonDataBytes, err := os.ReadFile("testIIS.json")
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// jsonData = string(jsonDataBytes)
	return jsonData
}
