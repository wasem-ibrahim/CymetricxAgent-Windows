package controls

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

type ACLPermission struct {
	Principal     string `json:"Principal"`
	Type          string `json:"Type"`
	Access        string `json:"Access"`
	InheritedFrom string `json:"InheritedFrom"`
	AppliesTo     string `json:"AppliesTo"`
	IsInherited   bool   `json:"IsInherited"`
}

func mainsp() {
	serviceName := "AnyDesk" // Replace with your specific service name
	registryPath := fmt.Sprintf("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\%s", serviceName)

	output, err := getRegistryPermissions(registryPath)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	var permissions []ACLPermission
	err = json.Unmarshal([]byte(output), &permissions)
	if err != nil {
		fmt.Println("Error unmarshaling JSON data:", err)
		return
	}

	// Print the permissions
	for _, perm := range permissions {
		fmt.Printf("%+v\n", perm)
	}
}

func getRegistryPermissions(path string) (string, error) {
	powershellScript := fmt.Sprintf(`
function Get-InheritedFrom {
    param (
        [string]$path,
        [string]$identity
    )
    $parentPath = Split-Path -Parent $path
    if ($parentPath -eq $null -or $parentPath -eq "") {
        return "None"
    }
    $parentAcl = Get-Acl -Path $parentPath
    $parentAce = $parentAcl.Access | Where-Object { $_.IdentityReference -eq $identity -and $_.IsInherited -eq $false }
    if ($parentAce) {
        return $parentPath
    } else {
        return Get-InheritedFrom -path $parentPath -identity $identity
    }
}

$servicePath = '%s'
$acl = Get-Acl -Path $servicePath
$uniquePrincipals = @{}
$results = $acl.Access | ForEach-Object {
    $principal = if ($_.IdentityReference) { $_.IdentityReference.Value } else { "None" }
    if (-not $uniquePrincipals.ContainsKey($principal)) {
        $inheritedFrom = if ($_.IsInherited) { 
            Get-InheritedFrom -path $servicePath -identity $principal
        } else { "None" }
        $type = if ($_.AccessControlType -ne $null) { $_.AccessControlType.ToString() } else { "None" }
        $access = if ($_.RegistryRights -ne $null) { $_.RegistryRights.ToString() } else { "None" }
        $appliesTo = switch -Regex ($_.InheritanceFlags.ToString() + "," + $_.PropagationFlags.ToString()) {
            "None,.*" { "This key only" }
            "ContainerInherit,None" { "This key and subkeys" }
            "ObjectInherit,None" { "This key and subkeys" }
            "ContainerInherit,InheritOnly" { "Subkeys only" }
            "ObjectInherit,InheritOnly" { "Files only" }
            "ContainerInherit,ObjectInherit,InheritOnly" { "Subkeys and files only" }
            default { "This key and subkeys" }
        }

        $uniquePrincipals[$principal] = [PSCustomObject]@{
            Principal = $principal
            Type = $type
            Access = $access
            InheritedFrom = $inheritedFrom
            AppliesTo = $appliesTo
            IsInherited = $_.IsInherited
        }
    }
}

$uniquePrincipals.Values | ConvertTo-Json -Compress
`, path)

	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", powershellScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("error executing script: %w\nOutput: %s", err, string(output))
	}

	return string(output), nil
}
