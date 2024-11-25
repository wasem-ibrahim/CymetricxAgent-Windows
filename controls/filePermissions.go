package controls

import (
	"encoding/json"
	"fmt"
	"os/exec"
)

type AclEntry struct {
	IdentityReference string `json:"IdentityReference"`
	FileSystemRights  string `json:"FileSystemRights"`
	AccessControlType string `json:"AccessControlType"`
	IsInherited       bool   `json:"IsInherited"`
	InheritanceFlags  string `json:"InheritanceFlags"`
	PropagationFlags  string `json:"PropagationFlags"`
	InheritedFrom     string `json:"InheritedFrom"`
}

func Mainfp() {
	path := "C:\\Users\\HP\\Documents\\Cymetricx\\Cymetricx\\CymetricxAgent-WindowsV2.0\\test.txt"

	output, err := getPermissions(path)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	var aclEntries []AclEntry
	if err := json.Unmarshal([]byte(output), &aclEntries); err != nil {
		fmt.Println("Error unmarshalling JSON:", err)
		return
	}

	for _, entry := range aclEntries {
		fmt.Println("IdentityReference:", entry.IdentityReference)
		fmt.Println("FileSystemRights:", entry.FileSystemRights)
		fmt.Println("AccessControlType:", entry.AccessControlType)
		fmt.Println("IsInherited:", entry.IsInherited)
		fmt.Println("InheritanceFlags:", entry.InheritanceFlags)
		fmt.Println("PropagationFlags:", entry.PropagationFlags)
		fmt.Println("InheritedFrom:", entry.InheritedFrom)
		fmt.Println()
	}
}

func getPermissions(path string) (string, error) {
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

$acl = Get-Acl -Path '%s'
$results = $acl.Access | ForEach-Object {
    $inheritedFrom = if ($_.IsInherited) { 
        Get-InheritedFrom -path '%s' -identity $_.IdentityReference.Value
    } else { "None" }
    [PSCustomObject]@{
        IdentityReference = $_.IdentityReference.Value
        FileSystemRights = $_.FileSystemRights.ToString()
        AccessControlType = $_.AccessControlType.ToString()
        IsInherited = $_.IsInherited
        InheritanceFlags = $_.InheritanceFlags.ToString()
        PropagationFlags = $_.PropagationFlags.ToString()
        InheritedFrom = $inheritedFrom
    }
}

$results | ConvertTo-Json
`, path, path)

	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", powershellScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("error executing script: %w\nOutput: %s", err, string(output))
	}

	return string(output), nil
}
