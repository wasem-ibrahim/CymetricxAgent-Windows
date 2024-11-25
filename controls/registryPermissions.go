package controls

import (
	"fmt"
	"os/exec"
)

func mainrp() {
	registryPath := "HKLM:\\SOFTWARE\\Adobe"

	output, err := getRegistryPermissions2(registryPath)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Registry ACL Permissions:")
	fmt.Println(output)
}

func getRegistryPermissions2(path string) (string, error) {
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

$path = '%s'
$acl = Get-Acl -Path $path
$uniquePrincipals = @{}
$results = $acl.Access | ForEach-Object {
    $principal = if ($_.IdentityReference) { $_.IdentityReference.Value } else { "None" }
    if (-not $uniquePrincipals.ContainsKey($principal)) {
        $inheritedFrom = if ($_.IsInherited) { 
            Get-InheritedFrom -path $path -identity $principal
        } else { "None" }
        $type = if ($_.AccessControlType -ne $null) { $_.AccessControlType.ToString() } else { "None" }
        $access = if ($_.RegistryRights -ne $null) { $_.RegistryRights.ToString() } else { "None" }
        $appliesTo = if ($_.InheritanceFlags -ne $null -or $_.PropagationFlags -ne $null) { 
            ($_.InheritanceFlags.ToString() + ", " + $_.PropagationFlags.ToString()) 
        } else { "This key and subkeys" }

        $uniquePrincipals[$principal] = [PSCustomObject]@{
            Principal = $principal
            Type = $type
            Access = $access
            InheritedFrom = $inheritedFrom
            AppliesTo = "This key and subkeys"
        }
    }
}

$uniquePrincipals.Values | Format-Table -AutoSize | Out-String
`, path)

	cmd := exec.Command("powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", powershellScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("error executing script: %w\nOutput: %s", err, string(output))
	}

	return string(output), nil
}
