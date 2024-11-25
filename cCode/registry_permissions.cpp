#include <windows.h>
#include <sddl.h>
#include <Aclapi.h>
#include <iostream>
#include <string>

std::wstring GetRegistryPermissionsString(DWORD mask) {
    std::wstring permissions;

    if (mask & KEY_QUERY_VALUE) {
        permissions += L"query value, ";
    }
    if (mask & KEY_SET_VALUE) {
        permissions += L"set value, ";
    }
    if (mask & KEY_CREATE_SUB_KEY) {
        permissions += L"create subkey, ";
    }
    if (mask & KEY_ENUMERATE_SUB_KEYS) {
        permissions += L"enumerate subkeys, ";
    }
    if (mask & KEY_NOTIFY) {
        permissions += L"notify, ";
    }
    if (mask & KEY_CREATE_LINK) {
        permissions += L"create link, ";
    }
    if (mask & DELETE) {
        permissions += L"delete, ";
    }
    if (mask & WRITE_DAC) {
        permissions += L"write dac, ";
    }
    if (mask & WRITE_OWNER) {
        permissions += L"write owner, ";
    }
    if (mask & READ_CONTROL) {
        permissions += L"read control, ";
    }
    if (mask & KEY_ALL_ACCESS) {
        permissions += L"full control, ";
    }

    // Remove the trailing comma and space
    if (!permissions.empty()) {
        permissions = permissions.substr(0, permissions.size() - 2);
    }

    return permissions;
}

std::wstring GetInheritanceString(BYTE aceFlags) {
    if (aceFlags & INHERITED_ACE) {
        return L"inherited";
    } else {
        return L"not inherited";
    }
}

std::wstring GetAppliesToString(BYTE aceFlags) {
    if (aceFlags & CONTAINER_INHERIT_ACE) {
        if (aceFlags & INHERIT_ONLY_ACE) {
            return L"subkeys only";
        }
        return L"this key and subkeys";
    } else {
        return L"this key only";
    }
}

void PrintAceDetails(PACE_HEADER pAceHeader) {
    std::wstring accessType;
    std::wstring permissions;
    std::wstring appliesTo;
    PSID pSid;
    LPWSTR sidString = nullptr;
    wchar_t name[256], domain[256];
    DWORD nameSize = sizeof(name) / sizeof(wchar_t), domainSize = sizeof(domain) / sizeof(wchar_t);
    SID_NAME_USE sidType;

    if (pAceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE) {
        accessType = L"Allow";
        ACCESS_ALLOWED_ACE *pAce = (ACCESS_ALLOWED_ACE *)pAceHeader;
        pSid = &pAce->SidStart;
        permissions = GetRegistryPermissionsString(pAce->Mask);
    } else if (pAceHeader->AceType == ACCESS_DENIED_ACE_TYPE) {
        accessType = L"Deny";
        ACCESS_DENIED_ACE *pAce = (ACCESS_DENIED_ACE *)pAceHeader;
        pSid = &pAce->SidStart;
        permissions = GetRegistryPermissionsString(pAce->Mask);
    }

    if (ConvertSidToStringSidW(pSid, &sidString)) {
        LocalFree(sidString);
    }

    if (LookupAccountSidW(NULL, pSid, name, &nameSize, domain, &domainSize, &sidType)) {
        std::wcout << L"Principal: " << domain << L"\\" << name << std::endl;
    } else {
        std::wcerr << L"LookupAccountSid Error: " << GetLastError() << std::endl;
    }

    appliesTo = GetAppliesToString(pAceHeader->AceFlags);

    std::wcout << L"Inheritance: " << GetInheritanceString(pAceHeader->AceFlags) << std::endl;
    std::wcout << L"Access Type: " << accessType << std::endl;
    std::wcout << L"Permissions: " << permissions << std::endl;
    std::wcout << L"Applies to: " << appliesTo << std::endl;
    std::wcout << std::endl;
}

void PrintAclInfo(PACL pAcl) {
    ACL_SIZE_INFORMATION aclSizeInfo;
    if (!GetAclInformation(pAcl, &aclSizeInfo, sizeof(aclSizeInfo), AclSizeInformation)) {
        std::wcerr << L"GetAclInformation Error: " << GetLastError() << std::endl;
        return;
    }

    for (DWORD i = 0; i < aclSizeInfo.AceCount; ++i) {
        PACE_HEADER pAceHeader;
        if (!GetAce(pAcl, i, (LPVOID *)&pAceHeader)) {
            std::wcerr << L"GetAce Error: " << GetLastError() << std::endl;
            return;
        }

        PrintAceDetails(pAceHeader);
    }
}

void PrintSecurityDescriptorInfo(PSECURITY_DESCRIPTOR pSd) {
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    PACL pDacl = NULL;

    if (!GetSecurityDescriptorDacl(pSd, &daclPresent, &pDacl, &daclDefaulted)) {
        std::wcerr << L"GetSecurityDescriptorDacl Error: " << GetLastError() << std::endl;
        return;
    }

    if (daclPresent && pDacl) {
        PrintAclInfo(pDacl);
    } else {
        std::wcout << L"No DACL present" << std::endl;
    }
}

int main() {
    const wchar_t *keyPath = L"SOFTWARE\\CPUID";

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, READ_CONTROL, &hKey) != ERROR_SUCCESS) {
        std::cerr << "RegOpenKeyEx Error" << std::endl;
        return 1;
    }

    PSECURITY_DESCRIPTOR pSd = NULL;
    DWORD sdSize = 0;

    // First call to get the buffer size
    if (RegGetKeySecurity(hKey, DACL_SECURITY_INFORMATION, pSd, &sdSize) == ERROR_INSUFFICIENT_BUFFER) {
        pSd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, sdSize);
    }

    if (RegGetKeySecurity(hKey, DACL_SECURITY_INFORMATION, pSd, &sdSize) != ERROR_SUCCESS) {
        std::cerr << "RegGetKeySecurity Error" << std::endl;
        return 1;
    }

    PrintSecurityDescriptorInfo(pSd);

    if (pSd) {
        LocalFree(pSd);
    }

    RegCloseKey(hKey);

    return 0;
}
