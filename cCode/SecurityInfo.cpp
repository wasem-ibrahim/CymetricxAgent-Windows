#include <windows.h>
#include <sddl.h>
#include <Aclapi.h>
#include <iostream>
#include <string>
#include <vector>

#ifdef BUILD_DLL
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT __declspec(dllimport)
#endif

struct SecurityInfo {
    LPWSTR Inheritance;
    LPWSTR AccessType;
    LPWSTR Permissions;
    LPWSTR Principal;
    LPWSTR AppliesTo;
};

std::wstring GetPermissionsString(DWORD mask) {
    std::wstring permissions;

    if (mask & GENERIC_ALL) {
        permissions += L"full control, ";
    } else {
        if (mask & FILE_READ_DATA) {
            permissions += L"list folder / read data, ";
        }
        if (mask & FILE_WRITE_DATA) {
            permissions += L"create files / write data, ";
        }
        if (mask & FILE_APPEND_DATA) {
            permissions += L"create folders / append data, ";
        }
        if (mask & FILE_READ_EA) {
            permissions += L"read extended attributes, ";
        }
        if (mask & FILE_WRITE_EA) {
            permissions += L"write extended attributes, ";
        }
        if (mask & FILE_EXECUTE) {
            permissions += L"traverse folder / execute file, ";
        }
        if (mask & FILE_DELETE_CHILD) {
            permissions += L"delete subfolders and files, ";
        }
        if (mask & FILE_READ_ATTRIBUTES) {
            permissions += L"read attributes, ";
        }
        if (mask & FILE_WRITE_ATTRIBUTES) {
            permissions += L"write attributes, ";
        }
        if (mask & DELETE) {
            permissions += L"delete, ";
        }
        if (mask & READ_CONTROL) {
            permissions += L"read permissions, ";
        }
        if (mask & WRITE_DAC) {
            permissions += L"change permissions, ";
        }
        if (mask & WRITE_OWNER) {
            permissions += L"take ownership, ";
        }
    }

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
    if (aceFlags & OBJECT_INHERIT_ACE) {
        if (aceFlags & CONTAINER_INHERIT_ACE) {
            if (aceFlags & INHERIT_ONLY_ACE) {
                return L"subfolders and files only";
            }
            return L"this folder, subfolders and files";
        }
        if (aceFlags & INHERIT_ONLY_ACE) {
            return L"files only";
        }
        return L"this folder and files";
    } else if (aceFlags & CONTAINER_INHERIT_ACE) {
        if (aceFlags & INHERIT_ONLY_ACE) {
            return L"subfolders only";
        }
        return L"this folder and subfolders";
    } else {
        return L"this folder only";
    }
}

void GetAceDetails(PACE_HEADER pAceHeader, std::vector<SecurityInfo>& securityInfoList) {
    SecurityInfo info = {0};
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
        permissions = GetPermissionsString(pAce->Mask);
    } else if (pAceHeader->AceType == ACCESS_DENIED_ACE_TYPE) {
        accessType = L"Deny";
        ACCESS_DENIED_ACE *pAce = (ACCESS_DENIED_ACE *)pAceHeader;
        pSid = &pAce->SidStart;
        permissions = GetPermissionsString(pAce->Mask);
    }

    if (ConvertSidToStringSidW(pSid, &sidString)) {
        LocalFree(sidString);
    }

    if (LookupAccountSidW(NULL, pSid, name, &nameSize, domain, &domainSize, &sidType)) {
        std::wstring principal = std::wstring(domain) + L"\\" + std::wstring(name);
        info.Principal = _wcsdup(principal.c_str());
    } else {
        std::wcerr << L"LookupAccountSid Error: " << GetLastError() << std::endl;
        info.Principal = _wcsdup(L"Unknown");
    }

    info.Inheritance = _wcsdup(GetInheritanceString(pAceHeader->AceFlags).c_str());
    info.AccessType = _wcsdup(accessType.c_str());
    info.Permissions = _wcsdup(permissions.c_str());
    info.AppliesTo = _wcsdup(GetAppliesToString(pAceHeader->AceFlags).c_str());

    securityInfoList.push_back(info);
}

void GetAclInfo(PACL pAcl, std::vector<SecurityInfo>& securityInfoList) {
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

        GetAceDetails(pAceHeader, securityInfoList);
    }
}

void GetSecurityDescriptorInfo(PSECURITY_DESCRIPTOR pSd, std::vector<SecurityInfo>& securityInfoList) {
    BOOL daclPresent = FALSE;
    BOOL daclDefaulted = FALSE;
    PACL pDacl = NULL;

    if (!GetSecurityDescriptorDacl(pSd, &daclPresent, &pDacl, &daclDefaulted)) {
        std::wcerr << L"GetSecurityDescriptorDacl Error: " << GetLastError() << std::endl;
        return;
    }

    if (daclPresent && pDacl) {
        GetAclInfo(pDacl, securityInfoList);
    } else {
        std::wcout << L"No DACL present" << std::endl;
    }
}

extern "C" {
    DLL_EXPORT SecurityInfo* GetCustomSecurityInfo(const wchar_t* path, int* count) {
        std::vector<SecurityInfo> securityInfoList;

        PSECURITY_DESCRIPTOR pSd = NULL;
        DWORD result = GetNamedSecurityInfoW(
            path,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            NULL,
            NULL,
            NULL,
            NULL,
            &pSd
        );

        if (result != ERROR_SUCCESS) {
            std::wcerr << L"GetNamedSecurityInfo Error: " << result << std::endl;
            *count = 0;
            return nullptr;
        }

        GetSecurityDescriptorInfo(pSd, securityInfoList);

        if (pSd) {
            LocalFree(pSd);
        }

        *count = securityInfoList.size();
        SecurityInfo* securityInfoArray = new SecurityInfo[*count];
        std::copy(securityInfoList.begin(), securityInfoList.end(), securityInfoArray);

        return securityInfoArray;
    }

    DLL_EXPORT void FreeSecurityInfoArray(SecurityInfo* array, int count) {
        for (int i = 0; i < count; ++i) {
            free(array[i].Inheritance);
            free(array[i].AccessType);
            free(array[i].Permissions);
            free(array[i].Principal);
            free(array[i].AppliesTo);
        }
        delete[] array;
    }
}
