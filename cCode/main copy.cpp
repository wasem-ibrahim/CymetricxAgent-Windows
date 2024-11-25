#include <iostream>
#include <vector>
#include <Windows.h>
#include <AclAPI.h>
#include <sddl.h>
#include <tchar.h>
#include <string>

extern "C" {
#define DLL_EXPORT __declspec(dllexport)

struct AclEntry {
    wchar_t IdentityReference[256];
    wchar_t FileSystemRights[256];
    wchar_t AccessControlType[256];
    int IsInherited;
    wchar_t InheritanceFlags[256];
    wchar_t PropagationFlags[256];
    wchar_t InheritedFrom[256];
};

std::wstring ConvertToWString(LPCTSTR str) {
#ifdef UNICODE
    return std::wstring(str);
#else
    int size_needed = MultiByteToWideChar(CP_ACP, 0, str, strlen(str), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_ACP, 0, str, strlen(str), &wstrTo[0], size_needed);
    return wstrTo;
#endif
}

std::wstring ConvertTCharToWString(TCHAR* str) {
#ifdef UNICODE
    return std::wstring(str);
#else
    int size_needed = MultiByteToWideChar(CP_ACP, 0, str, strlen(str), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_ACP, 0, str, strlen(str), &wstrTo[0], size_needed);
    return wstrTo;
#endif
}

std::wstring GetFileSystemRights(DWORD mask) {
    if (mask == GENERIC_ALL) return L"FullControl";
    if ((mask & FILE_GENERIC_READ) && (mask & FILE_GENERIC_WRITE) && (mask & FILE_GENERIC_EXECUTE) && (mask & SYNCHRONIZE) && (mask & DELETE)) {
        return L"FullControl";
    }
    std::wstring rights;
    if (mask & FILE_GENERIC_READ) rights += L"ReadAndExecute, ";
    if (mask & FILE_GENERIC_WRITE) rights += L"Modify, ";
    if (mask & FILE_GENERIC_EXECUTE) rights += L"Execute, ";
    if (mask & DELETE) rights += L"Delete, ";
    if (mask & SYNCHRONIZE) rights += L"Synchronize, ";

    if (!rights.empty()) {
        rights = rights.substr(0, rights.size() - 2);
    }

    return rights;
}

std::wstring GetInheritedFrom(const std::wstring& path, PSID sid) {
    std::wstring parentPath = path;
    while (true) {
        size_t pos = parentPath.find_last_of(L"\\");
        if (pos == std::wstring::npos) {
            break;
        }
        parentPath = parentPath.substr(0, pos);
        PSECURITY_DESCRIPTOR parentSD = NULL;
        PACL parentDACL = NULL;
        PSID ownerSID = NULL;
        PSID groupSID = NULL;

        DWORD result = GetNamedSecurityInfoW(parentPath.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, &ownerSID, &groupSID, &parentDACL, NULL, &parentSD);
        if (result == ERROR_SUCCESS && parentDACL) {
            ACL_SIZE_INFORMATION aclSizeInfo;
            if (GetAclInformation(parentDACL, &aclSizeInfo, sizeof(aclSizeInfo), AclSizeInformation)) {
                for (DWORD i = 0; i < aclSizeInfo.AceCount; i++) {
                    ACCESS_ALLOWED_ACE* ace;
                    if (GetAce(parentDACL, i, (void**)&ace)) {
                        if (EqualSid(&ace->SidStart, sid) && !(ace->Header.AceFlags & INHERITED_ACE)) {
                            LocalFree(parentSD);
                            return parentPath;
                        }
                    }
                }
            }
        }
        if (parentSD) {
            LocalFree(parentSD);
        }
    }
    return L"None";
}

void PopulateAclEntry(std::vector<AclEntry>& entries, ACCESS_ALLOWED_ACE* ace, const std::wstring& inheritedFrom) {
    LPTSTR accountName = NULL;
    LPTSTR domainName = NULL;
    DWORD accountNameLen = 0;
    DWORD domainNameLen = 0;
    SID_NAME_USE sidType;

    LookupAccountSid(NULL, &ace->SidStart, NULL, &accountNameLen, NULL, &domainNameLen, &sidType);
    accountName = (LPTSTR)malloc(accountNameLen * sizeof(TCHAR));
    domainName = (LPTSTR)malloc(domainNameLen * sizeof(TCHAR));

    if (LookupAccountSid(NULL, &ace->SidStart, accountName, &accountNameLen, domainName, &domainNameLen, &sidType)) {
        AclEntry entry;
        wcsncpy_s(entry.IdentityReference, ConvertTCharToWString(domainName).c_str(), _TRUNCATE);
        wcsncat_s(entry.IdentityReference, L"\\", _TRUNCATE);
        wcsncat_s(entry.IdentityReference, ConvertTCharToWString(accountName).c_str(), _TRUNCATE);
        wcsncpy_s(entry.FileSystemRights, GetFileSystemRights(ace->Mask).c_str(), _TRUNCATE);
        wcsncpy_s(entry.AccessControlType, L"Allow", _TRUNCATE);
        entry.IsInherited = (ace->Header.AceFlags & INHERITED_ACE) != 0;
        wcsncpy_s(entry.InheritanceFlags, (ace->Header.AceFlags & CONTAINER_INHERIT_ACE) ? L"ContainerInherit" : L"None", _TRUNCATE);
        wcsncpy_s(entry.PropagationFlags, (ace->Header.AceFlags & OBJECT_INHERIT_ACE) ? L"ObjectInherit" : L"None", _TRUNCATE);
        wcsncpy_s(entry.InheritedFrom, inheritedFrom.c_str(), _TRUNCATE);

        entries.push_back(entry);
    } else {
        std::wcerr << L"LookupAccountSid failed: " << GetLastError() << std::endl;
    }

    free(accountName);
    free(domainName);
}

std::vector<AclEntry> GetAclEntries(PACL acl, const std::wstring& path) {
    std::vector<AclEntry> entries;
    ACL_SIZE_INFORMATION aclSizeInfo;
    if (GetAclInformation(acl, &aclSizeInfo, sizeof(aclSizeInfo), AclSizeInformation)) {
        for (DWORD i = 0; i < aclSizeInfo.AceCount; i++) {
            ACCESS_ALLOWED_ACE* ace;
            if (GetAce(acl, i, (void**)&ace)) {
                if (ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE) {
                    std::wstring inheritedFrom = L"None";
                    if (ace->Header.AceFlags & INHERITED_ACE) {
                        inheritedFrom = GetInheritedFrom(path, (PSID)&ace->SidStart);
                    }
                    PopulateAclEntry(entries, ace, inheritedFrom);
                }
            }
        }
    } else {
        std::wcerr << L"GetAclInformation failed: " << GetLastError() << std::endl;
    }
    return entries;
}

extern "C" DLL_EXPORT void GetFileSecurityInfo(LPCTSTR fileName, AclEntry** aclEntries, int* count) {
    PSECURITY_DESCRIPTOR pSD = NULL;
    PACL dacl = NULL;
    PSID ownerSID = NULL;
    PSID groupSID = NULL;
    std::vector<AclEntry> entries;
    DWORD result = GetNamedSecurityInfo(fileName, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &ownerSID, &groupSID, &dacl, NULL, &pSD);
    if (result == ERROR_SUCCESS) {
        if (dacl) {
            std::wstring filePath = ConvertToWString(fileName);
            entries = GetAclEntries(dacl, filePath);
        }
    } else {
        std::wcerr << L"GetNamedSecurityInfo failed: " << GetLastError() << std::endl;
    }

    if (pSD) {
        LocalFree(pSD);
    }

    *count = entries.size();
    *aclEntries = new AclEntry[*count];
    for (int i = 0; i < *count; ++i) {
        (*aclEntries)[i] = entries[i];
    }
}

}
