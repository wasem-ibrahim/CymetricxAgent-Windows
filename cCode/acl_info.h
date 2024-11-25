#ifndef ACL_INFO_H
#define ACL_INFO_H

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

struct AclEntry {
    wchar_t* IdentityReference;
    wchar_t* FileSystemRights;
    wchar_t* AccessControlType;
    BOOL IsInherited;
    wchar_t* InheritanceFlags;
    wchar_t* PropagationFlags;
    wchar_t* InheritedFrom;
};

__declspec(dllexport) struct AclEntry* GetFileSecurityInfo(LPCTSTR fileName, int* entryCount);
__declspec(dllexport) void FreeAclEntries(struct AclEntry* entries, int entryCount);

#ifdef __cplusplus
}
#endif

#endif // ACL_INFO_H
