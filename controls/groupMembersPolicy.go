package controls

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// Windows API constants and types
const (
	MAX_PREFERRED_LENGTH = 0xFFFFFFFF
)

var (
	modNetapi32_3             = syscall.NewLazyDLL("netapi32.dll")
	procNetUserGetLocalGroups = modNetapi32_3.NewProc("NetUserGetLocalGroups")
	procNetApiBufferFree_3    = modNetapi32_3.NewProc("NetApiBufferFree")
)

type LOCALGROUP_USERS_INFO_0 struct {
	GroupName *uint16
}

// NetUserGetLocalGroups wraps the Windows API function
func NetUserGetLocalGroups(servername *uint16, username *uint16, level uint32, flags uint32, bufptr *uintptr, prefmaxlen uint32, entriesread *uint32, totalentries *uint32) (neterr error) {
	r0, _, _ := syscall.Syscall9(procNetUserGetLocalGroups.Addr(), 8, uintptr(unsafe.Pointer(servername)), uintptr(unsafe.Pointer(username)), uintptr(level), uintptr(flags), uintptr(unsafe.Pointer(bufptr)), uintptr(prefmaxlen), uintptr(unsafe.Pointer(entriesread)), uintptr(unsafe.Pointer(totalentries)), 0)
	if r0 != 0 {
		neterr = syscall.Errno(r0)
	}
	return
}

// NetApiBufferFree wraps the Windows API function
func NetApiBufferFree(buffer uintptr) (neterr error) {
	r0, _, _ := syscall.Syscall(procNetApiBufferFree_3.Addr(), 1, uintptr(buffer), 0, 0)
	if r0 != 0 {
		neterr = syscall.Errno(r0)
	}
	return
}

// checkUserInGroups checks if a user is part of one or more specified groups
func checkUserInGroups(userName string, groups []string) (bool, []string, error) {
	fmt.Printf("Checking user %s in groups %v\n", userName, groups)
	localGroups, err := getLocalGroups(userName)
	if err != nil {
		return false, localGroups, fmt.Errorf("could not get local groups for user %s: %v", userName, err)
	}

	for _, group := range groups {

		for _, localGroup := range localGroups {
			if group == localGroup {
				fmt.Printf("User %s is a member of group %s\n", userName, group)
				return true, localGroups, nil
			}
		}
	}

	return false, localGroups, nil
}

// getLocalGroups retrieves the local groups a user is a member of
func getLocalGroups(userName string) ([]string, error) {
	var (
		serverName     *uint16
		userNamePtr, _ = syscall.UTF16PtrFromString(userName)
		buf            uintptr
		entriesRead    uint32
		totalEntries   uint32
	)

	err := NetUserGetLocalGroups(serverName, userNamePtr, 0, 0, &buf, MAX_PREFERRED_LENGTH, &entriesRead, &totalEntries)
	if err != nil {
		return nil, err
	}
	defer NetApiBufferFree(buf)

	groups := make([]string, entriesRead)
	groupNames := (*[1 << 20]LOCALGROUP_USERS_INFO_0)(unsafe.Pointer(buf))[:entriesRead:entriesRead]

	for i, groupInfo := range groupNames {
		groups[i] = syscall.UTF16ToString((*[256]uint16)(unsafe.Pointer(groupInfo.GroupName))[:])
	}

	return groups, nil
}

func Maingmp() {
	users := []string{"Administrator", "HP", "Guest", "Test"}
	groups := []string{"Administrators", "Guests"}

	for _, user := range users {
		inGroup, _, err := checkUserInGroups(user, groups)
		if err != nil {
			fmt.Printf("Error checking user %s: %v\n", user, err)
			continue
		}

		if inGroup {
			fmt.Printf("User %s is a member of one or more specified groups.\n", user)
		} else {
			fmt.Printf("User %s is not a member of any specified groups.\n", user)
		}
	}
}

func GetGroupMembersPolicy(obj map[string]string, variables map[string]string) (map[string]string, error) {
	// valueType := obj["value_type"]
	valueData := obj["value_data"]
	groupName := obj["group_name"]

	var users []string
	var groups []string

	if valueData == "" {
		return nil, fmt.Errorf("value_data is required")
	}

	// Check if it is a variable and return it if so.
	if value, found := getValueFromVariables(valueData, variables); found {
		valueData = value
	} else {
		return nil, fmt.Errorf("variable %s not found", valueData)
	}

	// Check if it is a variable and return it if so.
	if group, found := getValueFromVariables(groupName, variables); found {
		groupName = group
	} else {
		return nil, fmt.Errorf("variable %s not found", groupName)
	}

	if strings.Contains(valueData, "&&") {
		users = strings.Split(valueData, "&&")
		// trim all the spaces from the users
		for i, user := range users {
			users[i] = strings.TrimSpace(user)
		}

	} else {
		users = []string{valueData}
	}

	groups = []string{groupName}
	var localGroups []string

	var result bool = true
	var status string

	// fmt.Println("Users:", users)
	// fmt.Println("Groups:", groups)

	for _, user := range users {
		var inGroup bool
		var err error
		inGroup, localGroups, err = checkUserInGroups(user, groups)
		if err != nil {
			fmt.Printf("Error checking user %s: %v\n", user, err)
			continue
		}

		if !inGroup {
			result = false
			break
		}
	}

	if result {
		status = "true"
	} else {
		status = "false"
	}

	// Constructing the result map
	resultMap := map[string]string{
		"type":         obj["type"],
		"control_key":  obj["control_key"],
		"Resulting Data":   valueData,
		"Audit Output": fmt.Sprintf("Local groups: %v", localGroups),
		"status":       status,
	}

	return resultMap, nil
}
