//go:build windows

package pair

import (
	"errors"
	"os"
	"runtime"

	"golang.org/x/sys/windows"
)

// restrictToCurrentUser replaces the object's DACL with one explicit entry
// for the current user SID. The DACL is protected, so it is not inherited
// from the parent. chmod is not used: on Windows a mode bit is not this ACL.
func restrictToCurrentUser(path string) error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return localCode("copy_incomplete", "file protection could not be applied")
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return localCode("copy_incomplete", "file protection could not be applied")
	}
	sid := user.User.Sid
	var pin runtime.Pinner
	pin.Pin(sid)
	defer pin.Unpin()
	defer runtime.KeepAlive(user)

	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}}, nil)
	if err != nil {
		return localCode("copy_incomplete", "file protection could not be applied")
	}
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	)
	if err != nil {
		return localCode("copy_incomplete", "file protection could not be applied")
	}
	return nil
}

func restrictDir(path string) error {
	return restrictToCurrentUser(path)
}

func restrictFile(path string) error {
	return restrictToCurrentUser(path)
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return localCode("copy_incomplete", "copy could not be saved")
	}
	defer f.Close()
	err = f.Sync()
	if err == nil {
		return nil
	}
	// Directory handles do not implement FlushFileBuffers.
	if errors.Is(err, windows.ERROR_INVALID_FUNCTION) {
		return nil
	}
	return localCode("copy_incomplete", "copy could not be saved")
}
