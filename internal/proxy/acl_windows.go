//go:build windows

package proxy

import (
	"errors"
	"os"
	"runtime"

	"golang.org/x/sys/windows"
)

// restrictToCurrentUser replaces the DACL with one explicit entry for the
// current user. The DACL is protected, so it is not inherited. chmod is not
// the access check on Windows.
func restrictToCurrentUser(path string) error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return local("copy_incomplete", "file protection could not be applied")
	}
	defer token.Close()

	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsValid() {
		return local("copy_incomplete", "file protection could not be applied")
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
		return local("copy_incomplete", "file protection could not be applied")
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
		return local("copy_incomplete", "file protection could not be applied")
	}
	return nil
}

func restrictDir(path string) error {
	return restrictToCurrentUser(path)
}

func restrictFile(path string) error {
	return restrictToCurrentUser(path)
}

// openForSync opens a writable handle. FlushFileBuffers rejects a read-only one.
func openForSync(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDWR, 0o600)
}

func syncFile(path string) error {
	f, err := openForSync(path)
	if err != nil {
		return local("copy_incomplete", "file protection could not be applied")
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return local("copy_incomplete", "file protection could not be applied")
	}
	return nil
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return local("copy_incomplete", "file protection could not be applied")
	}
	defer f.Close()
	err = f.Sync()
	if err == nil || errors.Is(err, windows.ERROR_INVALID_FUNCTION) {
		return nil
	}
	return local("copy_incomplete", "file protection could not be applied")
}

func executableMode(_ os.FileMode) bool {
	return true
}

func caseFoldPaths() bool {
	return true
}
