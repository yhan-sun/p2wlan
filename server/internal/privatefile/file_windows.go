package privatefile

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func OpenNew(path string) (*os.File, error) {
	account, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("query private file owner: %w", err)
	}
	owner := account.User.Sid.String()
	descriptor, err := windows.SecurityDescriptorFromString("O:" + owner + "D:P(A;;FA;;;SY)(A;;FA;;;" + owner + ")")
	if err != nil {
		return nil, fmt.Errorf("build private file ACL: %w", err)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(absolute, `\\?\`) {
		if strings.HasPrefix(absolute, `\\`) {
			absolute = `\\?\UNC\` + absolute[2:]
		} else {
			absolute = `\\?\` + absolute
		}
	}
	name, err := windows.UTF16PtrFromString(absolute)
	if err != nil {
		return nil, err
	}
	attributes := windows.SecurityAttributes{SecurityDescriptor: descriptor}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	handle, err := windows.CreateFile(name, uint32(windows.GENERIC_READ|windows.GENERIC_WRITE),
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		&attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	runtime.KeepAlive(descriptor)
	if err != nil {
		return nil, &os.PathError{Op: "create private file", Path: path, Err: err}
	}
	file := os.NewFile(uintptr(handle), path)
	applied, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err == nil {
		err = verifyDescriptor(applied, account.User.Sid)
	}
	if err != nil {
		file.Close()
		os.Remove(path)
		return nil, fmt.Errorf("private file ACL was not enforced: %w", err)
	}
	return file, nil
}

func Verify(path string) error {
	account, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	return verifyDescriptor(descriptor, account.User.Sid)
}

func verifyDescriptor(descriptor *windows.SECURITY_DESCRIPTOR, owner *windows.SID) error {
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("private DACL inherits parent access")
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if acl == nil || acl.AceCount == 0 || acl.AceCount > 2 {
		return fmt.Errorf("private DACL has unexpected entries")
	}
	ownerAllowed, systemAllowed := false, false
	for i := uint32(0); i < uint32(acl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != 0 || ace.Mask != 0x001f01ff {
			return fmt.Errorf("unexpected private file access entry")
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case sid.Equals(owner):
			ownerAllowed = true
			if sid.IsWellKnown(windows.WinLocalSystemSid) {
				systemAllowed = true
			}
		case sid.IsWellKnown(windows.WinLocalSystemSid):
			systemAllowed = true
		default:
			return fmt.Errorf("private file grants access outside its owner and SYSTEM")
		}
	}
	runtime.KeepAlive(descriptor)
	if !ownerAllowed || !systemAllowed {
		return fmt.Errorf("private file owner or SYSTEM access is missing")
	}
	return nil
}
